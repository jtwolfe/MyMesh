//! Join request (joiner) and host-side pending approval.
use chrono::Utc;
use mymesh_core::{
    ArmState, Capability, DeviceId, DeviceLabel, DeviceRecord, DeviceStore, JoinDecision,
    JoinStore, NodeFingerprint, PendingJoin, Result, TrustState,
};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

fn sign_material(device_id: &DeviceId, label: &str, ts: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(device_id.as_bytes());
    v.extend_from_slice(label.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(b"mymesh-join-v1");
    v
}

/// Joiner: send JoinRequest and wait for Accept/Deny.
pub async fn run_join_as_guest(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    store: &mut DeviceStore,
    requested_caps: Vec<Capability>,
) -> Result<DeviceRecord> {
    let device_id = identity.device_id();
    let ts = Utc::now().timestamp();
    let material = sign_material(&device_id, label, ts);
    let req = ControlMessage::JoinRequest {
        protocol_version: 1,
        device_id,
        label: label.to_string(),
        verifying_key: identity.verifying_key_bytes(),
        capabilities: requested_caps,
        ts,
        signature: identity.sign(&material),
    };
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&req)?,
    })
    .await?;

    loop {
        let frame = conn.recv_frame().await?;
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        match msg {
            ControlMessage::JoinPending {
                host_label,
                message,
                ..
            } => {
                info!(%host_label, %message, "waiting for host approval");
                println!("waiting for approval on host ({host_label})…");
            }
            ControlMessage::JoinAccept {
                device_id: host_id,
                label: host_label,
                capabilities,
                signature,
            } => {
                // Host signs with ts=0 convention for accept
                let pub_id = mymesh_crypto::IdentityPublic {
                    verifying_key: *host_id.as_bytes(),
                };
                // Accept signature covers device_id||label||"mymesh-join-accept-v1"
                let mut mat = Vec::new();
                mat.extend_from_slice(host_id.as_bytes());
                mat.extend_from_slice(host_label.as_bytes());
                mat.extend_from_slice(b"mymesh-join-accept-v1");
                pub_id.verify(&mat, &signature)?;
                let rec = DeviceRecord {
                    id: host_id,
                    label: DeviceLabel::new(host_label),
                    fingerprint: NodeFingerprint::from_device_id(&host_id).as_str().to_string(),
                    capabilities,
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: Some(Utc::now()),
                    endpoint_hint: None,
                };
                store.upsert(rec.clone())?;
                let _ = conn.close().await;
                return Ok(rec);
            }
            ControlMessage::JoinDeny { reason } => {
                let _ = conn.close().await;
                return Err(mymesh_core::Error::PermissionDenied(reason));
            }
            other => {
                return Err(mymesh_core::Error::Protocol(format!(
                    "unexpected join response: {other:?}"
                )));
            }
        }
    }
}

/// Host agent: handle a join from an untrusted peer while armed.
pub async fn handle_join_as_host(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    devices_path: &Path,
    arm_path: &Path,
    join_dir: &Path,
    arm_timeout_hint: u64,
) -> Result<()> {
    let peer = conn.peer_id();
    let arm = ArmState::load(arm_path)?;
    if !arm.is_effectively_armed() {
        let deny = ControlMessage::JoinDeny {
            reason: "host is not accepting connection requests (run: mymesh connect-request allow)"
                .into(),
        };
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&deny)?,
            })
            .await;
        let _ = conn.close().await;
        return Ok(());
    }

    let frame = conn.recv_frame().await?;
    let msg: ControlMessage = decode_msg(&frame.payload)?;
    let (joiner_id, joiner_label, caps, ts, sig, vk) = match msg {
        ControlMessage::JoinRequest {
            protocol_version,
            device_id,
            label: jl,
            verifying_key,
            capabilities,
            ts,
            signature,
        } => {
            if protocol_version != 1 {
                return Err(mymesh_core::Error::Protocol("bad join version".into()));
            }
            (device_id, jl, capabilities, ts, signature, verifying_key)
        }
        _ => {
            let deny = ControlMessage::JoinDeny {
                reason: "expected JoinRequest".into(),
            };
            let _ = conn
                .send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&deny)?,
                })
                .await;
            let _ = conn.close().await;
            return Ok(());
        }
    };

    if joiner_id != peer || vk != *joiner_id.as_bytes() {
        let deny = ControlMessage::JoinDeny {
            reason: "device id mismatch".into(),
        };
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&deny)?,
            })
            .await;
        let _ = conn.close().await;
        return Ok(());
    }

    let material = sign_material(&joiner_id, &joiner_label, ts);
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: vk,
    };
    if let Err(e) = pub_id.verify(&material, &sig) {
        warn!(%e, "join signature invalid");
        let deny = ControlMessage::JoinDeny {
            reason: "invalid signature".into(),
        };
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&deny)?,
            })
            .await;
        let _ = conn.close().await;
        return Ok(());
    }

    // Freshness: allow ±1 hour skew
    let now = Utc::now().timestamp();
    if (now - ts).abs() > 3600 {
        let deny = ControlMessage::JoinDeny {
            reason: "join request timestamp out of range".into(),
        };
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&deny)?,
            })
            .await;
        let _ = conn.close().await;
        return Ok(());
    }

    let joins = JoinStore::open(join_dir)?;
    joins.write_pending(&PendingJoin {
        device_id: joiner_id,
        label: joiner_label.clone(),
        capabilities: caps.clone(),
        received_at: Utc::now(),
        fingerprint: NodeFingerprint::from_device_id(&joiner_id).as_str().to_string(),
    })?;

    info!(
        peer = %joiner_id.short(),
        label = %joiner_label,
        "join request pending — run: mymesh requests accept {}",
        joiner_id.short()
    );

    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&ControlMessage::JoinPending {
            host_id: identity.device_id(),
            host_label: label.to_string(),
            message: format!(
                "approve with: mymesh requests accept {}",
                joiner_id.short()
            ),
        })?,
    })
    .await?;

    // Wait for operator decision
    let deadline = std::time::Instant::now() + Duration::from_secs(arm_timeout_hint.max(60));
    let decision = loop {
        if std::time::Instant::now() > deadline {
            break JoinDecision::Deny {
                reason: "approval timed out".into(),
            };
        }
        // Also bail if disarmed without decision
        let arm = ArmState::load(arm_path)?;
        if !arm.is_effectively_armed() {
            // still allow if decision file present
            if let Some(d) = joins.take_decision(&joiner_id)? {
                break d;
            }
            break JoinDecision::Deny {
                reason: "host disarmed before approval".into(),
            };
        }
        if let Some(d) = joins.take_decision(&joiner_id)? {
            break d;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    match decision {
        JoinDecision::Accept => {
            let mut store = DeviceStore::open(devices_path)?;
            let rec = DeviceRecord {
                id: joiner_id,
                label: DeviceLabel::new(joiner_label.clone()),
                fingerprint: NodeFingerprint::from_device_id(&joiner_id).as_str().to_string(),
                capabilities: if caps.is_empty() {
                    Capability::all()
                } else {
                    caps
                },
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: Some(Utc::now()),
                endpoint_hint: None,
            };
            store.upsert(rec)?;

            let host_id = identity.device_id();
            let mut mat = Vec::new();
            mat.extend_from_slice(host_id.as_bytes());
            mat.extend_from_slice(label.as_bytes());
            mat.extend_from_slice(b"mymesh-join-accept-v1");
            let accept = ControlMessage::JoinAccept {
                device_id: host_id,
                label: label.to_string(),
                capabilities: Capability::all(),
                signature: identity.sign(&mat),
            };
            conn.send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&accept)?,
            })
            .await?;

            // Auto-disarm after successful accept
            ArmState::disarm(arm_path)?;
            info!(peer = %joiner_id.short(), "join accepted; disarmed");
            // Give the joiner time to read JoinAccept before tearing down QUIC.
            tokio::time::sleep(Duration::from_millis(800)).await;
            let _ = conn.close().await;
            Ok(())
        }
        JoinDecision::Deny { reason } => {
            joins.clear_pending(&joiner_id)?;
            conn.send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&ControlMessage::JoinDeny { reason })?,
            })
            .await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = conn.close().await;
            Ok(())
        }
    }
}
