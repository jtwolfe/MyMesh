//! Join request (joiner) and host-side pending approval + membership handoff.
use chrono::Utc;
use mymesh_core::{
    apply_guest_device_record, ArmState, Capability, Config, DeviceId, DeviceLabel, DeviceRecord,
    DeviceStore, Grant, GrantRole, GrantStore, JoinDecision, JoinStore, MeshRole, MeshState,
    NodeFingerprint, PairPhase, PairSessionStore, Paths, PendingJoin, Result, TrustState,
};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

use crate::mesh_sync::{apply_membership, build_snapshot, verify_membership};

fn sign_material(device_id: &DeviceId, label: &str, ts: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(device_id.as_bytes());
    v.extend_from_slice(label.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(b"mymesh-join-v1");
    v
}

/// Joiner: send JoinRequest and wait for Accept/Deny (+ membership snapshot).
pub async fn run_join_as_guest(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    store: &mut DeviceStore,
    mesh_path: &Path,
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

    let mut host_rec: Option<DeviceRecord> = None;
    // True once a MembershipSnapshot was applied (full member join).
    let mut got_membership = false;

    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(600), conn.recv_frame()).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                if let Some(rec) = finish_joiner_host_rec(store, host_rec, got_membership)? {
                    return Ok(rec);
                }
                return Err(e);
            }
            Err(_) => {
                if let Some(rec) = finish_joiner_host_rec(store, host_rec, got_membership)? {
                    let _ = conn.close().await;
                    return Ok(rec);
                }
                return Err(mymesh_core::Error::Other(
                    "join timed out waiting for host".into(),
                ));
            }
        };
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
                let pub_id = mymesh_crypto::IdentityPublic {
                    verifying_key: *host_id.as_bytes(),
                };
                let mut mat = Vec::new();
                mat.extend_from_slice(host_id.as_bytes());
                mat.extend_from_slice(host_label.as_bytes());
                mat.extend_from_slice(b"mymesh-join-accept-v1");
                pub_id.verify(&mat, &signature)?;
                // Provisional Guest until MembershipSnapshot upgrades to Member
                // (crash between accept and finalize must not leave wrong Member role).
                let rec = DeviceRecord {
                    id: host_id,
                    label: DeviceLabel::new(host_label),
                    fingerprint: NodeFingerprint::from_device_id(&host_id)
                        .as_str()
                        .to_string(),
                    capabilities,
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: Some(Utc::now()),
                    endpoint_hint: None,
                    mesh_id: None,

                    aliases: Vec::new(),
                    groups: Vec::new(),
                    mesh_role: MeshRole::Guest,
                };
                store.upsert(rec.clone())?;
                host_rec = Some(rec);
            }
            ControlMessage::MembershipSnapshot {
                mesh_id,
                from_id,
                members,
                ts,
                signature,
                ..
            } => {
                verify_membership(&from_id, &mesh_id, ts, &members, &signature)?;
                let n = apply_membership(
                    store,
                    mesh_path,
                    &from_id,
                    &mesh_id,
                    &members,
                    identity.device_id(),
                )?;
                info!(added = n, "applied mesh membership from join host");
                got_membership = true;
                if let Some(rec) = host_rec {
                    // Full roster handoff ⇒ member bilateral role for host.
                    if let Some(mut r) = store.get(&rec.id).cloned() {
                        r.mesh_role = MeshRole::Member;
                        store.upsert(r.clone())?;
                        let _ = conn.close().await;
                        return Ok(r);
                    }
                    let mut r = rec;
                    r.mesh_role = MeshRole::Member;
                    store.upsert(r.clone())?;
                    let _ = conn.close().await;
                    return Ok(r);
                }
            }
            ControlMessage::JoinDeny { reason } => {
                let _ = conn.close().await;
                return Err(mymesh_core::Error::PermissionDenied(reason));
            }
            other => {
                if let Some(rec) = finish_joiner_host_rec(store, host_rec, got_membership)? {
                    warn!("ignoring post-accept message: {other:?}");
                    let _ = conn.close().await;
                    return Ok(rec);
                }
                return Err(mymesh_core::Error::Protocol(format!(
                    "unexpected join response: {other:?}"
                )));
            }
        }
    }
}

/// Finalize joiner's host DeviceRecord after accept.
/// Host is already Guest on JoinAccept; MembershipSnapshot upgrades to Member.
fn finish_joiner_host_rec(
    store: &mut DeviceStore,
    host_rec: Option<DeviceRecord>,
    got_membership: bool,
) -> Result<Option<DeviceRecord>> {
    let Some(rec) = host_rec else {
        return Ok(None);
    };
    let mut r = store.get(&rec.id).cloned().unwrap_or(rec);
    r.mesh_role = if got_membership {
        MeshRole::Member
    } else {
        MeshRole::Guest
    };
    r.trust = TrustState::Trusted;
    store.upsert(r.clone())?;
    Ok(Some(r))
}

/// Same iroh path as `pair_v2_dial` / `mymesh link`: connect + `JoinRequest`.
///
/// Fire-and-forget. Host approval may take up to 600s; HTTP must not wait.
/// Never opens `OpenChannel(Admin)` (KD-F17).
pub fn spawn_join_as_guest_to_resident(
    identity: Identity,
    label: String,
    paths: Paths,
    resident: DeviceId,
) {
    tokio::spawn(async move {
        let mut store = match DeviceStore::open(paths.devices_file()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%e, "introduce/dial: device store");
                return;
            }
        };
        let cfg = Config::load(paths.config_file()).unwrap_or_default();
        let sock = PathBuf::from(&cfg.daemon.control_socket);
        match mymesh_net::connect_mesh(&identity, resident, &sock).await {
            Ok((conn, transport)) => {
                match run_join_as_guest(
                    conn,
                    &identity,
                    &label,
                    &mut store,
                    &paths.mesh_file(),
                    Capability::all(),
                )
                .await
                {
                    Ok(peer) => info!(peer = %peer.id.short(), "join as guest completed"),
                    Err(e) => tracing::warn!(%e, "join as guest failed"),
                }
                if let Some(tr) = transport {
                    tr.shutdown().await;
                }
            }
            Err(e) => tracing::warn!(%e, "connect_mesh failed — is mymesh serve running?"),
        }
    });
}

/// Outcome of a host-side join attempt (for mesh dirty / gossip side-effects).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinHostOutcome {
    /// Denied, not armed, protocol error handled, or no accept.
    Noop,
    /// Full member accepted (roster may need gossip).
    MemberAccepted,
    /// Guest accepted bilaterally (local DeviceStore only; no mesh dirty).
    GuestAccepted,
}

/// Host agent: handle a join from an untrusted peer while armed.
///
/// When a PairSession exists in `armed|bound`, binds (or verifies) the joiner
/// to that session (PAIR-V2.md join integration).
///
/// When `ArmState.guest_grant_id` is set, accept uses the guest path: Guest
/// role + grant caps, **no** full [`MembershipSnapshot`] (GUEST.md).
#[allow(clippy::too_many_arguments)]
pub async fn handle_join_as_host(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    devices_path: &Path,
    arm_path: &Path,
    join_dir: &Path,
    mesh_path: &Path,
    arm_timeout_hint: u64,
    pair_sessions_dir: Option<&Path>,
) -> Result<JoinHostOutcome> {
    // Derive grants path next to devices (data_dir/devices.json → data_dir/grants.json).
    let grants_path = devices_path
        .parent()
        .map(|p| p.join("grants.json"))
        .unwrap_or_else(|| Path::new("grants.json").to_path_buf());
    handle_join_as_host_with_grants(
        conn,
        identity,
        label,
        devices_path,
        &grants_path,
        arm_path,
        join_dir,
        mesh_path,
        arm_timeout_hint,
        pair_sessions_dir,
    )
    .await
}

/// Same as [`handle_join_as_host`] with explicit grants file path.
#[allow(clippy::too_many_arguments)]
pub async fn handle_join_as_host_with_grants(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    devices_path: &Path,
    grants_path: &Path,
    arm_path: &Path,
    join_dir: &Path,
    mesh_path: &Path,
    arm_timeout_hint: u64,
    pair_sessions_dir: Option<&Path>,
) -> Result<JoinHostOutcome> {
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
        return Ok(JoinHostOutcome::Noop);
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
            return Ok(JoinHostOutcome::Noop);
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
        return Ok(JoinHostOutcome::Noop);
    }

    let material = sign_material(&joiner_id, &joiner_label, ts);
    let pub_id = mymesh_crypto::IdentityPublic { verifying_key: vk };
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
        return Ok(JoinHostOutcome::Noop);
    }

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
        return Ok(JoinHostOutcome::Noop);
    }

    let joins = JoinStore::open(join_dir)?;
    let fp = NodeFingerprint::from_device_id(&joiner_id)
        .as_str()
        .to_string();
    joins.write_pending(&PendingJoin {
        device_id: joiner_id,
        label: joiner_label.clone(),
        capabilities: caps.clone(),
        received_at: Utc::now(),
        fingerprint: fp.clone(),
    })?;

    // Pair v2: bind joiner to active PairSession when present (A3b).
    if let Some(pair_dir) = pair_sessions_dir {
        if let Err(e) = bind_joiner_to_pair_session(pair_dir, joiner_id, &joiner_label, &fp) {
            warn!(%e, peer = %joiner_id.short(), "pair session bind skipped");
        }
    }

    info!(
        peer = %joiner_id.short(),
        label = %joiner_label,
        "join request pending — run: mymesh requests accept {}  (or: mymesh pair confirm <code>)",
        joiner_id.short()
    );

    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&ControlMessage::JoinPending {
            host_id: identity.device_id(),
            host_label: label.to_string(),
            message: format!("approve with: mymesh requests accept {}", joiner_id.short()),
        })?,
    })
    .await?;

    let deadline = std::time::Instant::now() + Duration::from_secs(arm_timeout_hint.max(60));
    let decision = loop {
        if std::time::Instant::now() > deadline {
            break JoinDecision::Deny {
                reason: "approval timed out".into(),
            };
        }
        let arm = ArmState::load(arm_path)?;
        if !arm.is_effectively_armed() {
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
            let mesh = MeshState::load(mesh_path)?;
            let mut store = DeviceStore::open(devices_path)?;
            let host_id = identity.device_id();

            // Re-load arm so mid-pending re-arm (member ↔ guest / grant id) is honored.
            let arm_now = ArmState::load(arm_path)?;
            let guest_grant_id = arm_now.guest_grant_id.clone();

            // Guest path: arm bound to grant → bilateral Guest, no full roster.
            let guest_grant = if let Some(ref gid) = guest_grant_id {
                match resolve_guest_grant_for_accept(
                    grants_path,
                    gid,
                    &joiner_id,
                    &host_id,
                    &mesh.mesh_id,
                ) {
                    Ok(g) => Some(g),
                    Err(e) => {
                        warn!(%e, grant = %gid, "guest grant accept failed (fail closed)");
                        joins.clear_pending(&joiner_id)?;
                        let _ = conn
                            .send_frame(Frame {
                                channel: ChannelId::control(),
                                payload: encode_msg(&ControlMessage::JoinDeny {
                                    reason: format!("guest grant rejected: {e}"),
                                })?,
                            })
                            .await;
                        let _ = conn.close().await;
                        return Ok(JoinHostOutcome::Noop);
                    }
                }
            } else {
                None
            };

            let (accept_caps, mesh_role) = if let Some(ref g) = guest_grant {
                (g.capabilities.clone(), MeshRole::Guest)
            } else {
                let c = if caps.is_empty() {
                    Capability::all()
                } else {
                    caps
                };
                (c, MeshRole::Member)
            };

            let mut rec = DeviceRecord {
                id: joiner_id,
                label: DeviceLabel::new(joiner_label.clone()),
                fingerprint: NodeFingerprint::from_device_id(&joiner_id)
                    .as_str()
                    .to_string(),
                capabilities: accept_caps.clone(),
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: Some(Utc::now()),
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: Vec::new(),
                groups: Vec::new(),
                mesh_role,
            };
            if let Some(ref g) = guest_grant {
                apply_guest_device_record(&mut rec, g);
            }
            store.upsert(rec)?;

            let mut mat = Vec::new();
            mat.extend_from_slice(host_id.as_bytes());
            mat.extend_from_slice(label.as_bytes());
            mat.extend_from_slice(b"mymesh-join-accept-v1");
            let accept = ControlMessage::JoinAccept {
                device_id: host_id,
                label: label.to_string(),
                // Guest: grant caps only. Member: full default grant to peer.
                capabilities: if guest_grant.is_some() {
                    accept_caps
                } else {
                    Capability::all()
                },
                signature: identity.sign(&mat),
            };
            conn.send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&accept)?,
            })
            .await?;

            let outcome = if guest_grant.is_some() {
                // Skip MembershipSnapshot — guests must not receive mesh roster.
                ArmState::disarm(arm_path)?;
                info!(
                    peer = %joiner_id.short(),
                    "guest join accepted (no membership snapshot); disarmed"
                );
                JoinHostOutcome::GuestAccepted
            } else {
                // Full roster of members only (guests already filtered in build_snapshot).
                let snap = build_snapshot(identity, label, &store, &mesh, 0);
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&snap)?,
                })
                .await?;
                ArmState::disarm(arm_path)?;
                info!(peer = %joiner_id.short(), "join accepted + membership shared; disarmed");
                JoinHostOutcome::MemberAccepted
            };
            tokio::time::sleep(Duration::from_millis(800)).await;
            let _ = conn.close().await;
            Ok(outcome)
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
            Ok(JoinHostOutcome::Noop)
        }
    }
}

/// Load and validate a guest grant for accept (fail closed).
fn resolve_guest_grant_for_accept(
    grants_path: &Path,
    grant_id: &str,
    joiner_id: &DeviceId,
    host_id: &DeviceId,
    mesh_id: &str,
) -> Result<Grant> {
    let grants = GrantStore::open(grants_path)?;
    let g = grants
        .get(grant_id)
        .cloned()
        .ok_or_else(|| mymesh_core::Error::NotFound(format!("grant {grant_id}")))?;
    if g.role != GrantRole::Guest {
        return Err(mymesh_core::Error::PermissionDenied(
            "armed grant is not a guest grant".into(),
        ));
    }
    if !g.is_active(Utc::now()) {
        return Err(mymesh_core::Error::PermissionDenied(
            "grant is revoked or expired".into(),
        ));
    }
    if !g.covers_object(host_id) {
        return Err(mymesh_core::Error::PermissionDenied(
            "grant object is not this host".into(),
        ));
    }
    if g.subject_device_id != *joiner_id {
        return Err(mymesh_core::Error::PermissionDenied(
            "joiner is not the grant subject".into(),
        ));
    }
    if !g.mesh_id.is_empty() && g.mesh_id != mesh_id {
        return Err(mymesh_core::Error::PermissionDenied(
            "grant mesh_id mismatch".into(),
        ));
    }
    if g.capabilities.is_empty() {
        return Err(mymesh_core::Error::PermissionDenied(
            "grant has no capabilities".into(),
        ));
    }
    if g.capabilities.contains(&Capability::Admin) {
        return Err(mymesh_core::Error::PermissionDenied(
            "Admin is not allowed on guest grants".into(),
        ));
    }
    Ok(g)
}

/// Bind pending joiner to an open PairSession (armed → bound; bound must match).
fn bind_joiner_to_pair_session(
    pair_sessions_dir: &Path,
    joiner_id: DeviceId,
    joiner_label: &str,
    fp: &str,
) -> Result<()> {
    if !pair_sessions_dir.exists() {
        return Ok(());
    }
    let store = PairSessionStore::open(pair_sessions_dir)?;
    let Some(sess) = store.active_session()? else {
        return Ok(());
    };
    if !matches!(sess.phase, PairPhase::Armed | PairPhase::Bound) {
        return Ok(());
    }
    // If already bound to a different peer, do not rebind (mismatch).
    if sess.phase == PairPhase::Bound {
        if let Some(existing) = sess.joiner_device_id {
            if existing != joiner_id {
                return Err(mymesh_core::Error::Session(format!(
                    "pair session {} already bound to different joiner",
                    sess.sid
                )));
            }
            // same joiner — refresh
        }
    }
    let bound = store.bind_joiner(
        &sess.sid,
        joiner_id,
        Some(joiner_label.to_string()),
        Some(fp.to_string()),
    )?;
    info!(
        sid = %bound.sid,
        peer = %joiner_id.short(),
        phase = %bound.phase.as_str(),
        "bound joiner to pair session"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_sync::members_from_store;
    use mymesh_core::{IssuedBy, MeshRole};
    use mymesh_net::{LocalFabric, Transport};
    use mymesh_protocol::{decode_msg, ControlMessage};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mymesh-join-{}-{}-{}",
            tag,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Capture frames the host sends so we can assert no MembershipSnapshot.
    struct CaptureConn {
        inner: Box<dyn PeerConnection>,
        sent: Arc<Mutex<Vec<ControlMessage>>>,
    }

    #[async_trait::async_trait]
    impl PeerConnection for CaptureConn {
        fn peer_id(&self) -> DeviceId {
            self.inner.peer_id()
        }
        async fn send_frame(&self, frame: Frame) -> mymesh_core::Result<()> {
            if let Ok(msg) = decode_msg::<ControlMessage>(&frame.payload) {
                self.sent.lock().unwrap().push(msg);
            }
            self.inner.send_frame(frame).await
        }
        async fn recv_frame(&self) -> mymesh_core::Result<Frame> {
            self.inner.recv_frame().await
        }
        async fn close(&self) -> mymesh_core::Result<()> {
            self.inner.close().await
        }
        async fn send_raw(&self, data: &[u8]) -> mymesh_core::Result<()> {
            self.inner.send_raw(data).await
        }
        async fn recv_raw(&self) -> mymesh_core::Result<Vec<u8>> {
            self.inner.recv_raw().await
        }
    }

    #[tokio::test]
    async fn run_join_as_guest_first_frame_is_join_request() {
        let root = tmp_root("join-req");
        let devices = root.join("devices.json");
        let mesh = root.join("mesh.json");
        MeshState::new_mesh().save(&mesh).unwrap();
        let guest = Identity::generate();
        let host_id = DeviceId::from_bytes([0x11; 32]);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let deny = Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&ControlMessage::JoinDeny {
                reason: "test".into(),
            })
            .unwrap(),
        };
        let conn = RecordGuestConn {
            peer: host_id,
            sent: sent.clone(),
            reply: tokio::sync::Mutex::new(Some(deny)),
        };
        let mut store = DeviceStore::open(&devices).unwrap();
        let err = run_join_as_guest(
            Box::new(conn),
            &guest,
            "joiner",
            &mut store,
            &mesh,
            Capability::all(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("test"));
        let msgs = sent.lock().unwrap();
        assert!(
            matches!(msgs.first(), Some(ControlMessage::JoinRequest { .. })),
            "{msgs:?}"
        );
        assert!(
            !msgs
                .iter()
                .any(|m| matches!(m, ControlMessage::OpenChannel { .. })),
            "introduce must not OpenChannel: {msgs:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    struct RecordGuestConn {
        peer: DeviceId,
        sent: Arc<Mutex<Vec<ControlMessage>>>,
        reply: tokio::sync::Mutex<Option<Frame>>,
    }

    #[async_trait::async_trait]
    impl PeerConnection for RecordGuestConn {
        fn peer_id(&self) -> DeviceId {
            self.peer
        }
        async fn send_frame(&self, frame: Frame) -> mymesh_core::Result<()> {
            if let Ok(msg) = decode_msg::<ControlMessage>(&frame.payload) {
                self.sent.lock().unwrap().push(msg);
            }
            Ok(())
        }
        async fn recv_frame(&self) -> mymesh_core::Result<Frame> {
            self.reply
                .lock()
                .await
                .take()
                .ok_or_else(|| mymesh_core::Error::Other("no reply".into()))
        }
        async fn close(&self) -> mymesh_core::Result<()> {
            Ok(())
        }
        async fn send_raw(&self, _data: &[u8]) -> mymesh_core::Result<()> {
            Ok(())
        }
        async fn recv_raw(&self) -> mymesh_core::Result<Vec<u8>> {
            Err(mymesh_core::Error::Other("not implemented".into()))
        }
    }

    #[test]
    fn resolve_guest_grant_fail_closed() {
        let root = tmp_root("grant-resolve");
        let grants_path = root.join("grants.json");
        let host = DeviceId::from_bytes([0x01; 32]);
        let subject = DeviceId::from_bytes([0x02; 32]);
        let mut grants = GrantStore::open(&grants_path).unwrap();
        let g = grants
            .create_guest(
                "mesh-x",
                subject,
                host,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host),
            )
            .unwrap();

        // wrong subject
        let err = resolve_guest_grant_for_accept(
            &grants_path,
            &g.grant_id,
            &DeviceId::from_bytes([0x99; 32]),
            &host,
            "mesh-x",
        )
        .unwrap_err();
        assert!(err.to_string().contains("subject") || err.to_string().contains("Permission"));

        // missing grant
        assert!(
            resolve_guest_grant_for_accept(&grants_path, "NOPE", &subject, &host, "mesh-x",)
                .is_err()
        );

        // happy path
        let ok =
            resolve_guest_grant_for_accept(&grants_path, &g.grant_id, &subject, &host, "mesh-x")
                .unwrap();
        assert_eq!(ok.grant_id, g.grant_id);

        // revoked
        grants.revoke(&g.grant_id).unwrap();
        assert!(resolve_guest_grant_for_accept(
            &grants_path,
            &g.grant_id,
            &subject,
            &host,
            "mesh-x",
        )
        .is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn guest_accept_skips_membership_snapshot() {
        let root = tmp_root("guest-join");
        let host_data = root.join("host");
        let guest_data = root.join("guest");
        std::fs::create_dir_all(&host_data).unwrap();
        std::fs::create_dir_all(&guest_data).unwrap();

        let id_host = Identity::generate();
        let id_guest = Identity::generate();
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();

        let devices_path = host_data.join("devices.json");
        let grants_path = host_data.join("grants.json");
        let arm_path = host_data.join("arm.json");
        let join_dir = host_data.join("join");
        let mesh_path = host_data.join("mesh.json");
        MeshState::new_mesh().save(&mesh_path).unwrap();
        let mesh = MeshState::load(&mesh_path).unwrap();

        // Pre-existing member on host — must not leak to guest
        {
            let mut store = DeviceStore::open(&devices_path).unwrap();
            store
                .upsert(DeviceRecord {
                    id: DeviceId::from_bytes([0xee; 32]),
                    label: DeviceLabel::new("secret-member"),
                    fingerprint: "fp-ee".into(),
                    capabilities: Capability::all(),
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: None,
                    endpoint_hint: None,
                    mesh_id: Some(mesh.mesh_id.clone()),
                    aliases: vec![],
                    groups: vec![],
                    mesh_role: MeshRole::Member,
                })
                .unwrap();
        }

        let mut grants = GrantStore::open(&grants_path).unwrap();
        let grant = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal, Capability::Files],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        ArmState::arm_with_guest_grant(&arm_path, 120, &grant.grant_id).unwrap();

        let fabric = LocalFabric::new();
        let ep_host = fabric.endpoint(host_id);
        let ep_guest = fabric.endpoint(guest_id);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();

        let host_secret = id_host.to_secret_bytes();
        let guest_secret = id_guest.to_secret_bytes();

        let host_fut = async move {
            let id = Identity::from_secret_bytes(host_secret);
            let conn = ep_host.accept().await.unwrap();
            let cap = CaptureConn {
                inner: conn,
                sent: sent_c,
            };
            handle_join_as_host_with_grants(
                Box::new(cap),
                &id,
                "host",
                &devices_path,
                &grants_path,
                &arm_path,
                &join_dir,
                &mesh_path,
                120,
                None,
            )
            .await
        };

        let guest_devices = guest_data.join("devices.json");
        let guest_mesh = guest_data.join("mesh.json");
        MeshState::new_mesh().save(&guest_mesh).unwrap();
        let guest_fut = async move {
            let id = Identity::from_secret_bytes(guest_secret);
            let mut store = DeviceStore::open(&guest_devices).unwrap();
            let conn = ep_guest.connect(host_id).await.unwrap();
            run_join_as_guest(
                conn,
                &id,
                "guest",
                &mut store,
                &guest_mesh,
                vec![Capability::Terminal],
            )
            .await
            .map(|r| (r, store))
        };

        // Accept after pending appears
        let join_dir_accept = host_data.join("join");
        let accept_fut = async move {
            let joins = JoinStore::open(&join_dir_accept).unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let pending = joins.list_pending().unwrap();
                if !pending.is_empty() {
                    joins
                        .write_decision(&pending[0].device_id, JoinDecision::Accept)
                        .unwrap();
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    panic!("timeout waiting pending");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };

        let (host_res, guest_res, _) = tokio::join!(host_fut, guest_fut, accept_fut);
        assert_eq!(host_res.expect("host"), JoinHostOutcome::GuestAccepted);
        let (host_rec, store_g) = guest_res.expect("guest");

        // Guest only knows object host, as Guest role bilateral
        assert_eq!(host_rec.id, host_id);
        assert_eq!(host_rec.mesh_role, MeshRole::Guest);
        assert_eq!(store_g.list().len(), 1);
        assert!(!store_g
            .list()
            .iter()
            .any(|d| d.id == DeviceId::from_bytes([0xee; 32])));

        // Host recorded joiner as Guest with grant caps
        let store_h = DeviceStore::open(host_data.join("devices.json")).unwrap();
        let guest_rec = store_h.get(&guest_id).expect("guest on host");
        assert_eq!(guest_rec.mesh_role, MeshRole::Guest);
        assert!(guest_rec.capabilities.contains(&Capability::Terminal));
        assert!(!guest_rec.capabilities.contains(&Capability::Desktop));

        // Wire: JoinAccept present, no MembershipSnapshot
        let msgs = sent.lock().unwrap().clone();
        assert!(
            msgs.iter()
                .any(|m| matches!(m, ControlMessage::JoinAccept { .. })),
            "expected JoinAccept, got {msgs:?}"
        );
        assert!(
            !msgs
                .iter()
                .any(|m| matches!(m, ControlMessage::MembershipSnapshot { .. })),
            "guest must not receive MembershipSnapshot: {msgs:?}"
        );

        // build_snapshot on host still excludes the guest
        let members = members_from_store(&store_h, host_id, "host");
        assert!(
            !members.iter().any(|m| m.id == guest_id),
            "guest filtered from snapshot"
        );
        assert!(members
            .iter()
            .any(|m| m.id == DeviceId::from_bytes([0xee; 32])));

        // Session-open path must not send mesh gossip to guests either (GUEST.md).
        assert!(
            !crate::mesh_sync::peer_receives_mesh_gossip(&store_h, &guest_id),
            "guest peer must not receive session-open MembershipSnapshot"
        );
        assert!(!crate::mesh_sync::peer_may_mutate_grants(
            &store_h, &guest_id
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn member_accept_sends_membership_snapshot_without_guests() {
        let root = tmp_root("member-join");
        let host_data = root.join("host");
        let joiner_data = root.join("joiner");
        std::fs::create_dir_all(&host_data).unwrap();
        std::fs::create_dir_all(&joiner_data).unwrap();

        let id_host = Identity::generate();
        let id_join = Identity::generate();
        let host_id = id_host.device_id();
        let join_id = id_join.device_id();

        let devices_path = host_data.join("devices.json");
        let arm_path = host_data.join("arm.json");
        let join_dir = host_data.join("join");
        let mesh_path = host_data.join("mesh.json");
        MeshState::new_mesh().save(&mesh_path).unwrap();
        let mesh = MeshState::load(&mesh_path).unwrap();

        {
            let mut store = DeviceStore::open(&devices_path).unwrap();
            // existing member
            store
                .upsert(DeviceRecord {
                    id: DeviceId::from_bytes([0xab; 32]),
                    label: DeviceLabel::new("peer-ab"),
                    fingerprint: "fp-ab".into(),
                    capabilities: Capability::all(),
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: None,
                    endpoint_hint: None,
                    mesh_id: Some(mesh.mesh_id.clone()),
                    aliases: vec![],
                    groups: vec![],
                    mesh_role: MeshRole::Member,
                })
                .unwrap();
            // existing guest — must not appear in snapshot to new member
            store
                .upsert(DeviceRecord {
                    id: DeviceId::from_bytes([0xcd; 32]),
                    label: DeviceLabel::new("guest-cd"),
                    fingerprint: "fp-cd".into(),
                    capabilities: vec![Capability::Terminal],
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: None,
                    endpoint_hint: None,
                    mesh_id: Some(mesh.mesh_id.clone()),
                    aliases: vec![],
                    groups: vec![],
                    mesh_role: MeshRole::Guest,
                })
                .unwrap();
        }

        ArmState::arm(&arm_path, 120).unwrap();

        let fabric = LocalFabric::new();
        let ep_host = fabric.endpoint(host_id);
        let ep_join = fabric.endpoint(join_id);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();
        let host_secret = id_host.to_secret_bytes();
        let join_secret = id_join.to_secret_bytes();

        let host_fut = async move {
            let id = Identity::from_secret_bytes(host_secret);
            let conn = ep_host.accept().await.unwrap();
            let cap = CaptureConn {
                inner: conn,
                sent: sent_c,
            };
            handle_join_as_host(
                Box::new(cap),
                &id,
                "host",
                &devices_path,
                &arm_path,
                &join_dir,
                &mesh_path,
                120,
                None,
            )
            .await
        };

        let join_devices = joiner_data.join("devices.json");
        let join_mesh = joiner_data.join("mesh.json");
        MeshState::new_mesh().save(&join_mesh).unwrap();
        let guest_fut = async move {
            let id = Identity::from_secret_bytes(join_secret);
            let mut store = DeviceStore::open(&join_devices).unwrap();
            let conn = ep_join.connect(host_id).await.unwrap();
            run_join_as_guest(
                conn,
                &id,
                "joiner",
                &mut store,
                &join_mesh,
                Capability::all(),
            )
            .await
            .map(|r| (r, store))
        };

        let join_dir_accept = host_data.join("join");
        let accept_fut = async move {
            let joins = JoinStore::open(&join_dir_accept).unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let pending = joins.list_pending().unwrap();
                if !pending.is_empty() {
                    joins
                        .write_decision(&pending[0].device_id, JoinDecision::Accept)
                        .unwrap();
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    panic!("timeout waiting pending");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };

        let (host_res, join_res, _) = tokio::join!(host_fut, guest_fut, accept_fut);
        assert_eq!(host_res.expect("host"), JoinHostOutcome::MemberAccepted);
        let (host_rec, store_j) = join_res.expect("joiner");
        assert_eq!(host_rec.mesh_role, MeshRole::Member);
        // Joiner learned host + peer-ab, not guest-cd
        assert!(store_j.is_trusted(&host_id));
        assert!(store_j.is_trusted(&DeviceId::from_bytes([0xab; 32])));
        assert!(!store_j.is_trusted(&DeviceId::from_bytes([0xcd; 32])));

        let msgs = sent.lock().unwrap().clone();
        let snap = msgs
            .iter()
            .find_map(|m| match m {
                ControlMessage::MembershipSnapshot { members, .. } => Some(members.clone()),
                _ => None,
            })
            .expect("member join must send MembershipSnapshot");
        assert!(
            !snap
                .iter()
                .any(|m| m.id == DeviceId::from_bytes([0xcd; 32])),
            "snapshot must exclude guests"
        );
        assert!(snap
            .iter()
            .any(|m| m.id == DeviceId::from_bytes([0xab; 32])));

        let store_h = DeviceStore::open(host_data.join("devices.json")).unwrap();
        assert_eq!(store_h.get(&join_id).unwrap().mesh_role, MeshRole::Member);

        let _ = std::fs::remove_dir_all(root);
    }

    /// Session-open path: after handshake, host must not push MembershipSnapshot to guests
    /// (mirrors agent `handle_session` gate via `peer_receives_mesh_gossip`).
    #[tokio::test]
    async fn session_open_skips_snapshot_for_guest_peer() {
        use crate::mesh_sync::{build_snapshot, peer_receives_mesh_gossip};
        use crate::session::Session;
        use mymesh_protocol::{encode_msg, ChannelId, Frame};

        let root = tmp_root("session-guest");
        let host_data = root.join("host");
        let guest_data = root.join("guest");
        std::fs::create_dir_all(&host_data).unwrap();
        std::fs::create_dir_all(&guest_data).unwrap();

        let id_host = Identity::generate();
        let id_guest = Identity::generate();
        let host_id = id_host.device_id();
        let guest_id = id_guest.device_id();

        let mesh_path = host_data.join("mesh.json");
        MeshState::new_mesh().save(&mesh_path).unwrap();
        let mesh = MeshState::load(&mesh_path).unwrap();

        let mut store_h = DeviceStore::open(host_data.join("devices.json")).unwrap();
        store_h
            .upsert(DeviceRecord {
                id: DeviceId::from_bytes([0xee; 32]),
                label: DeviceLabel::new("secret-member"),
                fingerprint: "fp-ee".into(),
                capabilities: Capability::all(),
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: MeshRole::Member,
            })
            .unwrap();
        store_h
            .upsert(DeviceRecord {
                id: guest_id,
                label: DeviceLabel::new("guest"),
                fingerprint: "fp-g".into(),
                capabilities: vec![Capability::Terminal],
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: MeshRole::Guest,
            })
            .unwrap();

        let mut store_g = DeviceStore::open(guest_data.join("devices.json")).unwrap();
        store_g
            .upsert(DeviceRecord {
                id: host_id,
                label: DeviceLabel::new("host"),
                fingerprint: "fp-h".into(),
                capabilities: Capability::all(),
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: None,
                aliases: vec![],
                groups: vec![],
                mesh_role: MeshRole::Guest,
            })
            .unwrap();

        let mut grants = GrantStore::open(host_data.join("grants.json")).unwrap();
        grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_id,
                host_id,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host_id),
            )
            .unwrap();
        let grants = GrantStore::open(host_data.join("grants.json")).unwrap();

        assert!(!peer_receives_mesh_gossip(&store_h, &guest_id));

        let fabric = LocalFabric::new();
        let ep_host = fabric.endpoint(host_id);
        let ep_guest = fabric.endpoint(guest_id);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();
        let host_secret = id_host.to_secret_bytes();
        let guest_secret = id_guest.to_secret_bytes();

        let host_fut = async move {
            let id = Identity::from_secret_bytes(host_secret);
            let conn = ep_host.accept().await.unwrap();
            let cap = CaptureConn {
                inner: conn,
                sent: sent_c,
            };
            let session = Session::handshake_acceptor_with_grants(
                Box::new(cap),
                &id,
                "host",
                &store_h,
                Some(&grants),
                vec![Capability::Terminal],
            )
            .await
            .expect("handshake");
            let peer = session.peer_id();
            let conn = session.into_conn();
            // Same gate as agent handle_session
            if peer_receives_mesh_gossip(&store_h, &peer) {
                let snap = build_snapshot(&id, "host", &store_h, &mesh, 0);
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&snap).unwrap(),
                })
                .await
                .unwrap();
            }
            let _ = conn.close().await;
        };

        let guest_fut = async move {
            let id = Identity::from_secret_bytes(guest_secret);
            let conn = ep_guest.connect(host_id).await.unwrap();
            Session::handshake_dialer_with_grants(
                conn,
                &id,
                "guest",
                &store_g,
                None,
                vec![Capability::Terminal],
            )
            .await
            .expect("guest handshake");
        };

        let ((), ()) = tokio::join!(host_fut, guest_fut);
        let msgs = sent.lock().unwrap().clone();
        assert!(
            !msgs
                .iter()
                .any(|m| matches!(m, ControlMessage::MembershipSnapshot { .. })),
            "session open must not send MembershipSnapshot to guest: {msgs:?}"
        );
        // HelloAck is expected
        assert!(
            msgs.iter()
                .any(|m| matches!(m, ControlMessage::HelloAck { .. })),
            "expected HelloAck: {msgs:?}"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
