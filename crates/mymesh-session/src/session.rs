use bytes::Bytes;
use mymesh_core::{allows, Capability, DeviceId, DeviceStore, GrantStore, Result};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame, ALPN};
use tracing::debug;

/// Authenticated session over an established peer connection.
pub struct Session {
    conn: Box<dyn PeerConnection>,
    local_id: DeviceId,
    peer_id: DeviceId,
    capabilities: Vec<Capability>,
}

impl Session {
    pub fn alpn() -> &'static [u8] {
        ALPN
    }

    /// Dialer-side handshake: send Hello, expect HelloAck.
    pub async fn handshake_dialer(
        conn: Box<dyn PeerConnection>,
        identity: &Identity,
        label: &str,
        store: &DeviceStore,
        offered: Vec<Capability>,
    ) -> Result<Self> {
        Self::handshake_dialer_with_grants(conn, identity, label, store, None, offered).await
    }

    /// Dialer handshake with optional grant-aware path (S5 guests).
    pub async fn handshake_dialer_with_grants(
        conn: Box<dyn PeerConnection>,
        identity: &Identity,
        label: &str,
        store: &DeviceStore,
        grants: Option<&GrantStore>,
        offered: Vec<Capability>,
    ) -> Result<Self> {
        let peer_id = conn.peer_id();
        if !store.is_trusted(&peer_id) {
            return Err(mymesh_core::Error::PermissionDenied(format!(
                "peer {peer_id} is not a linked device"
            )));
        }
        let local_id = identity.device_id();
        // Filter offered caps for guests when grants present (fail-closed if guest + no grants).
        let offered = filter_offered_caps(store, grants, &local_id, &peer_id, offered);
        let material = [local_id.as_bytes().as_slice(), label.as_bytes()].concat();
        let hello = ControlMessage::Hello {
            protocol_version: 1,
            device_id: local_id,
            label: label.to_string(),
            capabilities: offered.clone(),
            signature: identity.sign(&material),
        };
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&hello)?,
        })
        .await?;

        let frame = conn.recv_frame().await?;
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        match msg {
            ControlMessage::HelloAck {
                device_id,
                label: peer_label,
                accepted_capabilities,
                ..
            } => {
                if device_id != peer_id {
                    return Err(mymesh_core::Error::Protocol("peer id mismatch".into()));
                }
                debug!(%peer_label, ?accepted_capabilities, "dialer handshake ok");
            }
            other => {
                return Err(mymesh_core::Error::Protocol(format!(
                    "expected HelloAck, got {other:?}"
                )))
            }
        }

        Ok(Self {
            conn,
            local_id,
            peer_id,
            capabilities: offered,
        })
    }

    /// Acceptor-side handshake: expect Hello, send HelloAck.
    pub async fn handshake_acceptor(
        conn: Box<dyn PeerConnection>,
        identity: &Identity,
        label: &str,
        store: &DeviceStore,
        offered: Vec<Capability>,
    ) -> Result<Self> {
        Self::handshake_acceptor_with_grants(conn, identity, label, store, None, offered).await
    }

    /// Acceptor handshake with grant-aware capability intersection (S5).
    pub async fn handshake_acceptor_with_grants(
        conn: Box<dyn PeerConnection>,
        identity: &Identity,
        label: &str,
        store: &DeviceStore,
        grants: Option<&GrantStore>,
        offered: Vec<Capability>,
    ) -> Result<Self> {
        let peer_id = conn.peer_id();
        if !store.is_trusted(&peer_id) {
            return Err(mymesh_core::Error::PermissionDenied(format!(
                "peer {peer_id} is not a linked device — unlink/ignore"
            )));
        }

        let frame = conn.recv_frame().await?;
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        let peer_caps = match msg {
            ControlMessage::Hello {
                protocol_version,
                device_id,
                label: peer_label,
                capabilities,
                ..
            } => {
                if protocol_version != 1 {
                    return Err(mymesh_core::Error::Protocol(format!(
                        "unsupported protocol {protocol_version}"
                    )));
                }
                if device_id != peer_id {
                    return Err(mymesh_core::Error::Protocol("peer id mismatch".into()));
                }
                debug!(%peer_label, ?capabilities, "acceptor got hello");
                capabilities
            }
            other => {
                return Err(mymesh_core::Error::Protocol(format!(
                    "expected Hello, got {other:?}"
                )))
            }
        };

        let local_id = identity.device_id();
        // Intersect offered ∩ peer_caps ∩ policy (member caps or active grant).
        let mut accepted: Vec<Capability> = offered
            .iter()
            .filter(|c| peer_caps.contains(c))
            .cloned()
            .collect();
        accepted.retain(|c| peer_allows(store, grants, &local_id, &peer_id, c));

        let material = [local_id.as_bytes().as_slice(), label.as_bytes()].concat();
        let ack = ControlMessage::HelloAck {
            device_id: local_id,
            label: label.to_string(),
            accepted_capabilities: accepted.clone(),
            signature: identity.sign(&material),
        };
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&ack)?,
        })
        .await?;

        Ok(Self {
            conn,
            local_id,
            peer_id,
            capabilities: accepted,
        })
    }

    /// Legacy symmetric handshake used by local fabric demos.
    pub async fn handshake(
        conn: Box<dyn PeerConnection>,
        identity: &Identity,
        label: &str,
        store: &DeviceStore,
        offered: Vec<Capability>,
    ) -> Result<Self> {
        // Prefer dialer path for demos (both sides send Hello then Ack — best-effort).
        Self::handshake_dialer(conn, identity, label, store, offered).await
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub fn local_id(&self) -> DeviceId {
        self.local_id
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        self.conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(msg)?,
            })
            .await
    }

    pub async fn send_raw(&self, channel: ChannelId, payload: Bytes) -> Result<()> {
        self.conn.send_frame(Frame { channel, payload }).await
    }

    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.conn.send_frame(frame).await
    }

    pub async fn recv(&self) -> Result<Frame> {
        self.conn.recv_frame().await
    }

    pub fn into_conn(self) -> Box<dyn PeerConnection> {
        self.conn
    }

    pub async fn close(self) -> Result<()> {
        self.conn.close().await
    }
}

/// Policy check: members via device caps; guests via GrantStore (fail-closed without grants).
fn peer_allows(
    store: &DeviceStore,
    grants: Option<&GrantStore>,
    local_id: &DeviceId,
    peer: &DeviceId,
    cap: &Capability,
) -> bool {
    match grants {
        Some(g) => allows(store, g, local_id, peer, cap),
        None => store.allows(peer, cap),
    }
}

fn filter_offered_caps(
    store: &DeviceStore,
    grants: Option<&GrantStore>,
    local_id: &DeviceId,
    peer: &DeviceId,
    offered: Vec<Capability>,
) -> Vec<Capability> {
    // Dialer is the initiator; policy is primarily enforced on acceptor.
    // Still drop caps the local store would deny for this peer when grants known.
    match grants {
        Some(g) => offered
            .into_iter()
            .filter(|c| allows(store, g, local_id, peer, c))
            .collect(),
        None => offered,
    }
}
