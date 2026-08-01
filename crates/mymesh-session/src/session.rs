use bytes::Bytes;
use mymesh_core::{Capability, DeviceId, DeviceStore, Result};
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
        let peer_id = conn.peer_id();
        if !store.is_trusted(&peer_id) {
            return Err(mymesh_core::Error::PermissionDenied(format!(
                "peer {peer_id} is not a linked device"
            )));
        }
        let local_id = identity.device_id();
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

        // Intersect capabilities with what we offer and what's stored.
        let mut accepted: Vec<Capability> = offered
            .iter()
            .filter(|c| peer_caps.contains(c))
            .cloned()
            .collect();
        if let Some(rec) = store.get(&peer_id) {
            accepted.retain(|c| rec.capabilities.contains(c));
        }

        let local_id = identity.device_id();
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
