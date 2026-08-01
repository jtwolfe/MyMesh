use bytes::Bytes;
use mymesh_core::{Capability, DeviceId, DeviceStore, Result};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame, ALPN};
use tracing::{debug, warn};

/// Authenticated session over an established peer connection.
pub struct Session {
    conn: Box<dyn PeerConnection>,
    local_id: DeviceId,
    peer_id: DeviceId,
    #[allow(dead_code)]
    capabilities: Vec<Capability>,
}

impl Session {
    pub fn alpn() -> &'static [u8] {
        ALPN
    }

    /// Perform control Hello / HelloAck using the device store as trust anchor.
    pub async fn handshake(
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
        let signature = identity.sign(&material);
        let hello = ControlMessage::Hello {
            protocol_version: 1,
            device_id: local_id,
            label: label.to_string(),
            capabilities: offered.clone(),
            signature,
        };
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&hello)?,
        })
        .await?;

        // Wait for peer hello or ack (symmetric hello for simplicity)
        let frame = conn.recv_frame().await?;
        if frame.channel.kind != mymesh_protocol::ChannelKind::Control {
            return Err(mymesh_core::Error::Protocol(
                "expected control channel".into(),
            ));
        }
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        match msg {
            ControlMessage::Hello {
                protocol_version,
                device_id,
                label: peer_label,
                capabilities: peer_caps,
                signature,
            } => {
                if protocol_version != 1 {
                    return Err(mymesh_core::Error::Protocol(format!(
                        "unsupported protocol {protocol_version}"
                    )));
                }
                if device_id != peer_id {
                    return Err(mymesh_core::Error::Protocol("peer id mismatch".into()));
                }
                debug!(%peer_label, ?peer_caps, "peer hello ok");
                let _ = signature; // full verify requires stored verifying key; v1 trusts link store
            }
            ControlMessage::HelloAck { .. } => {}
            other => {
                warn!(?other, "unexpected control message");
                return Err(mymesh_core::Error::Protocol("bad handshake".into()));
            }
        }

        // Send ack
        let ack = ControlMessage::HelloAck {
            device_id: local_id,
            label: label.to_string(),
            accepted_capabilities: offered.clone(),
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
            capabilities: offered,
        })
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub fn local_id(&self) -> DeviceId {
        self.local_id
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

    pub async fn recv(&self) -> Result<Frame> {
        self.conn.recv_frame().await
    }

    pub async fn close(self) -> Result<()> {
        self.conn.close().await
    }
}
