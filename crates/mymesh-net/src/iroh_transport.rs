//! Iroh-backed P2P transport (QUIC + hole punch + relays).
use crate::traits::{PeerConnection, Transport};
use async_trait::async_trait;
use iroh::endpoint::{presets, Connection, Endpoint, RecvStream, SendStream};
use iroh::{EndpointId, SecretKey};
use mymesh_core::{DeviceId, Error, Result};
use mymesh_crypto::Identity;
use mymesh_protocol::{read_frame, write_frame, Frame, ALPN, ALPN_ENROLL};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Which ALPN was negotiated on an accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedAlpn {
    /// Standard mymesh/1 protocol.
    Mesh,
    /// Enrollment protocol mymesh-enroll/1.
    Enroll,
}

pub struct IrohTransport {
    endpoint: Endpoint,
    local_id: DeviceId,
}

impl IrohTransport {
    /// Bind an iroh endpoint using the MyMesh identity seed.
    /// Accepts both standard mesh ALPN and enrollment ALPN.
    pub async fn bind(identity: &Identity) -> Result<Self> {
        let secret = SecretKey::from_bytes(&identity.to_secret_bytes());
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec(), ALPN_ENROLL.to_vec()])
            .bind()
            .await
            .map_err(|e| Error::Session(format!("iroh bind: {e}")))?;

        let local_id = identity.device_id();
        let iroh_id = endpoint.id();
        if iroh_id.as_bytes() != local_id.as_bytes() {
            return Err(Error::Identity(
                "iroh EndpointId does not match MyMesh DeviceId".into(),
            ));
        }

        info!(
            id = %local_id.short(),
            "iroh endpoint bound (mesh + enroll ALPNs)"
        );

        Ok(Self { endpoint, local_id })
    }

    /// Bind with only the standard mesh ALPN (for tests/compat).
    pub async fn bind_mesh_only(identity: &Identity) -> Result<Self> {
        let secret = SecretKey::from_bytes(&identity.to_secret_bytes());
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| Error::Session(format!("iroh bind: {e}")))?;

        let local_id = identity.device_id();
        let iroh_id = endpoint.id();
        if iroh_id.as_bytes() != local_id.as_bytes() {
            return Err(Error::Identity(
                "iroh EndpointId does not match MyMesh DeviceId".into(),
            ));
        }

        info!(
            id = %local_id.short(),
            "iroh endpoint bound (mesh ALPN only)"
        );

        Ok(Self { endpoint, local_id })
    }

    /// Accept a connection and return which ALPN was negotiated.
    pub async fn accept_with_alpn(&self) -> Result<(Box<dyn PeerConnection>, AcceptedAlpn)> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| Error::Session("endpoint closed".into()))?;
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(%e, "incoming connection failed");
                    continue;
                }
            };
            let alpn = match conn.alpn() {
                alpn if alpn == ALPN => AcceptedAlpn::Mesh,
                alpn if alpn == ALPN_ENROLL => AcceptedAlpn::Enroll,
                other => {
                    warn!(alpn = ?other, "unknown ALPN, rejecting");
                    conn.close(1u32.into(), b"unknown ALPN");
                    continue;
                }
            };
            match IrohConn::open_as_acceptor(conn).await {
                Ok(c) => return Ok((Box::new(c), alpn)),
                Err(e) => warn!(%e, "accept_bi failed"),
            }
        }
    }

    /// Connect using the enrollment ALPN.
    pub async fn connect_enroll(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>> {
        let eid = EndpointId::from_bytes(peer.as_bytes())
            .map_err(|e| Error::Session(format!("bad peer id: {e}")))?;
        debug!(peer = %peer.short(), "iroh connect (enroll)");
        let conn = self
            .endpoint
            .connect(eid, ALPN_ENROLL)
            .await
            .map_err(|e| Error::Session(format!("iroh connect enroll: {e}")))?;
        Ok(Box::new(IrohConn::open_as_dialer(conn).await?))
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn endpoint_addr_json(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self.endpoint.addr()).map_err(|e| Error::Serialize(e.to_string()))
    }

    pub async fn shutdown(self) {
        self.endpoint.close().await;
    }
}

struct IrohConn {
    peer: DeviceId,
    send: Mutex<SendStream>,
    recv: Mutex<RecvStream>,
    conn: Connection,
}

impl IrohConn {
    async fn open_as_dialer(conn: Connection) -> Result<Self> {
        let peer = DeviceId::from_bytes(*conn.remote_id().as_bytes());
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Session(format!("open_bi: {e}")))?;
        Ok(Self {
            peer,
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            conn,
        })
    }

    async fn open_as_acceptor(conn: Connection) -> Result<Self> {
        let peer = DeviceId::from_bytes(*conn.remote_id().as_bytes());
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Session(format!("accept_bi: {e}")))?;
        Ok(Self {
            peer,
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            conn,
        })
    }
}

#[async_trait]
impl PeerConnection for IrohConn {
    fn peer_id(&self) -> DeviceId {
        self.peer
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        let mut send = self.send.lock().await;
        write_frame(&mut *send, &frame)
            .await
            .map_err(|e| Error::Session(format!("send frame: {e}")))
    }

    async fn recv_frame(&self) -> Result<Frame> {
        let mut recv = self.recv.lock().await;
        read_frame(&mut *recv)
            .await
            .map_err(|e| Error::Session(format!("recv frame: {e}")))
    }

    async fn close(&self) -> Result<()> {
        self.conn.close(0u32.into(), b"bye");
        Ok(())
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut send = self.send.lock().await;
        send.write_all(data)
            .await
            .map_err(|e| Error::Session(format!("send raw: {e}")))?;
        send.flush()
            .await
            .map_err(|e| Error::Session(format!("flush raw: {e}")))
    }

    async fn recv_raw(&self) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut recv = self.recv.lock().await;
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Session(format!("recv raw len: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > mymesh_protocol::MAX_JSON_MSG_BYTES {
            return Err(Error::Protocol("message too large".into()));
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| Error::Session(format!("recv raw payload: {e}")))?;
        // Return the full message including the length prefix
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&payload);
        Ok(full)
    }
}

#[async_trait]
impl Transport for IrohTransport {
    fn local_id(&self) -> DeviceId {
        self.local_id
    }

    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>> {
        let eid = EndpointId::from_bytes(peer.as_bytes())
            .map_err(|e| Error::Session(format!("bad peer id: {e}")))?;
        debug!(peer = %peer.short(), "iroh connect");
        let conn = self
            .endpoint
            .connect(eid, ALPN)
            .await
            .map_err(|e| Error::Session(format!("iroh connect: {e}")))?;
        Ok(Box::new(IrohConn::open_as_dialer(conn).await?))
    }

    async fn accept(&self) -> Result<Box<dyn PeerConnection>> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| Error::Session("endpoint closed".into()))?;
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(%e, "incoming connection failed");
                    continue;
                }
            };
            match IrohConn::open_as_acceptor(conn).await {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) => warn!(%e, "accept_bi failed"),
            }
        }
    }
}

#[derive(Clone)]
pub struct SharedIroh(pub Arc<IrohTransport>);

impl SharedIroh {
    pub async fn bind(identity: &Identity) -> Result<Self> {
        Ok(Self(Arc::new(IrohTransport::bind(identity).await?)))
    }
}
