use async_trait::async_trait;
use bytes::Bytes;
use mymesh_core::{DeviceId, Result};
use mymesh_protocol::Frame;
use tokio::sync::mpsc;

/// Bidirectional connection to one peer.
#[async_trait]
pub trait PeerConnection: Send + Sync {
    fn peer_id(&self) -> DeviceId;
    async fn send_frame(&self, frame: Frame) -> Result<()>;
    async fn recv_frame(&self) -> Result<Frame>;
    async fn close(&self) -> Result<()>;
}

#[derive(Debug)]
pub enum TransportEvent {
    Incoming { peer: DeviceId },
    Closed { peer: DeviceId },
}

/// Abstraction over the P2P fabric.
#[async_trait]
pub trait Transport: Send + Sync {
    fn local_id(&self) -> DeviceId;
    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>>;
    async fn accept(&self) -> Result<Box<dyn PeerConnection>>;
    fn events(&self) -> mpsc::Receiver<TransportEvent>;
}

/// Simple duplex pipe used for tests and local demos.
pub struct PipeConnection {
    peer: DeviceId,
    tx: tokio::sync::Mutex<tokio::sync::mpsc::Sender<Frame>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Frame>>,
}

impl PipeConnection {
    pub fn pair(a: DeviceId, b: DeviceId) -> (Self, Self) {
        let (tx_ab, rx_ab) = mpsc::channel(64);
        let (tx_ba, rx_ba) = mpsc::channel(64);
        (
            Self {
                peer: b,
                tx: tokio::sync::Mutex::new(tx_ab),
                rx: tokio::sync::Mutex::new(rx_ba),
            },
            Self {
                peer: a,
                tx: tokio::sync::Mutex::new(tx_ba),
                rx: tokio::sync::Mutex::new(rx_ab),
            },
        )
    }
}

#[async_trait]
impl PeerConnection for PipeConnection {
    fn peer_id(&self) -> DeviceId {
        self.peer
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.tx
            .lock()
            .await
            .send(frame)
            .await
            .map_err(|_| mymesh_core::Error::Session("peer gone".into()))
    }

    async fn recv_frame(&self) -> Result<Frame> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| mymesh_core::Error::Session("connection closed".into()))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

// Silence unused import in some feature sets
#[allow(dead_code)]
fn _bytes_marker() -> Bytes {
    Bytes::new()
}
