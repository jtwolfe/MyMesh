use crate::traits::{PeerConnection, Transport};
use async_trait::async_trait;
use mymesh_core::{DeviceId, Error, Result};
use mymesh_protocol::Frame;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Default)]
struct Inbox {
    queue: VecDeque<Box<dyn PeerConnection>>,
    waiters: VecDeque<oneshot::Sender<Box<dyn PeerConnection>>>,
}

/// Shared registry of local endpoints for same-process / test networking.
#[derive(Clone, Default)]
pub struct LocalFabric {
    inner: Arc<Mutex<HashMap<DeviceId, Arc<Mutex<Inbox>>>>>,
}

impl LocalFabric {
    pub fn new() -> Self {
        Self::default()
    }

    fn inbox(&self, id: DeviceId) -> Arc<Mutex<Inbox>> {
        let mut g = self.inner.lock();
        g.entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(Inbox::default())))
            .clone()
    }

    pub fn endpoint(&self, id: DeviceId) -> FabricEndpoint {
        FabricEndpoint {
            id,
            fabric: self.clone(),
        }
    }
}

pub struct FabricEndpoint {
    id: DeviceId,
    fabric: LocalFabric,
}

pub struct FabricConnection {
    peer: DeviceId,
    tx: mpsc::Sender<Frame>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Frame>>,
}

impl FabricConnection {
    fn pair(a: DeviceId, b: DeviceId) -> (Self, Self) {
        let (tx_ab, rx_ab) = mpsc::channel(128);
        let (tx_ba, rx_ba) = mpsc::channel(128);
        (
            Self {
                peer: b,
                tx: tx_ab,
                rx: tokio::sync::Mutex::new(rx_ba),
            },
            Self {
                peer: a,
                tx: tx_ba,
                rx: tokio::sync::Mutex::new(rx_ab),
            },
        )
    }
}

#[async_trait]
impl PeerConnection for FabricConnection {
    fn peer_id(&self) -> DeviceId {
        self.peer
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| Error::Session("peer disconnected".into()))
    }

    async fn recv_frame(&self) -> Result<Frame> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Session("connection closed".into()))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use mymesh_protocol::ChannelId;
        let frame = Frame {
            channel: ChannelId::control(),
            payload: bytes::Bytes::copy_from_slice(data),
        };
        self.send_frame(frame).await
    }

    async fn recv_raw(&self) -> Result<Vec<u8>> {
        let frame = self.recv_frame().await?;
        Ok(frame.payload.to_vec())
    }
}

#[async_trait]
impl Transport for FabricEndpoint {
    fn local_id(&self) -> DeviceId {
        self.id
    }

    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>> {
        if peer == self.id {
            return Err(Error::Session("cannot connect to self".into()));
        }
        let (mine, theirs) = FabricConnection::pair(self.id, peer);
        let inbox = self.fabric.inbox(peer);
        {
            let mut ib = inbox.lock();
            if let Some(waiter) = ib.waiters.pop_front() {
                let _ = waiter.send(Box::new(theirs));
            } else {
                ib.queue.push_back(Box::new(theirs));
            }
        }
        Ok(Box::new(mine))
    }

    async fn accept(&self) -> Result<Box<dyn PeerConnection>> {
        let inbox = self.fabric.inbox(self.id);
        let rx = {
            let mut ib = inbox.lock();
            if let Some(conn) = ib.queue.pop_front() {
                return Ok(conn);
            }
            let (tx, rx) = oneshot::channel();
            ib.waiters.push_back(tx);
            rx
        };
        rx.await
            .map_err(|_| Error::Session("accept cancelled".into()))
    }
}
