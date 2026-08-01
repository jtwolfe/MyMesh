use async_trait::async_trait;
use mymesh_core::{Error, Result};
use mymesh_protocol::PairingMessage;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Pairing rendezvous: short-lived mailbox keyed by pairing code.
///
/// Implementations must provide **directional** delivery so host and guest never
/// receive their own messages when exchanging SPAKE2 blobs concurrently.
#[async_trait]
pub trait Rendezvous: Send + Sync {
    /// Publish a message toward the peer.
    ///
    /// `as_host == true` means this node is the pairing host (code display).
    async fn send(&self, code: &str, as_host: bool, msg: PairingMessage) -> Result<()>;
    /// Wait for the next message from the peer.
    async fn recv(&self, code: &str, as_host: bool) -> Result<PairingMessage>;
}

#[derive(Default)]
struct Lane {
    queue: VecDeque<PairingMessage>,
    waiters: VecDeque<oneshot::Sender<PairingMessage>>,
}

enum Pending {
    Ready(PairingMessage),
    Wait(oneshot::Receiver<PairingMessage>),
}

impl Lane {
    fn push(&mut self, msg: PairingMessage) {
        if let Some(w) = self.waiters.pop_front() {
            let _ = w.send(msg);
        } else {
            self.queue.push_back(msg);
        }
    }

    fn take_or_wait(&mut self) -> Pending {
        if let Some(msg) = self.queue.pop_front() {
            Pending::Ready(msg)
        } else {
            let (tx, rx) = oneshot::channel();
            self.waiters.push_back(tx);
            Pending::Wait(rx)
        }
    }
}

#[derive(Default)]
struct Duplex {
    /// Messages traveling host → guest.
    h2g: Lane,
    /// Messages traveling guest → host.
    g2h: Lane,
}

#[derive(Clone, Default)]
pub struct LocalRendezvous {
    boxes: Arc<Mutex<HashMap<String, Arc<Mutex<Duplex>>>>>,
}

impl LocalRendezvous {
    pub fn new() -> Self {
        Self::default()
    }

    fn duplex(&self, code: &str) -> Arc<Mutex<Duplex>> {
        let mut g = self.boxes.lock();
        g.entry(code.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Duplex::default())))
            .clone()
    }
}

#[async_trait]
impl Rendezvous for LocalRendezvous {
    async fn send(&self, code: &str, as_host: bool, msg: PairingMessage) -> Result<()> {
        let box_ = self.duplex(code);
        let mut g = box_.lock();
        if as_host {
            g.h2g.push(msg);
        } else {
            g.g2h.push(msg);
        }
        Ok(())
    }

    async fn recv(&self, code: &str, as_host: bool) -> Result<PairingMessage> {
        let box_ = self.duplex(code);
        let pending = {
            let mut g = box_.lock();
            // Host receives on guest→host lane; guest receives on host→guest lane.
            if as_host {
                g.g2h.take_or_wait()
            } else {
                g.h2g.take_or_wait()
            }
        };
        match pending {
            Pending::Ready(msg) => Ok(msg),
            Pending::Wait(rx) => rx
                .await
                .map_err(|_| Error::Pairing("rendezvous closed".into())),
        }
    }
}
