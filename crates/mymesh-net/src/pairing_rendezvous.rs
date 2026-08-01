//! Short-code rendezvous: peers meet by pairing code before they know each other's keys.
//!
//! Production: mailbox over HTTPS or iroh discovery tickets.
//! This module provides an in-process rendezvous for demos/tests, and a trait
//! for pluggable backends.

use async_trait::async_trait;
use mymesh_core::{Error, Result};
use mymesh_protocol::PairingMessage;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone, Debug)]
pub struct RendezvousMessage {
    pub code: String,
    pub body: PairingMessage,
}

#[async_trait]
pub trait Rendezvous: Send + Sync {
    /// Post a message into the mailbox for `code`.
    async fn send(&self, code: &str, msg: PairingMessage) -> Result<()>;
    /// Wait for the next message on `code` from the other side.
    async fn recv(&self, code: &str) -> Result<PairingMessage>;
}

type Slot = Arc<Mutex<Mailbox>>;

#[derive(Default)]
struct Mailbox {
    queue: Vec<PairingMessage>,
    waiters: Vec<oneshot::Sender<PairingMessage>>,
}

/// Process-local rendezvous (both sides of pairing in one process or tests).
#[derive(Clone, Default)]
pub struct LocalRendezvous {
    boxes: Arc<Mutex<HashMap<String, Slot>>>,
}

impl LocalRendezvous {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, code: &str) -> Slot {
        let mut map = self.boxes.lock();
        map.entry(code.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Mailbox::default())))
            .clone()
    }
}

#[async_trait]
impl Rendezvous for LocalRendezvous {
    async fn send(&self, code: &str, msg: PairingMessage) -> Result<()> {
        let slot = self.slot(code);
        let mut mb = slot.lock();
        if let Some(waiter) = mb.waiters.pop() {
            let _ = waiter.send(msg);
        } else {
            mb.queue.push(msg);
        }
        Ok(())
    }

    async fn recv(&self, code: &str) -> Result<PairingMessage> {
        let slot = self.slot(code);
        {
            let mut mb = slot.lock();
            if let Some(msg) = mb.queue.pop() {
                return Ok(msg);
            }
            let (tx, rx) = oneshot::channel();
            mb.waiters.push(tx);
            drop(mb);
            return rx
                .await
                .map_err(|_| Error::Pairing("rendezvous closed".into()));
        }
    }
}
