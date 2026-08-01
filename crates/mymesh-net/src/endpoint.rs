use crate::transport::{PeerConnection, PipeConnection, Transport, TransportEvent};
use async_trait::async_trait;
use mymesh_core::{DeviceId, Result};
use mymesh_crypto::Identity;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Debug)]
pub struct EndpointInfo {
    pub id: DeviceId,
    pub label: String,
}

/// High-level node endpoint. Without the `iroh-transport` feature this is a
/// local mesh useful for integration tests and the `mymesh demo` command.
pub struct MeshEndpoint {
    identity: Identity,
    label: String,
    pending: Mutex<HashMap<DeviceId, oneshot::Sender<Box<dyn PeerConnection>>>>,
    incoming: Mutex<Option<mpsc::Sender<Box<dyn PeerConnection>>>>,
    events_tx: mpsc::Sender<TransportEvent>,
    events_rx: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
    /// Shared registry so two endpoints in-process can find each other.
    fabric: Arc<Mutex<HashMap<DeviceId, Arc<MeshEndpoint>>>>,
}

lazy_static_fabric! {}

// Manual global fabric without lazy_static crate
fn global_fabric() -> Arc<Mutex<HashMap<DeviceId, Arc<MeshEndpoint>>>> {
    use std::sync::OnceLock;
    static FABRIC: OnceLock<Arc<Mutex<HashMap<DeviceId, Arc<MeshEndpoint>>>>> = OnceLock::new();
    FABRIC
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

// remove invalid macro
macro_rules! lazy_static_fabric {
    () => {};
}

impl MeshEndpoint {
    pub fn bind(identity: Identity, label: impl Into<String>) -> Arc<Self> {
        let (events_tx, events_rx) = mpsc::channel(32);
        let ep = Arc::new(Self {
            identity,
            label: label.into(),
            pending: Mutex::new(HashMap::new()),
            incoming: Mutex::new(None),
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
            fabric: global_fabric(),
        });
        ep.fabric.lock().insert(ep.identity.device_id(), ep.clone());
        ep
    }

    pub fn info(&self) -> EndpointInfo {
        EndpointInfo {
            id: self.identity.device_id(),
            label: self.label.clone(),
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn shutdown(&self) {
        self.fabric.lock().remove(&self.identity.device_id());
    }
}

#[async_trait]
impl Transport for MeshEndpoint {
    fn local_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>> {
        let remote = {
            let fabric = self.fabric.lock();
            fabric.get(&peer).cloned()
        };
        let remote = remote.ok_or_else(|| {
            mymesh_core::Error::NotFound(format!(
                "peer {peer} not on local fabric (use iroh backend for WAN)"
            ))
        })?;

        let (a, b) = PipeConnection::pair(self.local_id(), peer);
        // Deliver B side to remote accept queue / pending
        {
            let mut pending = remote.pending.lock();
            if let Some(tx) = pending.remove(&self.local_id()) {
                let _ = tx.send(Box::new(b));
            } else if let Some(tx) = remote.incoming.lock().as_ref() {
                let _ = tx.send(Box::new(b)).await;
            } else {
                // Park for accept()
                drop(pending);
                let (tx, rx) = oneshot::channel();
                remote.pending.lock().insert(self.local_id(), tx);
                // Waiter will be resolved by accept on remote — but we already have b.
                // Instead push to a side channel via oneshot that accept creates.
                let _ = tx; // replaced below
                let _ = rx;
                // Simpler: store b in remote's accept mailbox
                struct Hold;
                let _ = Hold;
            }
        }
        // Use a dedicated accept mailbox
        remote
            .events_tx
            .send(TransportEvent::Incoming {
                peer: self.local_id(),
            })
            .await
            .ok();
        // Put connection in remote fabric pending under our id for accept_from
        store_incoming(&remote, Box::new(b)).await;
        Ok(Box::new(a))
    }

    async fn accept(&self) -> Result<Box<dyn PeerConnection>> {
        take_incoming(self).await
    }

    fn events(&self) -> mpsc::Receiver<TransportEvent> {
        self.events_rx.lock().take().expect("events taken once")
    }
}

async fn store_incoming(ep: &MeshEndpoint, conn: Box<dyn PeerConnection>) {
    let (tx, rx) = oneshot::channel();
    {
        let mut g = INCOMING.lock().await;
        g.entry(ep.local_id()).or_default().push(conn);
        // wake one waiter if present
        if let Some(waiters) = WAITERS.lock().await.get_mut(&ep.local_id()) {
            if let Some(w) = waiters.pop() {
                if let Some(c) = g.get_mut(&ep.local_id()).and_then(|q| q.pop()) {
                    let _ = w.send(c);
                }
            }
        }
        let _ = tx;
        let _ = rx;
    }
}

async fn take_incoming(ep: &MeshEndpoint) -> Result<Box<dyn PeerConnection>> {
    {
        let mut g = INCOMING.lock().await;
        if let Some(q) = g.get_mut(&ep.local_id()) {
            if let Some(c) = q.pop() {
                return Ok(c);
            }
        }
    }
    let (tx, rx) = oneshot::channel();
    WAITERS
        .lock()
        .await
        .entry(ep.local_id())
        .or_default()
        .push(tx);
    rx.await
        .map_err(|_| mymesh_core::Error::Session("accept cancelled".into()))
}

use std::collections::HashMap as StdHashMap;
use tokio::sync::Mutex as AsyncMutex;

static INCOMING: once_cell_emulation::Lazy<
    AsyncMutex<StdHashMap<DeviceId, Vec<Box<dyn PeerConnection>>>>,
> = once_cell_emulation::Lazy::new(|| AsyncMutex::new(StdHashMap::new()));

static WAITERS: once_cell_emulation::Lazy<
    AsyncMutex<StdHashMap<DeviceId, Vec<oneshot::Sender<Box<dyn PeerConnection>>>>>,
> = once_cell_emulation::Lazy::new(|| AsyncMutex::new(StdHashMap::new()));

mod once_cell_emulation {
    use std::sync::OnceLock;
    pub struct Lazy<T, F = fn() -> T> {
        cell: OnceLock<T>,
        init: F,
    }
    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Self {
                cell: OnceLock::new(),
                init,
            }
        }
    }
    impl<T> std::ops::Deref for Lazy<T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.cell.get_or_init(self.init)
        }
    }
}
