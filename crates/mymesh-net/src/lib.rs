//! Transport layer for MyMesh.
//!
//! - **Iroh** (production): QUIC, dial-by-public-key, hole punch + relays
//! - **Local fabric**: in-process tests / demos
//! - **Mailboxes**: filesystem (multiproc local) + HTTP (self-hosted)

mod fabric;
mod iroh_transport;
mod local_dial;
mod mailbox_fs;
mod mailbox_http;
mod rendezvous;
mod traits;

pub use fabric::{FabricConnection, LocalFabric};
pub use iroh_transport::{IrohTransport, SharedIroh};
pub use local_dial::{agent_proxy_available, connect_mesh, connect_via_agent, default_control_socket, serve_dial_proxy};
pub use mailbox_fs::{default_local_mailbox_dir, open_default_fs, FsMailbox};
pub use mailbox_http::{run_mailbox_server, HttpMailbox};
pub use rendezvous::{LocalRendezvous, Rendezvous};
pub use traits::{PeerConnection, Transport};
