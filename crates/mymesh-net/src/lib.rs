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
pub use local_dial::{
    admin_request, agent_control_live, agent_proxy_available, arm_pair_qr_via_agent, connect_mesh,
    connect_via_agent, default_control_socket, pair_http_port_live, serve_control_socket,
    serve_dial_proxy, serve_owns_pair_http, ArmPairQrResponse, LocalAdmin, ADMIN_MAGIC, DIAL_MAGIC,
};
pub use mailbox_fs::{default_local_mailbox_dir, open_default_fs, FsMailbox};
pub use mailbox_http::{
    mailbox_router, run_mailbox_server, run_mailbox_server_with_metrics, AdminMailboxClient,
    AdminMailboxError, HttpMailbox, ADMIN_MAILBOX_MAX_BYTES_NET, ADMIN_MAILBOX_POLL_MS_NET,
};
pub use rendezvous::{LocalRendezvous, Rendezvous};
pub use traits::{PeerConnection, Transport};
