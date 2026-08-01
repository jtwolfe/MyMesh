//! Transport layer for MyMesh.
//!
//! ## Backends
//! - **Local fabric** (always available): in-process / same-host mesh for tests
//!   and `mymesh demo pair`.
//! - **Iroh** (production): enable via the `iroh` integration module documented
//!   in `docs/ARCHITECTURE.md`. The `Transport` trait is the stable boundary.
//!
//! NAT hole punching, relay fallback, and dial-by-public-key are provided by
//! iroh when wired in; this crate keeps that behind a clean interface so the
//! rest of the stack never depends on a specific QUIC stack.

mod fabric;
mod rendezvous;
mod traits;

pub use fabric::{FabricConnection, LocalFabric};
pub use rendezvous::{LocalRendezvous, Rendezvous};
pub use traits::{PeerConnection, Transport};
