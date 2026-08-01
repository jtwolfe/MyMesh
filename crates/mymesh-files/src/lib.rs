//! File transfer protocol handlers.
//!
//! Design goals:
//! - Resume-friendly chunked transfer
//! - Path sandboxing relative to an allowed root
//! - Explicit mkdir / remove / rename

mod sandbox;
mod transfer;

pub use sandbox::PathSandbox;
pub use transfer::{apply_host_message, FileTransferEngine};
