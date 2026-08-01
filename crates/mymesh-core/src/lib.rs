//! Core types shared across the MyMesh stack.
//!
//! Identity, device records, configuration paths, and error types live here
//! so higher crates stay free of circular deps.

mod config;
mod device;
mod error;
mod identity;
mod paths;

pub use config::{Config, DaemonConfig, Limits};
pub use device::{Capability, DeviceRecord, DeviceStore, TrustState};
pub use error::{Error, Result};
pub use identity::{DeviceId, DeviceLabel, NodeFingerprint};
pub use paths::Paths;
