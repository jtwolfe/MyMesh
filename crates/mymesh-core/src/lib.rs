//! Core types shared across the MyMesh stack.

mod config;
mod device;
mod error;
mod identity;
mod join;
mod metrics;
mod paths;

pub use config::{Config, DaemonConfig, Limits};
pub use device::{Capability, DeviceRecord, DeviceStore, TrustState};
pub use error::{Error, Result};
pub use identity::{DeviceId, DeviceLabel, NodeFingerprint};
pub use join::{ArmState, JoinDecision, JoinStore, PendingJoin};
pub use metrics::{BandwidthResult, HostStatsSnap, LatencySample, PeerMetrics};
pub use paths::Paths;
