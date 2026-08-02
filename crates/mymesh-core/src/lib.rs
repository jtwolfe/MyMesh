//! Core types shared across the MyMesh stack.

mod config;
mod device;
mod error;
mod identity;
mod join;
mod metrics;
mod mesh;
mod mesh_ip;
mod paths;

pub use config::{Config, DaemonConfig, Limits, MagicConfig};
pub use device::{Capability, DeviceRecord, DeviceStore, TrustState};
pub use error::{Error, Result};
pub use identity::{DeviceId, DeviceLabel, NodeFingerprint};
pub use join::{ArmState, JoinDecision, JoinStore, PendingJoin};
pub use metrics::{BandwidthResult, HostStatsSnap, LatencySample, PeerMetrics};
pub use mesh::{mark_mesh_dirty, mesh_dirty_mtime, KickNoticeRecord, MeshMember, MeshState, PendingKick, PendingKickStore};
pub use mesh_ip::{mesh_ip_string, mesh_ipv4};
pub use paths::Paths;
