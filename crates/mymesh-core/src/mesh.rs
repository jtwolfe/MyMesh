//! Mesh membership metadata (shared roster / kick notices).
use crate::{DeviceId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

/// Lightweight member entry for gossip (no secrets).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshMember {
    pub id: DeviceId,
    pub label: String,
    pub fingerprint: String,
    pub capabilities: Vec<crate::Capability>,
    pub linked_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshState {
    /// Stable mesh identifier shared among members.
    pub mesh_id: String,
    pub created_at: DateTime<Utc>,
    /// Last time we applied a remote membership snapshot.
    pub last_sync: Option<DateTime<Utc>>,
    /// If we were kicked, keep the notice for the operator.
    pub last_kick_notice: Option<KickNoticeRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KickNoticeRecord {
    pub by_id: DeviceId,
    pub by_label: String,
    pub message: String,
    pub at: DateTime<Utc>,
}

impl MeshState {
    pub fn new_mesh() -> Self {
        Self {
            mesh_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            last_sync: None,
            last_kick_notice: None,
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            let s = Self::new_mesh();
            s.save(path)?;
            return Ok(s);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn adopt_mesh_id(&mut self, other: &str) {
        // Prefer lexicographically smaller id when reconciling two meshes.
        if other < self.mesh_id.as_str() {
            self.mesh_id = other.to_string();
        }
    }
}
