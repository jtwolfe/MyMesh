use crate::{DeviceId, DeviceLabel, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// What a peer is allowed to do on this node after pairing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Terminal,
    Files,
    Desktop,
    /// Administrative: can approve further links, view logs.
    Admin,
}

impl Capability {
    pub fn all() -> Vec<Self> {
        vec![Self::Terminal, Self::Files, Self::Desktop]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// Linked and allowed.
    Trusted,
    /// Pairing completed but waiting for local confirmation.
    Pending,
    /// Explicitly revoked.
    Revoked,
}

/// Persistent record for a linked peer (Signal "linked devices" analogue).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub label: DeviceLabel,
    pub fingerprint: String,
    pub capabilities: Vec<Capability>,
    pub trust: TrustState,
    pub linked_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Optional iroh / transport endpoint tips (relay URLs, etc.) as opaque JSON.
    #[serde(default)]
    pub endpoint_hint: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    devices: HashMap<String, DeviceRecord>,
}

/// On-disk store of linked devices under the user's config directory.
#[derive(Debug)]
pub struct DeviceStore {
    path: PathBuf,
    devices: HashMap<DeviceId, DeviceRecord>,
}

impl DeviceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let devices = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: StoreFile = serde_json::from_str(&raw)?;
            file.devices.into_values().map(|d| (d.id, d)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, devices })
    }

    pub fn list(&self) -> Vec<&DeviceRecord> {
        let mut v: Vec<_> = self.devices.values().collect();
        v.sort_by(|a, b| a.label.as_str().cmp(b.label.as_str()));
        v
    }

    pub fn get(&self, id: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }

    pub fn upsert(&mut self, record: DeviceRecord) -> Result<()> {
        self.devices.insert(record.id, record);
        self.flush()
    }

    pub fn revoke(&mut self, id: &DeviceId) -> Result<()> {
        if let Some(r) = self.devices.get_mut(id) {
            r.trust = TrustState::Revoked;
            self.flush()
        } else {
            Err(Error::NotFound(id.to_string()))
        }
    }

    pub fn remove(&mut self, id: &DeviceId) -> Result<()> {
        if self.devices.remove(id).is_some() {
            self.flush()
        } else {
            Err(Error::NotFound(id.to_string()))
        }
    }

    pub fn is_trusted(&self, id: &DeviceId) -> bool {
        matches!(
            self.devices.get(id).map(|d| &d.trust),
            Some(TrustState::Trusted)
        )
    }

    pub fn allows(&self, id: &DeviceId, cap: &Capability) -> bool {
        self.devices
            .get(id)
            .filter(|d| d.trust == TrustState::Trusted)
            .map(|d| d.capabilities.contains(cap))
            .unwrap_or(false)
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = StoreFile {
            devices: self
                .devices
                .values()
                .cloned()
                .map(|d| (d.id.to_string(), d))
                .collect(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
