//! Mesh membership metadata, pending kicks, dirty-sync markers.
use crate::{DeviceId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    pub mesh_id: String,
    pub created_at: DateTime<Utc>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_kick_notice: Option<KickNoticeRecord>,
    /// Monotonic generation bumped on local roster changes (for dirty sync).
    #[serde(default)]
    pub roster_generation: u64,
    /// Optional mirror of live MMK fingerprint (set on `mesh init` / unlock paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mrk_fingerprint: Option<String>,
    /// Device that ran `mesh init` (creator). Host-local admin on that node;
    /// remote Admin still requires explicit grant or MRK proof (KD15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_device_id: Option<DeviceId>,
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
            roster_generation: 0,
            mrk_fingerprint: None,
            creator_device_id: None,
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
        if other < self.mesh_id.as_str() {
            self.mesh_id = other.to_string();
        }
    }

    pub fn bump_generation(&mut self) {
        self.roster_generation = self.roster_generation.saturating_add(1);
    }
}

/// Pending kick waiting for delivery / mesh-wide acks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingKick {
    pub target_id: DeviceId,
    pub target_label: String,
    pub by_id: DeviceId,
    pub by_label: String,
    pub mesh_id: String,
    pub message: String,
    pub ts: i64,
    #[serde(with = "serde_bytes_array64")]
    pub signature: [u8; 64],
    pub force: bool,
    pub created_at: DateTime<Utc>,
    /// Target has received KickNotice (or force local purge done).
    pub delivered_to_target: bool,
    /// Members who have acknowledged the kick / leave.
    pub acks: Vec<DeviceId>,
    /// Expected mesh members (excluding target) that should eventually ack.
    pub expected: Vec<DeviceId>,
}

mod serde_bytes_array64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if b.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut a = [0u8; 64];
        a.copy_from_slice(&b);
        Ok(a)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PendingKickFile {
    kicks: HashMap<String, PendingKick>,
}

#[derive(Debug)]
pub struct PendingKickStore {
    path: PathBuf,
    kicks: HashMap<DeviceId, PendingKick>,
}

impl PendingKickStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let kicks = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: PendingKickFile = serde_json::from_str(&raw)?;
            file.kicks.into_values().map(|k| (k.target_id, k)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, kicks })
    }

    pub fn list(&self) -> Vec<&PendingKick> {
        let mut v: Vec<_> = self.kicks.values().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        v
    }

    pub fn get(&self, target: &DeviceId) -> Option<&PendingKick> {
        self.kicks.get(target)
    }

    pub fn upsert(&mut self, kick: PendingKick) -> Result<()> {
        self.kicks.insert(kick.target_id, kick);
        self.flush()
    }

    pub fn mark_delivered(&mut self, target: &DeviceId) -> Result<()> {
        if let Some(k) = self.kicks.get_mut(target) {
            k.delivered_to_target = true;
            self.flush()?;
        }
        Ok(())
    }

    pub fn add_ack(&mut self, target: &DeviceId, from: DeviceId) -> Result<bool> {
        let done = if let Some(k) = self.kicks.get_mut(target) {
            if !k.acks.contains(&from) {
                k.acks.push(from);
            }
            let complete = k.delivered_to_target
                && k.expected.iter().all(|e| k.acks.contains(e) || *e == from);
            // also complete if force and delivered
            let complete = complete
                || (k.force
                    && k.delivered_to_target
                    && k.acks.len() >= k.expected.len().saturating_sub(0));
            Some(complete)
        } else {
            None
        };
        self.flush()?;
        Ok(done.unwrap_or(false))
    }

    pub fn remove(&mut self, target: &DeviceId) -> Result<()> {
        self.kicks.remove(target);
        self.flush()
    }

    /// Drop completed kicks (delivered + all expected acked, or force + delivered + 60s).
    pub fn gc_completed(&mut self) -> Result<usize> {
        let before = self.kicks.len();
        self.kicks.retain(|_, k| {
            if !k.delivered_to_target {
                return true;
            }
            let all_acked = k.expected.iter().all(|e| k.acks.contains(e));
            if all_acked {
                return false;
            }
            // force kicks expire pending after 24h even without full acks
            if k.force {
                let age = Utc::now().signed_duration_since(k.created_at);
                if age.num_hours() >= 24 {
                    return false;
                }
            }
            true
        });
        let n = before - self.kicks.len();
        if n > 0 {
            self.flush()?;
        }
        Ok(n)
    }

    fn flush(&self) -> Result<()> {
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let file = PendingKickFile {
            kicks: self
                .kicks
                .values()
                .cloned()
                .map(|k| (k.target_id.to_string(), k))
                .collect(),
        };
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

/// Touch dirty marker so agent pushes mesh sync soon.
pub fn mark_mesh_dirty(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(path, format!("{}\n", Utc::now().to_rfc3339()))?;
    Ok(())
}

pub fn mesh_dirty_mtime(path: impl AsRef<Path>) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}
