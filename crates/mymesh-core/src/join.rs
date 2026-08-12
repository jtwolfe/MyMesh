//! Join arming and pending connection requests (on-disk agent control plane).
use crate::{Capability, DeviceId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArmState {
    pub armed: bool,
    pub until: Option<DateTime<Utc>>,
    pub armed_at: Option<DateTime<Utc>>,
    /// When set, accepted joins use the guest path for this grant (GUEST.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_grant_id: Option<String>,
}

impl ArmState {
    pub fn is_effectively_armed(&self) -> bool {
        if !self.armed {
            return false;
        }
        match self.until {
            None => true,
            Some(t) => Utc::now() < t,
        }
    }

    /// Guest-join arming (host expects grant-scoped accept, no full roster).
    pub fn is_guest_arm(&self) -> bool {
        self.is_effectively_armed() && self.guest_grant_id.is_some()
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn arm(path: impl AsRef<Path>, ttl_secs: u64) -> Result<Self> {
        Self::arm_inner(path, ttl_secs, None)
    }

    /// Arm for guest join bound to an existing grant id (object host).
    pub fn arm_with_guest_grant(
        path: impl AsRef<Path>,
        ttl_secs: u64,
        grant_id: impl Into<String>,
    ) -> Result<Self> {
        Self::arm_inner(path, ttl_secs, Some(grant_id.into()))
    }

    fn arm_inner(
        path: impl AsRef<Path>,
        ttl_secs: u64,
        guest_grant_id: Option<String>,
    ) -> Result<Self> {
        let now = Utc::now();
        let state = Self {
            armed: true,
            until: Some(now + chrono::Duration::seconds(ttl_secs as i64)),
            armed_at: Some(now),
            guest_grant_id,
        };
        state.save(path.as_ref())?;
        Ok(state)
    }

    pub fn disarm(path: impl AsRef<Path>) -> Result<Self> {
        let state = Self::default();
        state.save(path.as_ref())?;
        Ok(state)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingJoin {
    pub device_id: DeviceId,
    pub label: String,
    pub capabilities: Vec<Capability>,
    pub received_at: DateTime<Utc>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinDecision {
    Accept,
    Deny { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinDecisionFile {
    pub decision: JoinDecision,
    pub decided_at: DateTime<Utc>,
}

pub struct JoinStore {
    root: PathBuf,
}

impl JoinStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("pending"))?;
        std::fs::create_dir_all(root.join("decisions"))?;
        Ok(Self { root })
    }

    pub fn pending_path(&self, id: &DeviceId) -> PathBuf {
        self.root.join("pending").join(format!("{id}.json"))
    }

    pub fn decision_path(&self, id: &DeviceId) -> PathBuf {
        self.root.join("decisions").join(format!("{id}.json"))
    }

    pub fn write_pending(&self, p: &PendingJoin) -> Result<()> {
        // Clear stale decision
        let _ = std::fs::remove_file(self.decision_path(&p.device_id));
        std::fs::write(
            self.pending_path(&p.device_id),
            serde_json::to_string_pretty(p)?,
        )?;
        Ok(())
    }

    pub fn list_pending(&self) -> Result<Vec<PendingJoin>> {
        let dir = self.root.join("pending");
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            if ent.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(ent.path())?;
            out.push(serde_json::from_str(&raw)?);
        }
        out.sort_by_key(|a| a.received_at);
        Ok(out)
    }

    pub fn write_decision(&self, id: &DeviceId, decision: JoinDecision) -> Result<()> {
        let f = JoinDecisionFile {
            decision,
            decided_at: Utc::now(),
        };
        std::fs::write(self.decision_path(id), serde_json::to_string_pretty(&f)?)?;
        Ok(())
    }

    pub fn take_decision(&self, id: &DeviceId) -> Result<Option<JoinDecision>> {
        let path = self.decision_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)?;
        let f: JoinDecisionFile = serde_json::from_str(&raw)?;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(self.pending_path(id));
        Ok(Some(f.decision))
    }

    pub fn clear_pending(&self, id: &DeviceId) -> Result<()> {
        let _ = std::fs::remove_file(self.pending_path(id));
        let _ = std::fs::remove_file(self.decision_path(id));
        Ok(())
    }
}
