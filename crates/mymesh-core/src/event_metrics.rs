//! JSON event counters under `paths.metrics_dir` (S9 metric names).
//!
//! Files: `metrics/event-counters.json`
//!
//! | Metric | Labels |
//! |--------|--------|
//! | `pair_decide_total` | `{result}` |
//! | `pair_status_total` | — |
//! | `mesh_auth_challenge_total` | — |
//! | `owner_backup_unwrap_total` | `{result}` |
//! | `grant_mutate_total` | — |
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// On-disk / in-memory S9 counters (Prometheus-style names, JSON values).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventCounters {
    /// `pair_decide_total{result}` — accept, deny, rate_limited, bad_code, …
    #[serde(default)]
    pub pair_decide_total: HashMap<String, u64>,
    /// Unauthenticated pair status polls.
    #[serde(default)]
    pub pair_status_total: u64,
    /// Mesh auth challenge mints.
    #[serde(default)]
    pub mesh_auth_challenge_total: u64,
    /// `owner_backup_unwrap_total{result}` — ok, fail, rate_limited.
    #[serde(default)]
    pub owner_backup_unwrap_total: HashMap<String, u64>,
    /// Grant create / revoke mutations.
    #[serde(default)]
    pub grant_mutate_total: u64,
}

impl EventCounters {
    pub fn path(metrics_dir: impl AsRef<Path>) -> PathBuf {
        metrics_dir.as_ref().join("event-counters.json")
    }

    pub fn load(metrics_dir: impl AsRef<Path>) -> Result<Self> {
        let path = Self::path(&metrics_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self, metrics_dir: impl AsRef<Path>) -> Result<()> {
        let dir = metrics_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir);
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(Self::path(dir), std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn inc_pair_decide(&mut self, result: &str) {
        *self
            .pair_decide_total
            .entry(result.to_string())
            .or_insert(0) += 1;
    }

    pub fn inc_pair_status(&mut self) {
        self.pair_status_total = self.pair_status_total.saturating_add(1);
    }

    pub fn inc_mesh_auth_challenge(&mut self) {
        self.mesh_auth_challenge_total = self.mesh_auth_challenge_total.saturating_add(1);
    }

    pub fn inc_owner_backup_unwrap(&mut self, result: &str) {
        *self
            .owner_backup_unwrap_total
            .entry(result.to_string())
            .or_insert(0) += 1;
    }

    pub fn inc_grant_mutate(&mut self) {
        self.grant_mutate_total = self.grant_mutate_total.saturating_add(1);
    }
}

/// Best-effort load → mutate → save. Never panics; logs via return only.
pub fn with_counters(metrics_dir: impl AsRef<Path>, f: impl FnOnce(&mut EventCounters)) {
    let dir = metrics_dir.as_ref();
    // Serialize disk updates process-wide so concurrent handlers don't clobber.
    static DISK: OnceLockDisk = OnceLockDisk::new();
    let _guard = DISK.lock();
    let mut c = EventCounters::load(dir).unwrap_or_default();
    f(&mut c);
    let _ = c.save(dir);
}

/// Tiny once-lock mutex without external deps (std only).
struct OnceLockDisk {
    inner: Mutex<()>,
}

impl OnceLockDisk {
    const fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Convenience wrappers matching S9 metric names.
pub fn record_pair_decide(metrics_dir: impl AsRef<Path>, result: &str) {
    with_counters(metrics_dir, |c| c.inc_pair_decide(result));
}

pub fn record_pair_status(metrics_dir: impl AsRef<Path>) {
    with_counters(metrics_dir, |c| c.inc_pair_status());
}

pub fn record_mesh_auth_challenge(metrics_dir: impl AsRef<Path>) {
    with_counters(metrics_dir, |c| c.inc_mesh_auth_challenge());
}

pub fn record_owner_backup_unwrap(metrics_dir: impl AsRef<Path>, result: &str) {
    with_counters(metrics_dir, |c| c.inc_owner_backup_unwrap(result));
}

pub fn record_grant_mutate(metrics_dir: impl AsRef<Path>) {
    with_counters(metrics_dir, |c| c.inc_grant_mutate());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("mymesh-evmetrics-{n}"));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn persist_roundtrip_and_labels() {
        let dir = tmp_dir();
        record_pair_decide(&dir, "accept");
        record_pair_decide(&dir, "accept");
        record_pair_decide(&dir, "deny");
        record_pair_status(&dir);
        record_mesh_auth_challenge(&dir);
        record_owner_backup_unwrap(&dir, "ok");
        record_grant_mutate(&dir);

        let c = EventCounters::load(&dir).unwrap();
        assert_eq!(c.pair_decide_total.get("accept"), Some(&2));
        assert_eq!(c.pair_decide_total.get("deny"), Some(&1));
        assert_eq!(c.pair_status_total, 1);
        assert_eq!(c.mesh_auth_challenge_total, 1);
        assert_eq!(c.owner_backup_unwrap_total.get("ok"), Some(&1));
        assert_eq!(c.grant_mutate_total, 1);
        assert!(EventCounters::path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
