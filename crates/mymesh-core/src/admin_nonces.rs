//! AdminEnvelope nonce replay cache (`admin-nonces.json`, mode 0600).
//!
//! Serve owns this file (KD-F16 / F4p). HTTP consume of AdminEnvelope nonces
//! is F4 — this module is the persist path so serve restart keeps the 15-min
//! window.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Replay window across serve restart (CARRIER-ADMIN-NEXT).
pub const ADMIN_NONCE_TTL_SECS: u64 = 15 * 60;
pub const ADMIN_NONCES_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdminNonceEntry {
    nonce: String,
    seen_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdminNoncesFile {
    version: u32,
    #[serde(default)]
    nonces: Vec<AdminNonceEntry>,
}

/// File-backed nonce set. Serve creates the empty file on start.
#[derive(Debug)]
pub struct AdminNonceStore {
    path: PathBuf,
    file: AdminNoncesFile,
}

impl AdminNonceStore {
    /// Load existing file, or an empty in-memory store if missing. Does not write.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: AdminNoncesFile = serde_json::from_str(&raw)?;
            if file.version != ADMIN_NONCES_VERSION {
                return Err(Error::Config(format!(
                    "unsupported admin-nonces.json version {}",
                    file.version
                )));
            }
            file
        } else {
            AdminNoncesFile {
                version: ADMIN_NONCES_VERSION,
                nonces: Vec::new(),
            }
        };
        Ok(Self { path, file })
    }

    /// Like [`open`], and persist an empty schema file (0600) when missing.
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let store = Self::open(path)?;
        if !store.path.exists() {
            store.flush()?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True if `nonce` was recorded inside the TTL window.
    pub fn contains(&self, nonce: &str) -> bool {
        let now = now_unix();
        self.file
            .nonces
            .iter()
            .any(|e| e.nonce == nonce && now.saturating_sub(e.seen_at) < ADMIN_NONCE_TTL_SECS)
    }

    /// Record `nonce`. Error if already present in the TTL window (replay).
    pub fn insert(&mut self, nonce: impl Into<String>) -> Result<()> {
        let nonce = nonce.into();
        self.prune();
        if self.file.nonces.iter().any(|e| e.nonce == nonce) {
            return Err(Error::PermissionDenied("admin nonce replay".into()));
        }
        self.file.nonces.push(AdminNonceEntry {
            nonce,
            seen_at: now_unix(),
        });
        self.flush()
    }

    fn prune(&mut self) {
        let now = now_unix();
        self.file
            .nonces
            .retain(|e| now.saturating_sub(e.seen_at) < ADMIN_NONCE_TTL_SECS);
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(&self.file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-nonces-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("admin-nonces.json")
    }

    #[test]
    fn open_or_create_writes_empty_0600() {
        let path = temp_path("create");
        let store = AdminNonceStore::open_or_create(&path).unwrap();
        assert!(path.exists());
        assert!(!store.contains("n1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn insert_rejects_replay() {
        let path = temp_path("replay");
        let mut store = AdminNonceStore::open_or_create(&path).unwrap();
        store.insert("abc").unwrap();
        assert!(store.contains("abc"));
        assert!(store.insert("abc").is_err());
        // Survives reopen (serve restart).
        let store2 = AdminNonceStore::open(&path).unwrap();
        assert!(store2.contains("abc"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unknown_version_fail_closed() {
        let path = temp_path("ver");
        std::fs::write(&path, r#"{"version":99,"nonces":[]}"#).unwrap();
        let err = AdminNonceStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
