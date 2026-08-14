use crate::Result;
use directories::ProjectDirs;
use std::path::PathBuf;

/// Standard filesystem layout for MyMesh state.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self> {
        let dirs = ProjectDirs::from("rs", "MyMesh", "mymesh")
            .ok_or_else(|| crate::Error::Config("could not resolve project directories".into()))?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            data_dir: dirs.data_dir().to_path_buf(),
            cache_dir: dirs.cache_dir().to_path_buf(),
        })
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.cache_dir)?;
        Ok(())
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn identity_file(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    pub fn devices_file(&self) -> PathBuf {
        self.data_dir.join("devices.json")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    pub fn arm_file(&self) -> PathBuf {
        self.data_dir.join("arm.json")
    }

    pub fn join_dir(&self) -> PathBuf {
        self.data_dir.join("join")
    }

    pub fn metrics_dir(&self) -> PathBuf {
        self.data_dir.join("metrics")
    }

    pub fn install_marker(&self) -> PathBuf {
        self.data_dir.join("install.json")
    }

    pub fn mesh_file(&self) -> PathBuf {
        self.data_dir.join("mesh.json")
    }

    pub fn kick_notice_file(&self) -> PathBuf {
        self.data_dir.join("kick-notice.txt")
    }

    pub fn pending_kicks_file(&self) -> PathBuf {
        self.data_dir.join("pending-kicks.json")
    }

    pub fn mesh_dirty_file(&self) -> PathBuf {
        self.data_dir.join("mesh.dirty")
    }

    /// Pair v2 sessions: `pair-sessions/<sid>.json` (mode 0600).
    pub fn pair_sessions_dir(&self) -> PathBuf {
        self.data_dir.join("pair-sessions")
    }

    /// Mesh master key wrap file (Argon2id + XChaCha20-Poly1305 over MRK), mode 0600.
    pub fn mesh_master_file(&self) -> PathBuf {
        self.data_dir.join("mesh-master.json")
    }

    /// Host-local unlock cache for unwrapped MRK (mode 0600). Cleared by `mesh lock`.
    /// Not an OS keyring — default policy remains re-prompt after lock / reboot.
    pub fn mmk_runtime_file(&self) -> PathBuf {
        self.data_dir.join("mmk-runtime.json")
    }

    /// Person owner claim file (mode 0600). Written by owner claim (S4 / B4).
    pub fn mesh_owner_file(&self) -> PathBuf {
        self.data_dir.join("mesh-owner.json")
    }

    /// MMK-authorized claim window (mode 0600). Minted by `mymesh owner allow-claim`.
    pub fn claim_window_file(&self) -> PathBuf {
        self.data_dir.join("claim-window.json")
    }

    /// Sealed person seed backup (password-AEAD only; mode 0600).
    pub fn owner_backup_file(&self) -> PathBuf {
        self.data_dir.join("owner-backup.sealed")
    }

    /// Guest / object grants store (mode 0600). S5 / docs/GRANTS.md.
    pub fn grants_file(&self) -> PathBuf {
        self.data_dir.join("grants.json")
    }

    /// Verified person drive bindings (`enrollments.json`, mode 0600). Wave F2.
    pub fn enrollments_file(&self) -> PathBuf {
        self.data_dir.join("enrollments.json")
    }

    /// AdminEnvelope replay cache (`admin-nonces.json`, mode 0600). Serve-owned (F4p / F4).
    pub fn admin_nonces_file(&self) -> PathBuf {
        self.data_dir.join("admin-nonces.json")
    }

    /// This-node membership catalog (`mesh-memberships.json`, mode 0600). F7 writes the
    /// primary row at first init; F8 owns guest rows.
    /// This-node membership catalog (`mesh-memberships.json`, mode 0600). Wave F8.
    pub fn mesh_memberships_file(&self) -> PathBuf {
        self.data_dir.join("mesh-memberships.json")
    }

    /// MMK-authorized first-create window (`create-window.json`, mode 0600).
    pub fn create_window_file(&self) -> PathBuf {
        self.data_dir.join("create-window.json")
    }

    /// One-shot MMK recovery codes (and generated password, if any). Mode 0600.
    /// Printed by `mymesh mesh recovery-show-once` or a TUI modal, then deleted.
    pub fn mesh_recovery_once_file(&self) -> PathBuf {
        self.data_dir.join("mesh-recovery-once.txt")
    }

    /// Heartbeat written while the TUI is attached (best-effort IPC).
    pub fn tui_attached_file(&self) -> PathBuf {
        self.data_dir.join("tui.attached")
    }

    /// Pending enrollment session (`enroll-session.json`, mode 0600).
    pub fn enroll_session_file(&self) -> PathBuf {
        self.data_dir.join("enroll-session.json")
    }

    /// Continuity packs root: `continuity/<pack_id>/` mode 0700 (S8).
    pub fn continuity_dir(&self) -> PathBuf {
        self.data_dir.join("continuity")
    }

    /// Single pack directory under continuity root.
    pub fn continuity_pack_dir(&self, pack_id: &str) -> PathBuf {
        self.continuity_dir().join(pack_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_nonces_path_is_serve_owned_file() {
        let p = Paths {
            config_dir: PathBuf::from("/tmp/cfg"),
            data_dir: PathBuf::from("/tmp/data"),
            cache_dir: PathBuf::from("/tmp/cache"),
        };
        assert_eq!(
            p.admin_nonces_file(),
            PathBuf::from("/tmp/data/admin-nonces.json")
        );
        assert_eq!(
            p.mesh_memberships_file(),
            PathBuf::from("/tmp/data/mesh-memberships.json")
        );
        assert_eq!(
            p.create_window_file(),
            PathBuf::from("/tmp/data/create-window.json")
        );
        assert_eq!(
            p.mesh_recovery_once_file(),
            PathBuf::from("/tmp/data/mesh-recovery-once.txt")
        );
    }
}
