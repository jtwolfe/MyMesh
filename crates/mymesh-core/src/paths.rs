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
}
