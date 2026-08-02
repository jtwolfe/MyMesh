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
}
