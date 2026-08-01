use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub device_label: String,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub limits: Limits,
    /// HTTP mailbox base URL for SPAKE2 rendezvous (e.g. http://127.0.0.1:9876).
    #[serde(default)]
    pub rendezvous_url: Option<String>,
    /// Shared directory mailbox (cross-process, same host / NFS).
    #[serde(default)]
    pub mailbox_dir: Option<PathBuf>,
    /// Host path sandbox root for remote file access (default: $HOME).
    #[serde(default)]
    pub sandbox_root: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_label: crate::DeviceLabel::default_host().as_str().to_string(),
            daemon: DaemonConfig::default(),
            limits: Limits::default(),
            rendezvous_url: std::env::var("MYMESH_MAILBOX").ok(),
            mailbox_dir: std::env::var_os("MYMESH_MAILBOX_DIR").map(PathBuf::from),
            sandbox_root: None,
        }
    }
}

impl Config {
    pub fn effective_sandbox_root(&self) -> PathBuf {
        if let Some(p) = &self.sandbox_root {
            return p.clone();
        }
        if let Some(u) = directories::UserDirs::new() {
            return u.home_dir().to_path_buf();
        }
        PathBuf::from(".")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub control_socket: String,
    pub enable_terminal: bool,
    pub enable_files: bool,
    pub enable_desktop: bool,
    pub auto_start: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            control_socket: default_control_socket(),
            enable_terminal: true,
            enable_files: true,
            enable_desktop: true,
            auto_start: true,
        }
    }
}

fn default_control_socket() -> String {
    if cfg!(windows) {
        r"\\.\pipe\mymesh".into()
    } else {
        let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
        format!("{runtime}/mymesh.sock")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub max_terminals: u32,
    pub max_transfers: u32,
    pub desktop_fps: u32,
    pub pair_ttl_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_terminals: 8,
            max_transfers: 4,
            desktop_fps: 30,
            pair_ttl_secs: 600,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.device_label.trim().is_empty() {
            return Err(Error::Config("device_label must not be empty".into()));
        }
        if self.limits.pair_ttl_secs < 30 {
            return Err(Error::Config("pair_ttl_secs too low".into()));
        }
        Ok(())
    }
}
