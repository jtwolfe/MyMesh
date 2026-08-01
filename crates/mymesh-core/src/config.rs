use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub device_label: String,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub limits: Limits,
    /// Optional custom rendezvous URL for pairing (empty = built-in public set).
    #[serde(default)]
    pub rendezvous_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_label: crate::DeviceLabel::default_host().as_str().to_string(),
            daemon: DaemonConfig::default(),
            limits: Limits::default(),
            rendezvous_url: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Listen for local CLI control socket.
    pub control_socket: String,
    pub enable_terminal: bool,
    pub enable_files: bool,
    pub enable_desktop: bool,
    /// Auto-start on boot (documented for systemd unit generation).
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
    /// Max concurrent terminal sessions.
    pub max_terminals: u32,
    /// Max concurrent file transfers.
    pub max_transfers: u32,
    /// Max desktop frame rate (soft).
    pub desktop_fps: u32,
    /// Pairing code TTL seconds.
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
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self)?;
        std::fs::write(path, raw)?;
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
