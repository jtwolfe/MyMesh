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
    /// Magic LAN plane: DNS + SOCKS + mesh-IP port forwards.
    #[serde(default)]
    pub magic: MagicConfig,
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
            magic: MagicConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MagicConfig {
    /// Enable magic plane when agent serves.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// DNS suffix without leading dot (default mym).
    #[serde(default = "default_domain")]
    pub domain: String,
    /// UDP bind for userspace DNS (default 127.0.0.1:5353).
    #[serde(default = "default_dns_bind")]
    pub dns_bind: String,
    /// SOCKS5 bind for browser/CLI tools (default 127.0.0.1:18080).
    #[serde(default = "default_socks_bind")]
    pub socks_bind: String,
    /// Ports auto-bound on each peer mesh IP → tunnel to peer localhost:port.
    #[serde(default = "default_auto_ports")]
    pub auto_ports: Vec<u16>,
    /// How often to probe peers for presence (seconds). 0 = disable.
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_probe_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_domain() -> String {
    "mym".into()
}
fn default_dns_bind() -> String {
    "127.0.0.1:5353".into()
}
fn default_socks_bind() -> String {
    "127.0.0.1:18080".into()
}
fn default_auto_ports() -> Vec<u16> {
    vec![22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090]
}
fn default_reconnect_secs() -> u64 {
    30
}

impl Default for MagicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            domain: default_domain(),
            dns_bind: default_dns_bind(),
            socks_bind: default_socks_bind(),
            auto_ports: default_auto_ports(),
            reconnect_probe_secs: default_reconnect_secs(),
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
    /// How long `connect-request allow` stays armed (seconds).
    #[serde(default = "default_arm_timeout")]
    pub arm_timeout_secs: u64,
}

fn default_arm_timeout() -> u64 {
    600
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_terminals: 8,
            max_transfers: 4,
            desktop_fps: 30,
            pair_ttl_secs: 600,
            arm_timeout_secs: 600,
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
