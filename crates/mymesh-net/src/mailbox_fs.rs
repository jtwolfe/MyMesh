//! Cross-process filesystem mailbox for SPAKE2 rendezvous.
use crate::rendezvous::Rendezvous;
use async_trait::async_trait;
use mymesh_core::{Error, Result};
use mymesh_protocol::PairingMessage;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use tracing::debug;

/// Directional FS mailbox under a shared root directory.
#[derive(Clone, Debug)]
pub struct FsMailbox {
    root: PathBuf,
    ttl: Duration,
}

impl FsMailbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            ttl: Duration::from_secs(600),
        })
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    fn lane_path(&self, code: &str, as_host: bool, outbound: bool) -> PathBuf {
        // as_host + outbound => h2g
        // as_host + inbound  => g2h
        // !as_host + outbound => g2h
        // !as_host + inbound  => h2g
        let lane = match (as_host, outbound) {
            (true, true) | (false, false) => "h2g",
            (true, false) | (false, true) => "g2h",
        };
        let safe: String = code
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
            .collect();
        self.root.join(format!("{safe}.{lane}.jsonl"))
    }
}

#[async_trait]
impl Rendezvous for FsMailbox {
    async fn send(&self, code: &str, as_host: bool, msg: PairingMessage) -> Result<()> {
        let path = self.lane_path(code, as_host, true);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(&msg).map_err(|e| Error::Serialize(e.to_string()))?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(f, "{line}")?;
        debug!(?path, "fs mailbox send");
        Ok(())
    }

    async fn recv(&self, code: &str, as_host: bool) -> Result<PairingMessage> {
        let path = self.lane_path(code, as_host, false);
        let deadline = SystemTime::now() + self.ttl;
        loop {
            if SystemTime::now() > deadline {
                return Err(Error::Pairing("mailbox recv timeout".into()));
            }
            if path.exists() {
                let raw = std::fs::read_to_string(&path)?;
                let mut lines: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
                if let Some(first) = lines.first().copied() {
                    let msg: PairingMessage = serde_json::from_str(first)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    lines.remove(0);
                    let rest = lines.join("\n");
                    if rest.is_empty() {
                        let _ = std::fs::remove_file(&path);
                    } else {
                        std::fs::write(&path, rest + "\n")?;
                    }
                    debug!(?path, "fs mailbox recv");
                    return Ok(msg);
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    }
}

pub fn default_local_mailbox_dir() -> PathBuf {
    if let Ok(p) = std::env::var("MYMESH_MAILBOX_DIR") {
        return PathBuf::from(p);
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime).join("mymesh-mailbox")
}

pub fn open_default_fs() -> Result<FsMailbox> {
    FsMailbox::new(default_local_mailbox_dir())
}

#[allow(dead_code)]
pub fn ensure_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p)?;
    Ok(())
}
