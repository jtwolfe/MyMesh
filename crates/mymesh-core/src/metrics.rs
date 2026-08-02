//! Peer latency / probe history (on-disk, ~60 samples).
use crate::{DeviceId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

const MAX_SAMPLES: usize = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencySample {
    pub at: DateTime<Utc>,
    pub rtt_ms: Option<u64>,
    pub ok: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PeerMetrics {
    pub device_id: Option<DeviceId>,
    pub samples: VecDeque<LatencySample>,
    pub last_bandwidth: Option<BandwidthResult>,
    pub last_host: Option<HostStatsSnap>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostStatsSnap {
    pub at: DateTime<Utc>,
    pub cpu_pct: f32,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub load_1: f32,
    pub uptime_secs: u64,
    pub hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BandwidthResult {
    pub at: DateTime<Utc>,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub mbps: f64,
    pub direction: String,
}

impl PeerMetrics {
    pub fn push_latency(&mut self, sample: LatencySample) {
        self.samples.push_back(sample);
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    pub fn latest_rtt(&self) -> Option<u64> {
        self.samples.iter().rev().find_map(|s| s.rtt_ms)
    }

    pub fn success_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let ok = self.samples.iter().filter(|s| s.ok).count();
        ok as f64 / self.samples.len() as f64
    }

    pub fn path(metrics_dir: impl AsRef<Path>, id: &DeviceId) -> PathBuf {
        metrics_dir.as_ref().join(format!("{id}.json"))
    }

    pub fn load(metrics_dir: impl AsRef<Path>, id: &DeviceId) -> Result<Self> {
        let path = Self::path(metrics_dir, id);
        if !path.exists() {
            return Ok(Self {
                device_id: Some(*id),
                ..Default::default()
            });
        }
        let raw = std::fs::read_to_string(path)?;
        let mut m: Self = serde_json::from_str(&raw)?;
        m.device_id = Some(*id);
        Ok(m)
    }

    pub fn save(&self, metrics_dir: impl AsRef<Path>) -> Result<()> {
        let id = self
            .device_id
            .ok_or_else(|| crate::Error::Other("metrics missing device id".into()))?;
        let dir = metrics_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir, &id);
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
