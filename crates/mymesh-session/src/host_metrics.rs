//! Best-effort local host metrics (Linux /proc + df).
use chrono::Utc;
use mymesh_protocol::ControlMessage;
use std::fs;
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
struct CpuSample {
    idle: u64,
    total: u64,
}

fn read_cpu() -> Option<CpuSample> {
    let s = fs::read_to_string("/proc/stat").ok()?;
    let line = s.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let nums: Vec<u64> = parts.filter_map(|x| x.parse().ok()).collect();
    if nums.len() < 4 {
        return None;
    }
    let idle = nums[3] + nums.get(4).copied().unwrap_or(0);
    let total = nums.iter().sum();
    Some(CpuSample { idle, total })
}

fn mem_info() -> (u64, u64) {
    let Ok(s) = fs::read_to_string("/proc/meminfo") else {
        return (0, 0);
    };
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = parse_kb(v) * 1024;
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(v) * 1024;
        }
    }
    (total.saturating_sub(avail), total)
}

fn parse_kb(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

fn disk_root() -> (u64, u64) {
    let out = Command::new("df").args(["-B1", "/"]).output().ok();
    let Some(out) = out else {
        return (0, 0);
    };
    let s = String::from_utf8_lossy(&out.stdout);
    // Filesystem 1B-blocks Used Available Use% Mounted
    for line in s.lines().skip(1) {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.len() >= 4 {
            let total: u64 = cols[1].parse().unwrap_or(0);
            let used: u64 = cols[2].parse().unwrap_or(0);
            return (used, total);
        }
    }
    (0, 0)
}

fn net_totals() -> (u64, u64) {
    let Ok(s) = fs::read_to_string("/proc/net/dev") else {
        return (0, 0);
    };
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in s.lines().skip(2) {
        let line = line.trim();
        if line.starts_with("lo:") {
            continue;
        }
        let mut sp = line.split_whitespace();
        let _iface = sp.next();
        // rx bytes is first after iface
        if let Some(r) = sp.next() {
            rx += r.parse().unwrap_or(0);
            // skip packets, errs, drop, fifo, frame, compressed, multicast = 7 fields
            if let Some(t) = sp.nth(7) {
                tx += t.parse().unwrap_or(0);
            }
        }
    }
    (rx, tx)
}

fn load1() -> f32 {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

fn uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|x| x as u64)
        .unwrap_or(0)
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// Sample CPU over a short sleep for a meaningful %.
pub async fn sample_metrics(nonce: u64) -> ControlMessage {
    let a = read_cpu();
    tokio::time::sleep(Duration::from_millis(120)).await;
    let b = read_cpu();
    let cpu = match (a, b) {
        (Some(a), Some(b)) => {
            let dt = b.total.saturating_sub(a.total) as f32;
            let di = b.idle.saturating_sub(a.idle) as f32;
            if dt > 0.0 {
                ((dt - di) / dt * 100.0).clamp(0.0, 100.0)
            } else {
                0.0
            }
        }
        _ => 0.0,
    };
    let (mem_used, mem_total) = mem_info();
    let (disk_used, disk_total) = disk_root();
    let (net_rx, net_tx) = net_totals();
    ControlMessage::HostMetrics {
        nonce,
        cpu_pct: cpu,
        mem_used_bytes: mem_used,
        mem_total_bytes: mem_total,
        disk_used_bytes: disk_used,
        disk_total_bytes: disk_total,
        net_rx_bytes: net_rx,
        net_tx_bytes: net_tx,
        load_1: load1(),
        uptime_secs: uptime(),
        hostname: hostname(),
        ts_unix: Utc::now().timestamp(),
    }
}
