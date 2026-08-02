//! Peer latency probe + bandwidth test over an established session path.
use anyhow::{bail, Context, Result};
use chrono::Utc;
use mymesh_core::{
    BandwidthResult, Capability, Config, DeviceStore, HostStatsSnap, LatencySample, Paths,
    PeerMetrics,
};
use mymesh_crypto::Identity;
use mymesh_net::{IrohTransport, Transport};
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, FileMessage, Frame};
use mymesh_session::Session;
use std::time::{Duration, Instant};

async fn open_session(
    paths: &Paths,
    device: &str,
) -> Result<(Session, IrohTransport, mymesh_core::DeviceId)> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = crate::resolve_device(&store, device)?;
    if !store.is_trusted(&peer) {
        bail!("device not trusted — link first");
    }
    let transport = IrohTransport::bind(&identity).await?;
    let conn = transport.connect(peer).await?;
    let session = Session::handshake_dialer(
        conn,
        &identity,
        &cfg.device_label,
        &store,
        Capability::all(),
    )
    .await?;
    Ok((session, transport, peer))
}

/// Single RTT probe via control Ping/Pong; records into metrics history.
pub async fn probe_ping(paths: &Paths, device: &str) -> Result<u64> {
    let (session, transport, peer) = open_session(paths, device).await?;
    let conn = session.into_conn();
    let nonce = rand::random::<u64>();
    let t0 = Instant::now();
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&ControlMessage::Ping { nonce })?,
    })
    .await?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let rtt = loop {
        if Instant::now() > deadline {
            let mut m = PeerMetrics::load(paths.metrics_dir(), &peer)?;
            m.push_latency(LatencySample {
                at: Utc::now(),
                rtt_ms: None,
                ok: false,
                note: Some("timeout".into()),
            });
            m.save(paths.metrics_dir())?;
            let _ = conn.close().await;
            transport.shutdown().await;
            bail!("ping timeout");
        }
        let frame = tokio::time::timeout(Duration::from_secs(5), conn.recv_frame())
            .await
            .context("recv timeout")??;
        if frame.channel.kind != mymesh_protocol::ChannelKind::Control {
            continue;
        }
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        match msg {
            ControlMessage::Pong { nonce: n } if n == nonce => {
                break t0.elapsed().as_millis() as u64;
            }
            ControlMessage::Ping { nonce: n } => {
                // echo if peer pings us mid-flight
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&ControlMessage::Pong { nonce: n })?,
                })
                .await?;
            }
            _ => {}
        }
    };

    let mut m = PeerMetrics::load(paths.metrics_dir(), &peer)?;
    m.push_latency(LatencySample {
        at: Utc::now(),
        rtt_ms: Some(rtt),
        ok: true,
        note: None,
    });
    m.save(paths.metrics_dir())?;
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(rtt)
}

/// Push ~`bytes` of payload to peer via file channel temp path; measure throughput.
pub async fn probe_bandwidth(paths: &Paths, device: &str, bytes: u64) -> Result<BandwidthResult> {
    let bytes = bytes.clamp(64 * 1024, 64 * 1024 * 1024);
    let (session, transport, peer) = open_session(paths, device).await?;
    let conn = session.into_conn();
    let remote = format!(".mymesh-bw-probe-{}", std::process::id());
    let chunk = vec![0xA5u8; 64 * 1024];
    let t0 = Instant::now();
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Put {
            path: remote.clone(),
            size: bytes,
            mode: 0o600,
            resume_from: 0,
        })?,
    })
    .await?;

    let mut sent = 0u64;
    while sent < bytes {
        let n = ((bytes - sent) as usize).min(chunk.len());
        conn.send_frame(Frame {
            channel: ChannelId::files(1),
            payload: encode_msg(&FileMessage::Chunk {
                offset: sent,
                data: chunk[..n].to_vec(),
            })?,
        })
        .await?;
        sent += n as u64;
    }
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Done {
            path: remote.clone(),
            bytes,
        })?,
    })
    .await?;

    // wait ack
    let frame = tokio::time::timeout(Duration::from_secs(60), conn.recv_frame())
        .await
        .context("bw ack timeout")??;
    let msg: FileMessage = decode_msg(&frame.payload)?;
    match msg {
        FileMessage::Done { .. } => {}
        FileMessage::Error { message } => bail!("{message}"),
        other => bail!("unexpected {other:?}"),
    }
    let elapsed = t0.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;
    let secs = elapsed.as_secs_f64().max(0.000_001);
    let mbps = (bytes as f64 * 8.0) / secs / 1_000_000.0;
    let result = BandwidthResult {
        at: Utc::now(),
        bytes,
        elapsed_ms,
        mbps,
        direction: "push".into(),
    };
    let mut m = PeerMetrics::load(paths.metrics_dir(), &peer)?;
    m.last_bandwidth = Some(result.clone());
    m.save(paths.metrics_dir())?;
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(result)
}

/// Poll once for each trusted device (best-effort).
pub async fn probe_all(paths: &Paths) -> Result<Vec<(String, Result<u64, String>)>> {
    let store = DeviceStore::open(paths.devices_file())?;
    let mut out = Vec::new();
    for d in store.list() {
        if !matches!(d.trust, mymesh_core::TrustState::Trusted) {
            continue;
        }
        let label = d.label.as_str().to_string();
        let r = probe_ping(paths, &d.id.to_string())
            .await
            .map_err(|e| e.to_string());
        out.push((label, r));
    }
    Ok(out)
}


pub async fn probe_host_metrics(paths: &Paths, device: &str) -> Result<HostStatsSnap> {
    let (session, transport, peer) = open_session(paths, device).await?;
    let conn = session.into_conn();
    let nonce = rand::random::<u64>();
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&ControlMessage::HostMetricsRequest { nonce })?,
    })
    .await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let snap = loop {
        if Instant::now() > deadline {
            let _ = conn.close().await;
            transport.shutdown().await;
            bail!("metrics timeout");
        }
        let frame = tokio::time::timeout(Duration::from_secs(10), conn.recv_frame())
            .await
            .context("metrics recv")??;
        if frame.channel.kind != mymesh_protocol::ChannelKind::Control {
            continue;
        }
        let msg: ControlMessage = decode_msg(&frame.payload)?;
        match msg {
            ControlMessage::HostMetrics {
                nonce: n,
                cpu_pct,
                mem_used_bytes,
                mem_total_bytes,
                disk_used_bytes,
                disk_total_bytes,
                net_rx_bytes,
                net_tx_bytes,
                load_1,
                uptime_secs,
                hostname,
                ..
            } if n == nonce => {
                break HostStatsSnap {
                    at: Utc::now(),
                    cpu_pct,
                    mem_used_bytes,
                    mem_total_bytes,
                    disk_used_bytes,
                    disk_total_bytes,
                    net_rx_bytes,
                    net_tx_bytes,
                    load_1,
                    uptime_secs,
                    hostname,
                };
            }
            ControlMessage::Ping { nonce: n } => {
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&ControlMessage::Pong { nonce: n })?,
                })
                .await?;
            }
            _ => {}
        }
    };
    let mut m = PeerMetrics::load(paths.metrics_dir(), &peer)?;
    m.last_host = Some(snap.clone());
    m.save(paths.metrics_dir())?;
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(snap)
}

pub async fn remote_list(
    paths: &Paths,
    device: &str,
    path: &str,
) -> Result<Vec<mymesh_protocol::FileEntry>> {
    let (session, transport, _) = open_session(paths, device).await?;
    let conn = session.into_conn();
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::List {
            path: path.to_string(),
        })?,
    })
    .await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            let _ = conn.close().await;
            transport.shutdown().await;
            bail!("list timeout");
        }
        let frame = tokio::time::timeout(Duration::from_secs(10), conn.recv_frame())
            .await
            .context("list recv")??;
        if frame.channel.kind != mymesh_protocol::ChannelKind::Files {
            continue;
        }
        let msg: FileMessage = decode_msg(&frame.payload)?;
        match msg {
            FileMessage::ListResult { entries } => {
                let _ = conn.close().await;
                transport.shutdown().await;
                return Ok(entries);
            }
            FileMessage::Error { message } => {
                let _ = conn.close().await;
                transport.shutdown().await;
                bail!("{message}");
            }
            _ => {}
        }
    }
}
