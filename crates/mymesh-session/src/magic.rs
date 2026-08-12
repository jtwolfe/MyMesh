//! Magic LAN plane: mesh IPs (127.64/16), DNS for *.mym, SOCKS5, auto port forwards.
use mymesh_core::{mesh_ipv4, Config, DeviceId, DeviceStore, MagicConfig, Paths, TrustState};
use mymesh_crypto::Identity;
use mymesh_net::{IrohTransport, Transport};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::session::Session;
use crate::tcp_tunnel;

#[derive(Clone)]
pub struct MagicPlane {
    paths: Paths,
    secret: [u8; 32],
    label: String,
    magic: MagicConfig,
    local_id: DeviceId,
    active_binds: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Shared agent endpoint — never bind a second iroh identity.
    transport: Option<Arc<IrohTransport>>,
}

impl MagicPlane {
    pub fn new(
        paths: Paths,
        identity: &Identity,
        label: String,
        cfg: &Config,
        transport: Option<Arc<IrohTransport>>,
    ) -> Self {
        Self {
            paths,
            secret: identity.to_secret_bytes(),
            label,
            magic: cfg.magic.clone(),
            local_id: identity.device_id(),
            active_binds: Arc::new(Mutex::new(HashSet::new())),
            transport,
        }
    }

    fn identity(&self) -> Identity {
        Identity::from_secret_bytes(self.secret)
    }

    pub async fn spawn(self) {
        if !self.magic.enabled {
            info!("magic plane disabled");
            return;
        }
        let domain = self.magic.domain.trim_start_matches('.').to_lowercase();
        info!(
            %domain,
            dns = %self.magic.dns_bind,
            socks = %self.magic.socks_bind,
            ports = ?self.magic.auto_ports,
            "magic plane starting"
        );
        let this = Arc::new(self);
        {
            let t = this.clone();
            tokio::spawn(async move {
                if let Err(e) = t.run_dns().await {
                    warn!(%e, "magic DNS exited");
                }
            });
        }
        {
            let t = this.clone();
            tokio::spawn(async move {
                if let Err(e) = t.run_socks().await {
                    warn!(%e, "magic SOCKS exited");
                }
            });
        }
        {
            let t = this.clone();
            tokio::spawn(async move {
                t.run_auto_forwards().await;
            });
        }
        if this.magic.reconnect_probe_secs > 0 {
            let t = this.clone();
            tokio::spawn(async move {
                t.run_reconnect_probes().await;
            });
        }
    }

    fn store(&self) -> mymesh_core::Result<DeviceStore> {
        DeviceStore::open(self.paths.devices_file())
    }

    fn name_map(&self) -> HashMap<String, (DeviceId, Ipv4Addr)> {
        let mut m = HashMap::new();
        let domain = self.magic.domain.trim_start_matches('.').to_lowercase();
        let push = |m: &mut HashMap<String, (DeviceId, Ipv4Addr)>, name: &str, id: DeviceId| {
            let ip = mesh_ipv4(&id);
            let n = name.trim().to_lowercase();
            if n.is_empty() {
                return;
            }
            m.insert(n.clone(), (id, ip));
            m.insert(format!("{n}.{domain}"), (id, ip));
        };
        push(&mut m, &self.label, self.local_id);
        if let Ok(store) = self.store() {
            for d in store.list() {
                if d.trust != TrustState::Trusted {
                    continue;
                }
                push(&mut m, d.label.as_str(), d.id);
                for a in &d.aliases {
                    push(&mut m, a, d.id);
                }
            }
        }
        m
    }

    async fn run_dns(&self) -> anyhow::Result<()> {
        let sock = UdpSocket::bind(&self.magic.dns_bind).await?;
        info!(bind = %self.magic.dns_bind, "magic DNS ready");
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if n < 12 {
                continue;
            }
            if let Some(resp) = build_dns_response(&buf[..n], &self.name_map()) {
                let _ = sock.send_to(&resp, from).await;
            }
        }
    }

    async fn run_socks(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.magic.socks_bind).await?;
        info!(bind = %self.magic.socks_bind, "magic SOCKS5 ready");
        loop {
            let (stream, _) = listener.accept().await?;
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_socks(stream).await {
                    debug!(%e, "socks session");
                }
            });
        }
    }

    async fn handle_socks(&self, mut stream: tokio::net::TcpStream) -> anyhow::Result<()> {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Ok(());
        }
        let nmethods = hdr[1] as usize;
        let mut methods = vec![0u8; nmethods];
        if nmethods > 0 {
            stream.read_exact(&mut methods).await?;
        }
        stream.write_all(&[0x05, 0x00]).await?;

        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        if req[0] != 0x05 || req[1] != 0x01 {
            let _ = stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
        let (host, port) = match req[3] {
            0x01 => {
                let mut a = [0u8; 4];
                stream.read_exact(&mut a).await?;
                let mut p = [0u8; 2];
                stream.read_exact(&mut p).await?;
                (
                    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
                    u16::from_be_bytes(p),
                )
            }
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await?;
                let mut name = vec![0u8; l[0] as usize];
                stream.read_exact(&mut name).await?;
                let mut p = [0u8; 2];
                stream.read_exact(&mut p).await?;
                (
                    String::from_utf8_lossy(&name).into_owned(),
                    u16::from_be_bytes(p),
                )
            }
            _ => {
                let _ = stream
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Ok(());
            }
        };

        let peer = match self.resolve_host(&host) {
            Ok(id) => id,
            Err(e) => {
                let _ = stream
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(e);
            }
        };

        // success
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        self.open_tunnel(peer, port, stream).await
    }

    fn resolve_host(&self, host: &str) -> anyhow::Result<DeviceId> {
        let key = host.trim_end_matches('.').to_lowercase();
        let map = self.name_map();
        if let Some((id, _)) = map.get(&key) {
            return Ok(*id);
        }
        if let Ok(ip) = key.parse::<Ipv4Addr>() {
            if let Some((id, _)) = map.values().find(|(_, mip)| *mip == ip) {
                return Ok(*id);
            }
        }
        Ok(self.store()?.resolve_query(host)?)
    }

    async fn open_tunnel(
        &self,
        peer: DeviceId,
        port: u16,
        local: tokio::net::TcpStream,
    ) -> anyhow::Result<()> {
        if peer == self.local_id {
            let remote = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            let (mut a, mut b) = local.into_split();
            let (mut c, mut d) = remote.into_split();
            let u = tokio::io::copy(&mut a, &mut d);
            let v = tokio::io::copy(&mut c, &mut b);
            tokio::select! {
                _ = u => {}
                _ = v => {}
            }
            return Ok(());
        }
        let identity = self.identity();
        let store = self.store()?;
        let Some(transport) = self.transport.clone() else {
            anyhow::bail!("magic tunnel: no shared transport (agent not wired)");
        };
        let conn = transport.connect(peer).await?;
        let session = Session::handshake_dialer(
            conn,
            &identity,
            &self.label,
            &store,
            mymesh_core::Capability::all(),
        )
        .await?;
        tcp_tunnel::client_bridge(session.into_conn(), local, port, None).await?;
        // do NOT shutdown shared transport
        Ok(())
    }

    async fn run_auto_forwards(&self) {
        loop {
            let map = self.name_map();
            let mut peers: HashMap<DeviceId, Ipv4Addr> = HashMap::new();
            for (_n, (id, ip)) in &map {
                peers.insert(*id, *ip);
            }
            for (id, ip) in peers {
                for &port in &self.magic.auto_ports {
                    let addr = SocketAddr::from((ip, port));
                    {
                        let mut g = self.active_binds.lock().await;
                        if g.contains(&addr) {
                            continue;
                        }
                        g.insert(addr);
                    }
                    let this = self.clone();
                    tokio::spawn(async move {
                        let listener = match TcpListener::bind(addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                debug!(%addr, %e, "bind skip");
                                this.active_binds.lock().await.remove(&addr);
                                return;
                            }
                        };
                        info!(%addr, peer = %id.short(), "magic port forward");
                        loop {
                            match listener.accept().await {
                                Ok((sock, _)) => {
                                    let this2 = this.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = this2.open_tunnel(id, port, sock).await {
                                            debug!(%e, "tunnel end");
                                        }
                                    });
                                }
                                Err(_) => break,
                            }
                        }
                        this.active_binds.lock().await.remove(&addr);
                    });
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    async fn run_reconnect_probes(&self) {
        let secs = self.magic.reconnect_probe_secs.max(10);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let Ok(store) = self.store() else { continue };
            for d in store.list() {
                if d.trust != TrustState::Trusted || d.id == self.local_id {
                    continue;
                }
                let this = self.clone();
                let peer = d.id;
                tokio::spawn(async move {
                    if let Err(e) = this.probe(peer).await {
                        debug!(peer = %peer.short(), %e, "probe miss");
                    } else {
                        debug!(peer = %peer.short(), "probe ok");
                    }
                });
            }
        }
    }

    async fn probe(&self, peer: DeviceId) -> anyhow::Result<()> {
        let identity = self.identity();
        let store = self.store()?;
        let Some(transport) = self.transport.clone() else {
            debug!("probe skipped — no shared transport");
            return Ok(());
        };
        let conn = transport.connect(peer).await?;
        let _ = Session::handshake_dialer(
            conn,
            &identity,
            &self.label,
            &store,
            mymesh_core::Capability::all(),
        )
        .await?;
        if let Ok(mut store) = DeviceStore::open(self.paths.devices_file()) {
            if let Some(mut rec) = store.get(&peer).cloned() {
                rec.last_seen = Some(chrono::Utc::now());
                let _ = store.upsert(rec);
            }
        }
        Ok(())
    }
}

fn build_dns_response(
    req: &[u8],
    names: &HashMap<String, (DeviceId, Ipv4Addr)>,
) -> Option<Vec<u8>> {
    if req.len() < 12 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    while i < req.len() {
        let l = req[i] as usize;
        if l == 0 {
            i += 1;
            break;
        }
        if l & 0xC0 == 0xC0 {
            return None;
        }
        i += 1;
        if i + l > req.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&req[i..i + l]).to_string());
        i += l;
    }
    if i + 4 > req.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([req[i], req[i + 1]]);
    let qname = labels.join(".").to_lowercase();
    let ip = if qtype == 1 || qtype == 255 {
        names.get(&qname).map(|(_, ip)| *ip)
    } else {
        None
    };
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&req[0..2]);
    out.extend_from_slice(&if ip.is_some() { 0x8180u16 } else { 0x8183u16 }.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(if ip.is_some() { 1u16 } else { 0 }).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&req[12..i + 4]);
    if let Some(ip) = ip {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&30u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    Some(out)
}
