//! Alpha.3 magic: names, hosts, ssh config, tcp expose, DNS/socks status, carrier.
use anyhow::{bail, Result};
use console::style;
use mymesh_core::{
    mesh_ip_string, Config, DeviceLabel, DeviceStore, Paths, TrustState,
};
use mymesh_crypto::{parse_device_id, Identity};
use mymesh_net::{IrohTransport, Transport};
use mymesh_session::{
    carrier_pending_path, client_bridge, run_join_as_guest, start_carrier, Session,
};
use qrcode::QrCode;
use std::net::SocketAddr;
use std::time::Duration;

use crate::resolve_device_pub;

pub async fn cmd_hosts(paths: &Paths, group: Option<String>) -> Result<()> {
    let store = DeviceStore::open(paths.devices_file())?;
    let cfg = Config::load(paths.config_file())?;
    let domain = cfg.magic.domain.trim_start_matches('.');
    let id = Identity::load_or_create(paths.identity_file())?;
    let local = id.device_id();
    println!(
        "{:<18} {:<16} {:<14} {}",
        "NAME", "MESH-IP", "ID", "ALIASES/GROUPS"
    );
    println!(
        "{:<18} {:<16} {:<14} {}",
        format!("{} (self)", cfg.device_label),
        mesh_ip_string(&local),
        local.short(),
        format!("*.{domain}")
    );
    for d in store.list() {
        if d.trust != TrustState::Trusted {
            continue;
        }
        if let Some(g) = &group {
            if !d.groups.iter().any(|x| x.eq_ignore_ascii_case(g)) {
                continue;
            }
        }
        let ag = format!(
            "aliases={} groups={}",
            d.aliases.join(","),
            d.groups.join(",")
        );
        println!(
            "{:<18} {:<16} {:<14} {}",
            d.label.as_str(),
            mesh_ip_string(&d.id),
            d.id.short(),
            ag
        );
        println!(
            "  dns: {}.{domain}  (and aliases)",
            d.label.as_str().to_lowercase()
        );
    }
    println!();
    println!(
        "DNS {}  SOCKS5 {}  auto_ports {:?}",
        cfg.magic.dns_bind, cfg.magic.socks_bind, cfg.magic.auto_ports
    );
    println!("Tip: point system DNS or resolv to {} for *.{domain}", cfg.magic.dns_bind);
    println!("     or export ALL_PROXY=socks5://{}", cfg.magic.socks_bind);
    Ok(())
}

pub async fn cmd_label(paths: &Paths, device: &str, name: &str) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device_pub(&store, device)?;
    store.set_label(&id, DeviceLabel::new(name))?;
    println!("{} {} → {}", style("ok").green().bold(), id.short(), name);
    Ok(())
}

pub async fn cmd_alias(paths: &Paths, device: &str, alias: &str, remove: bool) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device_pub(&store, device)?;
    if remove {
        store.remove_alias(&id, alias)?;
        println!("{} removed alias {alias}", style("ok").green().bold());
    } else {
        store.add_alias(&id, alias)?;
        println!("{} alias {alias} → {}", style("ok").green().bold(), id.short());
    }
    Ok(())
}

pub async fn cmd_group(paths: &Paths, device: &str, group: &str, remove: bool) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device_pub(&store, device)?;
    if remove {
        store.remove_group(&id, group)?;
        println!("{} removed group {group}", style("ok").green().bold());
    } else {
        store.add_group(&id, group)?;
        println!("{} group {group} → {}", style("ok").green().bold(), id.short());
    }
    Ok(())
}

pub async fn cmd_resolve(paths: &Paths, name: &str) -> Result<()> {
    let store = DeviceStore::open(paths.devices_file())?;
    let cfg = Config::load(paths.config_file())?;
    let local = Identity::load_or_create(paths.identity_file())?;
    let q = name.trim().trim_end_matches('.').to_lowercase();
    let q = q.strip_suffix(&format!(".{}", cfg.magic.domain)).unwrap_or(&q);
    let id = if cfg.device_label.eq_ignore_ascii_case(q)
        || local.device_id().short().starts_with(q)
        || local.device_id().to_string().starts_with(q)
    {
        local.device_id()
    } else {
        resolve_device_pub(&store, name)?
    };
    let rec = store.get(&id);
    println!("device  {}", id);
    println!("short   {}", id.short());
    println!("mesh-ip {}", mesh_ip_string(&id));
    if id == local.device_id() {
        println!("label   {} (self)", cfg.device_label);
    } else if let Some(r) = rec {
        println!("label   {}", r.label.as_str());
        println!("aliases {}", r.aliases.join(", "));
        println!("groups  {}", r.groups.join(", "));
    }
    Ok(())
}

pub fn cmd_ssh_config(paths: &Paths, domain: Option<String>) -> Result<()> {
    let cfg = Config::load(paths.config_file())?;
    let domain = domain.unwrap_or_else(|| cfg.magic.domain.clone());
    let domain = domain.trim_start_matches('.').to_string();
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "mymesh".into());
    let store = DeviceStore::open(paths.devices_file())?;
    println!("# MyMesh SSH — append to ~/.ssh/config");
    println!("Host *.{domain}");
    println!("  ProxyCommand {exe} proxy-ssh %h");
    println!("  StrictHostKeyChecking accept-new");
    println!("  UserKnownHostsFile ~/.ssh/mymesh_known_hosts");
    println!();
    for d in store.list() {
        if d.trust != TrustState::Trusted {
            continue;
        }
        let name = d.label.as_str().to_lowercase();
        println!("Host {name}.{domain} {name}");
        println!("  HostName {name}.{domain}");
        println!("  ProxyCommand {exe} proxy-ssh %h");
        for a in &d.aliases {
            println!("Host {a}.{domain} {a}");
            println!("  HostName {a}.{domain}");
            println!("  ProxyCommand {exe} proxy-ssh %h");
        }
        println!();
    }
    Ok(())
}

pub async fn cmd_proxy_ssh(paths: &Paths, host: &str) -> Result<()> {
    // OpenSSH ProxyCommand: stdout MUST be pure tunnel bytes.
    // All diagnostics go to stderr (tracing is also stderr + quiet for this cmd).
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = resolve_device_pub(&store, host).map_err(|e| {
        anyhow::anyhow!("proxy-ssh: resolve '{host}': {e} (is the device linked? try: mymesh hosts)")
    })?;
    if !store.is_trusted(&peer) {
        bail!("proxy-ssh: {host} is not trusted");
    }
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let transport = IrohTransport::bind(&identity).await.map_err(|e| {
        anyhow::anyhow!("proxy-ssh: bind transport: {e}")
    })?;
    let conn = transport.connect(peer).await.map_err(|e| {
        anyhow::anyhow!(
            "proxy-ssh: mesh connect to {}: {e}
  (peer mymesh serve running? network/relay ok? UFW rarely blocks this path)",
            peer.short()
        )
    })?;
    let session = Session::handshake_dialer(
        conn,
        &identity,
        &cfg.device_label,
        &store,
        mymesh_core::Capability::all(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("proxy-ssh: handshake: {e}"))?;
    // Tunnel to peer localhost:22 — requires peer agent alpha.3+ (Tcp channel) + sshd on 127.0.0.1
    ssh_stdio_bridge(session.into_conn(), 22).await?;
    let _ = transport.shutdown().await;
    Ok(())
}

async fn ssh_stdio_bridge(
    conn: Box<dyn mymesh_net::PeerConnection>,
    port: u16,
) -> Result<()> {
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ChannelKind, Frame, TcpMessage};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    conn.send_frame(Frame {
        channel: ChannelId::tcp(1),
        payload: encode_msg(&TcpMessage::Dial {
            port,
            host: None,
        })?,
    })
    .await?;
    let dial_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > dial_deadline {
            bail!(
                "proxy-ssh: timeout waiting for TCP dial ok to peer:{}\n                   peer needs `mymesh serve` (alpha.3+) and sshd listening on 127.0.0.1:{}",
                port, port
            );
        }
        let frame = tokio::time::timeout(std::time::Duration::from_secs(10), conn.recv_frame())
            .await
            .map_err(|_| {
                anyhow::anyhow!("proxy-ssh: recv timeout (connection stalled)")
            })?
            .map_err(|e| {
                anyhow::anyhow!(
                    "proxy-ssh: connection lost before dial: {e}\n                       usually mesh path drop, not UFW on local sshd"
                )
            })?;
        if frame.channel.kind != ChannelKind::Tcp {
            // skip mesh gossip / control frames
            continue;
        }
        match decode_msg::<TcpMessage>(&frame.payload)? {
            TcpMessage::DialOk => break,
            TcpMessage::DialErr { message } => bail!(
                "proxy-ssh: peer could not dial 127.0.0.1:{}: {message}\n                   is sshd running on the peer? (UFW does not block localhost)",
                port
            ),
            TcpMessage::Close { reason } => bail!("proxy-ssh: closed: {reason}"),
            _ => {}
        }
    }

    let conn = Arc::new(Mutex::new(conn));
    let c1 = conn.clone();
    let up = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let fr = Frame {
                channel: ChannelId::tcp(1),
                payload: encode_msg(&TcpMessage::Data {
                    data: buf[..n].to_vec(),
                })
                .unwrap_or_default(),
            };
            if c1.lock().await.send_frame(fr).await.is_err() {
                break;
            }
        }
    };
    let c2 = conn.clone();
    let down = async move {
        let mut stdout = tokio::io::stdout();
        loop {
            let frame = {
                let g = c2.lock().await;
                g.recv_frame().await
            };
            let frame = match frame {
                Ok(f) => f,
                Err(_) => break,
            };
            if frame.channel.kind != ChannelKind::Tcp {
                continue;
            }
            match decode_msg::<TcpMessage>(&frame.payload) {
                Ok(TcpMessage::Data { data }) => {
                    if stdout.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = stdout.flush().await;
                }
                Ok(TcpMessage::Close { .. }) => break,
                _ => {}
            }
        }
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

pub async fn cmd_expose(paths: &Paths, device: &str, port: u16, local_port: Option<u16>) -> Result<()> {
    let local_port = local_port.unwrap_or(port);
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = resolve_device_pub(&store, device)?;
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let listen: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "{} listening on {} → {}:{} via mesh",
        style("expose").bold(),
        listen,
        device,
        port
    );
    loop {
        let (sock, _) = listener.accept().await?;
        let identity = Identity::from_secret_bytes(identity.to_secret_bytes());
        let store = DeviceStore::open(paths.devices_file())?;
        let label = cfg.device_label.clone();
        tokio::spawn(async move {
            let transport = match IrohTransport::bind(&identity).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("bind: {e}");
                    return;
                }
            };
            let conn = match transport.connect(peer).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("connect: {e}");
                    return;
                }
            };
            let session = match Session::handshake_dialer(
                conn,
                &identity,
                &label,
                &store,
                mymesh_core::Capability::all(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("handshake: {e}");
                    return;
                }
            };
            let _ = client_bridge(session.into_conn(), sock, port, None).await;
            let _ = transport.shutdown().await;
        });
    }
}

pub async fn cmd_carrier(paths: &Paths, port: u16) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    // clear pending
    let pend = carrier_pending_path(paths);
    let _ = std::fs::remove_file(&pend);

    let handle = start_carrier(
        paths.clone(),
        Identity::from_secret_bytes(identity.to_secret_bytes()),
        cfg.device_label.clone(),
        port,
        None,
    )
    .await?;

    println!("{}", style("connect by carrier").bold());
    println!("  page  {}", handle.url);
    println!("  scan this QR with your phone (same LAN as this machine):");
    if let Ok(code) = QrCode::new(handle.url.as_bytes()) {
        let qr = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{qr}");
    }
    println!();
    println!("On the other machine: mymesh id --uri   (or show QR), scan/paste into the phone page.");
    println!("Waiting for phone to submit the other device… (Ctrl+C to cancel)");

    // also arm
    let _ = mymesh_core::ArmState::arm(paths.arm_file(), 900);

    loop {
        if pend.exists() {
            let uri = std::fs::read_to_string(&pend)?.trim().to_string();
            let _ = std::fs::remove_file(&pend);
            if uri.is_empty() {
                continue;
            }
            println!("{} got peer from phone — dialing join…", style("ok").green().bold());
            let host_id = parse_join_target(&uri)?;
            let transport = IrohTransport::bind(&identity).await?;
            let mut store = DeviceStore::open(paths.devices_file())?;
            match transport.connect(host_id).await {
                Ok(conn) => {
                    match run_join_as_guest(
                        conn,
                        &identity,
                        &cfg.device_label,
                        &mut store,
                        &paths.mesh_file(),
                        mymesh_core::Capability::all(),
                    )
                    .await
                    {
                        Ok(peer) => {
                            println!(
                                "{} linked via carrier to {} ({})",
                                style("ok").green().bold(),
                                peer.label,
                                peer.id.short()
                            );
                            let _ = transport.shutdown().await;
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("join failed: {e}");
                            let _ = transport.shutdown().await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("connect failed: {e}");
                    let _ = transport.shutdown().await;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

fn parse_join_target(uri: &str) -> Result<mymesh_core::DeviceId> {
    // mymesh://join/<hex> or raw hex/words
    let s = uri.trim();
    if let Some(rest) = s.strip_prefix("mymesh://join/") {
        let hex = rest.split(&['?', '#'][..]).next().unwrap_or(rest);
        return Ok(parse_device_id(hex)?);
    }
    if let Some(rest) = s.strip_prefix("mymesh://") {
        return Ok(parse_device_id(rest.split('/').next().unwrap_or(rest))?);
    }
    Ok(parse_device_id(s)?)
}

pub fn print_magic_help() {
    println!(
        r#"MyMesh magic plane (alpha.3)

  mymesh serve              # agent + DNS + SOCKS + auto port forwards + probes
  mymesh hosts              # names, mesh IPs, groups
  mymesh label <dev> <name>
  mymesh alias <dev> <name>
  mymesh group <dev> <tag>
  mymesh resolve <name>
  mymesh ssh-config         # print Host *.mym ProxyCommand block
  mymesh proxy-ssh <host>   # used by OpenSSH ProxyCommand
  mymesh expose <dev> <port> [--local N]
  mymesh carrier            # connect-by-carrier (phone QR page)

Browser:
  export ALL_PROXY=socks5://127.0.0.1:18080
  open http://laptop.mym:7878

  OR set DNS to 127.0.0.1:5353 and use mesh IPs on 127.64.x.y auto-ports.
"#
    );
}
