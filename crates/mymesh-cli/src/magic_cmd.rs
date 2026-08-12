//! Alpha.3 magic: names, hosts, ssh config, tcp expose, DNS/socks status, carrier.
use anyhow::{bail, Result};
use console::style;
use mymesh_core::{mesh_ip_string, Config, DeviceLabel, DeviceStore, Paths, TrustState};
use mymesh_crypto::{parse_device_id, Identity};
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
    println!(
        "Tip: point system DNS or resolv to {} for *.{domain}",
        cfg.magic.dns_bind
    );
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
        println!(
            "{} alias {alias} → {}",
            style("ok").green().bold(),
            id.short()
        );
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
        println!(
            "{} group {group} → {}",
            style("ok").green().bold(),
            id.short()
        );
    }
    Ok(())
}

pub async fn cmd_resolve(paths: &Paths, name: &str) -> Result<()> {
    let store = DeviceStore::open(paths.devices_file())?;
    let cfg = Config::load(paths.config_file())?;
    let local = Identity::load_or_create(paths.identity_file())?;
    let q = name.trim().trim_end_matches('.').to_lowercase();
    let q = q
        .strip_suffix(&format!(".{}", cfg.magic.domain))
        .unwrap_or(&q);
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
        anyhow::anyhow!(
            "proxy-ssh: resolve '{host}': {e} (is the device linked? try: mymesh hosts)"
        )
    })?;
    if !store.is_trusted(&peer) {
        bail!("proxy-ssh: {host} is not trusted");
    }
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let (conn, transport) = crate::mesh_conn::connect_raw(&identity, &cfg, peer)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "proxy-ssh: mesh connect to {}: {e}
  (is local `mymesh serve` up? dial proxy required when agent owns the endpoint)",
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
    crate::mesh_conn::shutdown_opt(transport).await;
    Ok(())
}

async fn ssh_stdio_bridge(conn: Box<dyn mymesh_net::PeerConnection>, port: u16) -> Result<()> {
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ChannelKind, Frame, TcpMessage};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let conn: Arc<dyn mymesh_net::PeerConnection> = Arc::from(conn);
    eprintln!("proxy-ssh: dialing peer localhost:{} via mesh…", port);
    conn.send_frame(Frame {
        channel: ChannelId::tcp(1),
        payload: encode_msg(&TcpMessage::Dial { port, host: None })?,
    })
    .await?;
    let dial_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > dial_deadline {
            bail!(
                "proxy-ssh: timeout waiting for TCP dial ok to peer:{}
                   peer needs `mymesh serve` (alpha.3+) and sshd listening on 127.0.0.1:{}",
                port,
                port
            );
        }
        let frame = tokio::time::timeout(std::time::Duration::from_secs(10), conn.recv_frame())
            .await
            .map_err(|_| anyhow::anyhow!("proxy-ssh: recv timeout (connection stalled)"))?
            .map_err(|e| {
                anyhow::anyhow!(
                    "proxy-ssh: connection lost before dial: {e}
                       usually mesh path drop, not UFW on local sshd"
                )
            })?;
        if frame.channel.kind != ChannelKind::Tcp {
            // skip mesh gossip / control frames (membership, etc.)
            continue;
        }
        match decode_msg::<TcpMessage>(&frame.payload)? {
            TcpMessage::DialOk => {
                eprintln!("proxy-ssh: dial ok — bridging stdio (OpenSSH traffic)");
                break;
            }
            TcpMessage::DialErr { message } => bail!(
                "proxy-ssh: peer could not dial 127.0.0.1:{}: {message}
                   is sshd running on the peer? (UFW does not block localhost)",
                port
            ),
            TcpMessage::Close { reason } => bail!("proxy-ssh: closed: {reason}"),
            _ => {}
        }
    }

    // Full duplex: never hold a lock across both send and recv.
    let c_up = conn.clone();
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
            if c_up.send_frame(fr).await.is_err() {
                break;
            }
        }
    };
    let c_dn = conn.clone();
    let down = async move {
        let mut stdout = tokio::io::stdout();
        loop {
            let frame = match c_dn.recv_frame().await {
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
                Ok(_) => {}
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    let _ = conn.close().await;
    Ok(())
}

pub async fn cmd_expose(
    paths: &Paths,
    device: &str,
    port: u16,
    local_port: Option<u16>,
) -> Result<()> {
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
        let sock_path = std::path::PathBuf::from(&cfg.daemon.control_socket);
        tokio::spawn(async move {
            let (conn, transport) =
                match mymesh_net::connect_mesh(&identity, peer, &sock_path).await {
                    Ok(v) => v,
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
            if let Some(tr) = transport {
                tr.shutdown().await;
            }
        });
    }
}

pub async fn cmd_carrier(paths: &Paths, port: u16, pair_v1: bool) -> Result<()> {
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
        pair_v1,
    )
    .await?;

    let pair_prefix = if handle.pair_protocol_version == 1 {
        "pair/v1"
    } else {
        "pair/v2"
    };
    println!("{}", style("connect by carrier").bold());
    println!(
        "  pair API  {}/{}  (QR v{})",
        handle.host_base, pair_prefix, handle.pair_protocol_version
    );
    println!("  page      {}  (deprecated HTML fallback)", handle.url);
    if pair_v1 {
        println!("  mode      pair/v1 LAN escape (--pair-v1)");
    } else {
        println!("  mode      pair/v2 default (use --pair-v1 for alpha.1 LAN QR)");
    }
    println!();
    println!("  scan this QR with Carrier (same LAN):");
    println!("  {}", handle.pair_qr);
    if let Ok(code) = QrCode::new(handle.pair_qr.as_bytes()) {
        let qr = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{qr}");
    }
    println!();
    println!("Join path: other machine runs  mymesh link <this-host-id>");
    println!(
        "Phone approves via {pair_prefix} (JoinStore). HTML paste path still works as fallback."
    );
    println!("Waiting for join approval or phone paste… (Ctrl+C to cancel)");

    loop {
        if pend.exists() {
            let uri = std::fs::read_to_string(&pend)?.trim().to_string();
            let _ = std::fs::remove_file(&pend);
            if uri.is_empty() {
                continue;
            }
            println!(
                "{} got peer from phone — dialing join…",
                style("ok").green().bold()
            );
            let host_id = parse_join_target(&uri)?;
            let mut store = DeviceStore::open(paths.devices_file())?;
            let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
            match mymesh_net::connect_mesh(&identity, host_id, &sock).await {
                Ok((conn, transport)) => {
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
                            if let Some(tr) = transport {
                                tr.shutdown().await;
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("join failed: {e}");
                            if let Some(tr) = transport {
                                tr.shutdown().await;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("connect failed: {e}");
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
  mymesh carrier            # connect-by-carrier (default pair/v2 QR)
  mymesh carrier --pair-v1  # escape: alpha.1 pair/v1 LAN QR

Browser:
  export ALL_PROXY=socks5://127.0.0.1:18080
  open http://laptop.mym:7878

  OR set DNS to 127.0.0.1:5353 and use mesh IPs on 127.64.x.y auto-ports.
"#
    );
}

/// Helpers that return strings for the TUI (no stdout dependency).
pub fn ssh_config_text(paths: &Paths, domain: Option<String>) -> Result<String> {
    let cfg = Config::load(paths.config_file())?;
    let domain = domain.unwrap_or_else(|| cfg.magic.domain.clone());
    let domain = domain.trim_start_matches('.').to_string();
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "mymesh".into());
    let store = DeviceStore::open(paths.devices_file())?;
    let mut o = String::new();
    o.push_str("# MyMesh SSH — append to ~/.ssh/config\n");
    o.push_str(&format!("Host *.{domain}\n"));
    o.push_str(&format!("  ProxyCommand {exe} proxy-ssh %h\n"));
    o.push_str("  StrictHostKeyChecking accept-new\n");
    o.push_str("  UserKnownHostsFile ~/.ssh/mymesh_known_hosts\n\n");
    for d in store.list() {
        if d.trust != TrustState::Trusted {
            continue;
        }
        let name = d.label.as_str().to_lowercase();
        o.push_str(&format!("Host {name}.{domain} {name}\n"));
        o.push_str(&format!("  HostName {name}.{domain}\n"));
        o.push_str(&format!("  ProxyCommand {exe} proxy-ssh %h\n"));
        for a in &d.aliases {
            o.push_str(&format!("Host {a}.{domain} {a}\n"));
            o.push_str(&format!("  HostName {a}.{domain}\n"));
            o.push_str(&format!("  ProxyCommand {exe} proxy-ssh %h\n"));
        }
        o.push('\n');
    }
    Ok(o)
}

pub fn hosts_text(paths: &Paths) -> Result<String> {
    let store = DeviceStore::open(paths.devices_file())?;
    let cfg = Config::load(paths.config_file())?;
    let domain = cfg.magic.domain.trim_start_matches('.');
    let id = Identity::load_or_create(paths.identity_file())?;
    let local = id.device_id();
    let mut o = String::new();
    o.push_str(&format!(
        "self  {}  {}  mesh-ip {}\n",
        cfg.device_label,
        local.short(),
        mesh_ip_string(&local)
    ));
    o.push_str(&format!(
        "magic DNS {}  SOCKS {}  *.{domain}\n",
        cfg.magic.dns_bind, cfg.magic.socks_bind
    ));
    for d in store.list() {
        if d.trust != TrustState::Trusted {
            continue;
        }
        o.push_str(&format!(
            "• {}  {}.{}  {}  aliases={} groups={}\n",
            d.label.as_str(),
            d.label.as_str().to_lowercase(),
            domain,
            mesh_ip_string(&d.id),
            d.aliases.join(","),
            d.groups.join(",")
        ));
    }
    Ok(o)
}

pub fn magic_status_text(paths: &Paths) -> Result<String> {
    let cfg = Config::load(paths.config_file())?;
    Ok(format!(
        "magic.enabled = {}\n\
         domain        = *.{}\n\
         dns_bind      = {}\n\
         socks_bind    = {}\n\
         auto_ports    = {:?}\n\
         agent must run (mymesh serve / user unit) for DNS+SOCKS+port plane.\n\
         Browser: ALL_PROXY=socks5://{}  or system DNS → {}\n",
        cfg.magic.enabled,
        cfg.magic.domain.trim_start_matches('.'),
        cfg.magic.dns_bind,
        cfg.magic.socks_bind,
        cfg.magic.auto_ports,
        cfg.magic.socks_bind,
        cfg.magic.dns_bind,
    ))
}

/// Start carrier HTTP + default pair/v2 QR; returns HTML page URL and pair QR deep link.
///
/// TUI uses product default (v2). CLI escape: `mymesh carrier --pair-v1`.
pub async fn start_carrier_ui(paths: &Paths, port: u16) -> Result<(String, String)> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let pend = carrier_pending_path(paths);
    let _ = std::fs::remove_file(&pend);
    // Arm *before* start so bootstrap token / session TTL matches arm.until
    let _ = mymesh_core::ArmState::arm(paths.arm_file(), 900);
    let handle = start_carrier(
        paths.clone(),
        Identity::from_secret_bytes(identity.to_secret_bytes()),
        cfg.device_label.clone(),
        port,
        None,
        false, // default pair/v2 QR (D5)
    )
    .await?;
    Ok((handle.url, handle.pair_qr))
}

/// If phone posted a peer URI, complete join. Returns Some(msg) when done/attempted.
pub async fn poll_carrier_join(paths: &Paths) -> Result<Option<String>> {
    let pend = carrier_pending_path(paths);
    if !pend.exists() {
        return Ok(None);
    }
    let uri = std::fs::read_to_string(&pend)?.trim().to_string();
    let _ = std::fs::remove_file(&pend);
    if uri.is_empty() {
        return Ok(None);
    }
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let host_id = parse_join_target(&uri)?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    match mymesh_net::connect_mesh(&identity, host_id, &sock).await {
        Ok((conn, transport)) => {
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
                    if let Some(tr) = transport {
                        tr.shutdown().await;
                    }
                    Ok(Some(format!(
                        "carrier linked → {} ({})",
                        peer.label,
                        peer.id.short()
                    )))
                }
                Err(e) => {
                    if let Some(tr) = transport {
                        tr.shutdown().await;
                    }
                    Ok(Some(format!("carrier join failed: {e}")))
                }
            }
        }
        Err(e) => Ok(Some(format!("carrier connect failed: {e}"))),
    }
}
