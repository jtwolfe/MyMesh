//! MyMesh CLI — pair devices, open shells, copy files, control desktops.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use mymesh_core::{Capability, Config, DeviceStore, Paths};
use mymesh_crypto::Identity;
use mymesh_net::{
    run_mailbox_server, FsMailbox, HttpMailbox, IrohTransport, LocalFabric,
    LocalRendezvous, Rendezvous, Transport,
};
use mymesh_protocol::{
    decode_msg, encode_msg, ChannelId, FileMessage, Frame, TerminalMessage,
};
use mymesh_session::{run_guest_pair, run_host_pair_code, Agent, Session};
use mymesh_terminal::TerminalClient;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "mymesh",
    version,
    about = "Peer-to-peer remote access: terminal, files, desktop — pair like Signal",
    long_about = "MyMesh links your machines with a short pairing code. After linking,\n\
devices dial each other with NAT traversal (no port forwards). Use one binary\n\
as both client and service."
)]
struct Cli {
    #[arg(long, global = true, env = "MYMESH_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Status,
    Init {
        #[arg(long)]
        label: Option<String>,
    },
    /// Link a new device (Signal-style pairing code)
    Link {
        code: Option<String>,
        #[arg(long)]
        nameplate: Option<u16>,
        /// Shared directory for FS mailbox (default: $MYMESH_MAILBOX_DIR or XDG runtime)
        #[arg(long, env = "MYMESH_MAILBOX_DIR")]
        mailbox_dir: Option<PathBuf>,
        /// HTTP mailbox base URL (default: $MYMESH_MAILBOX / config)
        #[arg(long, env = "MYMESH_MAILBOX")]
        mailbox: Option<String>,
    },
    Devices {
        #[arg(long)]
        json: bool,
    },
    Unlink { device: String },
    /// Open a remote terminal on a linked device
    Shell {
        device: String,
        #[arg(long)]
        shell: Option<String>,
    },
    /// Copy files: local path or device:path
    Cp { src: String, dst: String },
    Desktop {
        device: String,
        #[arg(long, default_value_t = 30)]
        fps: u8,
    },
    /// Run the background agent (accept shells/files)
    Serve {
        #[arg(long)]
        foreground: bool,
    },
    /// Run HTTP pairing mailbox server
    Mailbox {
        #[arg(long, default_value = "0.0.0.0:9876")]
        bind: String,
    },
    Demo {
        #[command(subcommand)]
        scenario: DemoCmd,
    },
    InstallNotes,
}

#[derive(Subcommand, Debug)]
enum DemoCmd {
    Pair,
    Session,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mymesh=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let paths = resolve_paths(cli.home.as_ref())?;

    match cli.command {
        Commands::Init { label } => cmd_init(&paths, label).await?,
        Commands::Status => cmd_status(&paths).await?,
        Commands::Link {
            code,
            nameplate,
            mailbox_dir,
            mailbox,
        } => cmd_link(&paths, code, nameplate, mailbox_dir, mailbox).await?,
        Commands::Devices { json } => cmd_devices(&paths, json).await?,
        Commands::Unlink { device } => cmd_unlink(&paths, &device).await?,
        Commands::Shell { device, shell } => cmd_shell(&paths, &device, shell).await?,
        Commands::Cp { src, dst } => cmd_cp(&paths, &src, &dst).await?,
        Commands::Desktop { device, fps } => {
            let _ = (device, fps);
            println!(
                "{}",
                style("desktop: deferred to M4 after M1–M3 validation").yellow()
            );
        }
        Commands::Serve { foreground } => {
            let _ = foreground;
            cmd_serve(&paths).await?;
        }
        Commands::Mailbox { bind } => {
            let addr: SocketAddr = bind.parse().context("invalid --bind address")?;
            run_mailbox_server(addr).await?;
        }
        Commands::Demo { scenario } => match scenario {
            DemoCmd::Pair => demo_pair().await?,
            DemoCmd::Session => demo_session().await?,
        },
        Commands::InstallNotes => print_install_notes(),
    }
    Ok(())
}

fn resolve_paths(home: Option<&PathBuf>) -> Result<Paths> {
    if let Some(h) = home {
        let p = Paths {
            config_dir: h.join("config"),
            data_dir: h.join("data"),
            cache_dir: h.join("cache"),
        };
        p.ensure()?;
        Ok(p)
    } else {
        let p = Paths::discover()?;
        p.ensure()?;
        Ok(p)
    }
}

async fn cmd_init(paths: &Paths, label: Option<String>) -> Result<()> {
    let id = Identity::load_or_create(paths.identity_file())?;
    let mut cfg = Config::load(paths.config_file())?;
    if let Some(l) = label {
        cfg.device_label = l;
    }
    cfg.validate()?;
    cfg.save(paths.config_file())?;
    let _ = DeviceStore::open(paths.devices_file())?;
    println!("{} identity {}", style("ok").green().bold(), id.device_id());
    println!(
        "  fingerprint  {}",
        mymesh_core::NodeFingerprint::from_device_id(&id.device_id())
    );
    println!("  config       {}", paths.config_file().display());
    println!("  devices      {}", paths.devices_file().display());
    Ok(())
}

async fn cmd_status(paths: &Paths) -> Result<()> {
    let id = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    println!("{}", style("MyMesh").bold());
    println!("  label        {}", cfg.device_label);
    println!("  device id    {}", id.device_id());
    println!(
        "  fingerprint  {}",
        mymesh_core::NodeFingerprint::from_device_id(&id.device_id())
    );
    println!("  linked       {}", store.list().len());
    println!(
        "  services     terminal={} files={} desktop={}",
        cfg.daemon.enable_terminal, cfg.daemon.enable_files, cfg.daemon.enable_desktop
    );
    if let Some(u) = &cfg.rendezvous_url {
        println!("  mailbox url  {u}");
    }
    if let Some(d) = &cfg.mailbox_dir {
        println!("  mailbox dir  {}", d.display());
    }
    println!(
        "  sandbox      {}",
        cfg.effective_sandbox_root().display()
    );
    Ok(())
}

enum BoxBackend {
    Fs(FsMailbox),
    Http(HttpMailbox),
    Local(LocalRendezvous),
}

#[async_trait::async_trait]
impl Rendezvous for BoxBackend {
    async fn send(
        &self,
        code: &str,
        as_host: bool,
        msg: mymesh_protocol::PairingMessage,
    ) -> mymesh_core::Result<()> {
        match self {
            Self::Fs(m) => m.send(code, as_host, msg).await,
            Self::Http(m) => m.send(code, as_host, msg).await,
            Self::Local(m) => m.send(code, as_host, msg).await,
        }
    }

    async fn recv(
        &self,
        code: &str,
        as_host: bool,
    ) -> mymesh_core::Result<mymesh_protocol::PairingMessage> {
        match self {
            Self::Fs(m) => m.recv(code, as_host).await,
            Self::Http(m) => m.recv(code, as_host).await,
            Self::Local(m) => m.recv(code, as_host).await,
        }
    }
}

fn pick_mailbox(
    paths: &Paths,
    mailbox_dir: Option<PathBuf>,
    mailbox: Option<String>,
) -> Result<BoxBackend> {
    let cfg = Config::load(paths.config_file())?;
    if let Some(url) = mailbox.or(cfg.rendezvous_url.clone()) {
        println!("  using HTTP mailbox {}", style(&url).cyan());
        return Ok(BoxBackend::Http(HttpMailbox::new(url)));
    }
    let dir = mailbox_dir
        .or(cfg.mailbox_dir.clone())
        .unwrap_or_else(mymesh_net::default_local_mailbox_dir);
    println!("  using FS mailbox {}", style(dir.display()).cyan());
    Ok(BoxBackend::Fs(FsMailbox::new(dir)?))
}

async fn cmd_link(
    paths: &Paths,
    code: Option<String>,
    nameplate: Option<u16>,
    mailbox_dir: Option<PathBuf>,
    mailbox: Option<String>,
) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let rendezvous = pick_mailbox(paths, mailbox_dir, mailbox)?;
    let caps = Capability::all();

    if let Some(code) = code {
        println!("Linking with code {} …", style(&code).cyan().bold());
        let outcome = run_guest_pair(
            &identity,
            &cfg.device_label,
            caps,
            &mut store,
            &rendezvous,
            &code,
        )
        .await?;
        println!(
            "{} linked {} ({})",
            style("ok").green().bold(),
            outcome.peer.label,
            outcome.peer.id.short()
        );
        println!("  Run `mymesh serve` on both sides, then `mymesh shell {}`", outcome.peer.label);
    } else {
        let np = nameplate.unwrap_or_else(|| rand::random::<u16>() % 900 + 100);
        let code = mymesh_crypto::code_from_entropy(np);
        println!("{}", style("Hosting a link session…").bold());
        println!();
        println!("  ┌─────────────────────────────────────────┐");
        println!(
            "  │  pairing code   {}  │",
            style(code.as_string()).cyan().bold()
        );
        println!("  └─────────────────────────────────────────┘");
        println!();
        println!(
            "On the other device:\n  {}",
            style(format!("mymesh link {}", code.as_string())).bold()
        );
        println!("Waiting for peer (ctrl-c to cancel)…");

        let outcome = run_host_pair_code(
            &identity,
            &cfg.device_label,
            caps,
            &mut store,
            &rendezvous,
            &code,
        )
        .await?;
        println!(
            "{} linked {} ({})",
            style("ok").green().bold(),
            outcome.peer.label,
            outcome.peer.id.short()
        );
    }
    Ok(())
}

async fn cmd_devices(paths: &Paths, json: bool) -> Result<()> {
    let store = DeviceStore::open(paths.devices_file())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&store.list())?);
        return Ok(());
    }
    if store.list().is_empty() {
        println!("No linked devices. Run `mymesh link` on both sides.");
        return Ok(());
    }
    for d in store.list() {
        println!(
            "{}  {}  {:?}  caps={:?}",
            d.id.short(),
            d.label,
            d.trust,
            d.capabilities
        );
        println!("    {}", d.fingerprint);
    }
    Ok(())
}

async fn cmd_unlink(paths: &Paths, device: &str) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device(&store, device)?;
    store.revoke(&id)?;
    println!("{} revoked {}", style("ok").green().bold(), id);
    Ok(())
}

fn resolve_device(store: &DeviceStore, q: &str) -> Result<mymesh_core::DeviceId> {
    if let Ok(id) = q.parse::<mymesh_core::DeviceId>() {
        return Ok(id);
    }
    let matches: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| d.label.as_str().starts_with(q) || d.id.short().starts_with(q))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no device matched '{q}'"),
        _ => bail!("ambiguous device '{q}'"),
    }
}

async fn cmd_serve(paths: &Paths) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    println!(
        "{} serving as {} ({})",
        style("mymeshd").bold(),
        cfg.device_label,
        identity.device_id().short()
    );
    println!("  sandbox  {}", cfg.effective_sandbox_root().display());
    println!("  transport iroh (NAT traversal + relays)");

    // Keep transport alive for the entire client operation (dropping it closes connections).
    let transport = IrohTransport::bind(&identity).await?;
    println!("  endpoint {}", identity.device_id());

    let agent = Agent::new(
        &identity,
        cfg.device_label.clone(),
        paths.devices_file(),
        cfg,
    )?;
    agent.run(&transport).await?;
    Ok(())
}

async fn open_session_to(
    paths: &Paths,
    device: &str,
) -> Result<(Session, IrohTransport, mymesh_core::DeviceId)> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = resolve_device(&store, device)?;
    if !store.is_trusted(&peer) {
        bail!("device {device} is not trusted — pair with `mymesh link` first");
    }
    // Keep transport alive for the entire client operation (dropping it closes connections).
    let transport = IrohTransport::bind(&identity).await?;
    println!(
        "connecting to {} ({})…",
        store.get(&peer).map(|d| d.label.as_str()).unwrap_or("?"),
        peer.short()
    );
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

async fn cmd_shell(paths: &Paths, device: &str, shell: Option<String>) -> Result<()> {
    let (session, transport, _peer) = open_session_to(paths, device).await?;
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    session
        .send_raw(
            ChannelId::terminal(1),
            encode_msg(&TerminalMessage::Open {
                cols,
                rows,
                shell,
                env: vec![],
            })?,
        )
        .await?;

    let client = TerminalClient::attach()?;
    let conn = session.into_conn();

    // stdin thread → channel
    let (tx_in, mut rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx_in.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            frame = conn.recv_frame() => {
                let frame = frame?;
                if frame.channel.kind != mymesh_protocol::ChannelKind::Terminal {
                    continue;
                }
                let msg: TerminalMessage = decode_msg(&frame.payload)?;
                if !client.handle_host_msg(msg)? {
                    break;
                }
            }
            input = rx_in.recv() => {
                match input {
                    Some(data) => {
                        conn.send_frame(Frame {
                            channel: ChannelId::terminal(1),
                            payload: encode_msg(&TerminalMessage::Input(data))?,
                        }).await?;
                    }
                    None => break,
                }
            }
        }
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

#[derive(Debug)]
enum CpSide {
    Local(PathBuf),
    Remote { device: String, path: String },
}

fn parse_cp_side(s: &str) -> CpSide {
    // device:path — device has no slash; path may be absolute
    if let Some((dev, path)) = s.split_once(':') {
        if !dev.contains('/') && !dev.is_empty() {
            return CpSide::Remote {
                device: dev.to_string(),
                path: path.to_string(),
            };
        }
    }
    CpSide::Local(PathBuf::from(s))
}

async fn cmd_cp(paths: &Paths, src: &str, dst: &str) -> Result<()> {
    let src_s = parse_cp_side(src);
    let dst_s = parse_cp_side(dst);
    match (src_s, dst_s) {
        (CpSide::Local(local), CpSide::Remote { device, path }) => {
            push_file(paths, &local, &device, &path).await
        }
        (CpSide::Remote { device, path }, CpSide::Local(local)) => {
            pull_file(paths, &device, &path, &local).await
        }
        (CpSide::Local(_), CpSide::Local(_)) => {
            bail!("both sides local — use cp(1) instead")
        }
        (CpSide::Remote { .. }, CpSide::Remote { .. }) => {
            bail!("device-to-device copy not yet supported; pull then push")
        }
    }
}

async fn push_file(paths: &Paths, local: &Path, device: &str, remote: &str) -> Result<()> {
    let data = std::fs::read(local).with_context(|| format!("read {}", local.display()))?;
    let size = data.len() as u64;
    let (session, transport, _) = open_session_to(paths, device).await?;
    let conn = session.into_conn();

    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Put {
            path: remote.to_string(),
            size,
            mode: 0o644,
            resume_from: 0,
        })?,
    })
    .await?;

    let pb = indicatif::ProgressBar::new(size);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )?
        .progress_chars("#>-"),
    );

    const CHUNK: usize = 64 * 1024;
    let mut offset = 0u64;
    for chunk in data.chunks(CHUNK) {
        conn.send_frame(Frame {
            channel: ChannelId::files(1),
            payload: encode_msg(&FileMessage::Chunk {
                offset,
                data: chunk.to_vec(),
            })?,
        })
        .await?;
        offset += chunk.len() as u64;
        pb.set_position(offset);
    }
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Done {
            path: remote.to_string(),
            bytes: size,
        })?,
    })
    .await?;

    // Wait for host Done ack
    let frame = conn.recv_frame().await?;
    let msg: FileMessage = decode_msg(&frame.payload)?;
    pb.finish_and_clear();
    match msg {
        FileMessage::Done { bytes, .. } => {
            println!(
                "{} pushed {} → {}:{} ({bytes} bytes)",
                style("ok").green().bold(),
                local.display(),
                device,
                remote
            );
        }
        FileMessage::Error { message } => bail!("remote error: {message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

async fn pull_file(paths: &Paths, device: &str, remote: &str, local: &Path) -> Result<()> {
    let (session, transport, _) = open_session_to(paths, device).await?;
    let conn = session.into_conn();
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Get {
            path: remote.to_string(),
            offset: 0,
            length: None,
        })?,
    })
    .await?;

    if let Some(parent) = local.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(local)?;
    let mut total = 0u64;
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(indicatif::ProgressStyle::with_template(
        "{spinner:.green} {msg}",
    )?);

    loop {
        let frame = conn.recv_frame().await?;
        let msg: FileMessage = decode_msg(&frame.payload)?;
        match msg {
            FileMessage::Chunk { offset: _, data } => {
                use std::io::Write;
                file.write_all(&data)?;
                total += data.len() as u64;
                pb.set_message(format!("received {total} bytes"));
            }
            FileMessage::Done { bytes, .. } => {
                pb.finish_and_clear();
                println!(
                    "{} pulled {}:{} → {} ({bytes} bytes)",
                    style("ok").green().bold(),
                    device,
                    remote,
                    local.display()
                );
                break;
            }
            FileMessage::Error { message } => bail!("remote error: {message}"),
            other => bail!("unexpected: {other:?}"),
        }
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

// --- demos (in-process, no iroh) ---

async fn demo_pair() -> Result<()> {
    use mymesh_session::run_guest_pair;

    let dir = tempfile_dir()?;
    let host_paths = sub_paths(&dir, "host")?;
    let guest_paths = sub_paths(&dir, "guest")?;

    let host_id = Identity::load_or_create(host_paths.identity_file())?;
    let guest_id = Identity::load_or_create(guest_paths.identity_file())?;
    let mut host_store = DeviceStore::open(host_paths.devices_file())?;
    let mut guest_store = DeviceStore::open(guest_paths.devices_file())?;
    let rendezvous = LocalRendezvous::new();
    let caps = Capability::all();
    let code = "42-maple-orbit";

    let host_fut = run_host_pair_with_code(
        &host_id,
        "host-demo",
        caps.clone(),
        &mut host_store,
        &rendezvous,
        code,
    );
    let guest_fut = run_guest_pair(
        &guest_id,
        "guest-demo",
        caps,
        &mut guest_store,
        &rendezvous,
        code,
    );

    let (h, g) = tokio::join!(host_fut, guest_fut);
    let h = h?;
    let g = g?;
    assert_eq!(h.shared_confirm, g.shared_confirm);
    println!("{} SPAKE2 pairing succeeded", style("ok").green().bold());
    println!(
        "  host  linked guest {} ({})",
        h.peer.label,
        h.peer.id.short()
    );
    println!(
        "  guest linked host  {} ({})",
        g.peer.label,
        g.peer.id.short()
    );
    println!("  confirm {}", hex::encode(h.shared_confirm));
    Ok(())
}

async fn run_host_pair_with_code(
    identity: &Identity,
    label: &str,
    capabilities: Vec<Capability>,
    store: &mut DeviceStore,
    rendezvous: &impl Rendezvous,
    code: &str,
) -> mymesh_core::Result<mymesh_session::PairOutcome> {
    use chrono::Utc;
    use mymesh_core::{DeviceLabel, DeviceRecord, NodeFingerprint, TrustState};
    use mymesh_crypto::{parse_code, PairingRole, PairingSession};
    use mymesh_protocol::PairingMessage;
    use sha2::{Digest, Sha256};

    let code = parse_code(code)?;
    let code_str = code.as_string();
    let spake = PairingSession::start(PairingRole::Host, &code.password_bytes())?;
    let my_spake = spake.outbound_message().to_vec();
    rendezvous
        .send(&code_str, true, PairingMessage::Spake(my_spake))
        .await?;
    let peer_spake = match rendezvous.recv(&code_str, true).await? {
        PairingMessage::Spake(m) => m,
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "expected SPAKE, got {other:?}"
            )))
        }
    };
    let secret = spake.finish(&peer_spake)?;

    let vk = identity.verifying_key_bytes();
    let device_id = identity.device_id();
    let sign_material = [device_id.as_bytes().as_slice(), label.as_bytes(), &vk].concat();
    let signature = identity.sign(&sign_material);
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update(&sign_material);
    let offer_binder: [u8; 32] = h.finalize().into();

    rendezvous
        .send(
            &code_str,
            true,
            PairingMessage::IdentityOffer {
                device_id,
                label: label.to_string(),
                verifying_key: vk,
                capabilities: capabilities.clone(),
                signature,
                binder: offer_binder,
            },
        )
        .await?;

    let peer = match rendezvous.recv(&code_str, true).await? {
        PairingMessage::IdentityAccept {
            device_id: peer_id,
            label: peer_label,
            verifying_key,
            accepted_capabilities,
            signature,
            binder: peer_binder,
        } => {
            let material = [
                peer_id.as_bytes().as_slice(),
                peer_label.as_bytes(),
                &verifying_key,
            ]
            .concat();
            let mut h = Sha256::new();
            h.update(secret.as_bytes());
            h.update(&material);
            let expect: [u8; 32] = h.finalize().into();
            if expect != peer_binder {
                return Err(mymesh_core::Error::Pairing("binder mismatch".into()));
            }
            let pub_id = mymesh_crypto::IdentityPublic { verifying_key };
            pub_id.verify(&material, &signature)?;
            DeviceRecord {
                id: peer_id,
                label: DeviceLabel::new(peer_label),
                fingerprint: NodeFingerprint::from_device_id(&peer_id).as_str().to_string(),
                capabilities: accepted_capabilities,
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: Some(Utc::now()),
                endpoint_hint: None,
            }
        }
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "unexpected: {other:?}"
            )))
        }
    };
    store.upsert(peer.clone())?;
    Ok(mymesh_session::PairOutcome {
        code: Some(code),
        peer,
        shared_confirm: secret.derive(b"mymesh/confirm"),
    })
}

async fn demo_session() -> Result<()> {
    use mymesh_protocol::{encode_msg, ChannelId, TerminalMessage};

    demo_pair().await?;

    let fabric = LocalFabric::new();
    let host_id = Identity::generate();
    let guest_id = Identity::generate();
    let dir = tempfile_dir()?;
    let host_paths = sub_paths(&dir, "host2")?;
    let guest_paths = sub_paths(&dir, "guest2")?;
    let mut host_store = DeviceStore::open(host_paths.devices_file())?;
    let mut guest_store = DeviceStore::open(guest_paths.devices_file())?;

    let now = chrono::Utc::now();
    host_store.upsert(mymesh_core::DeviceRecord {
        id: guest_id.device_id(),
        label: mymesh_core::DeviceLabel::new("guest"),
        fingerprint: mymesh_core::NodeFingerprint::from_device_id(&guest_id.device_id())
            .as_str()
            .into(),
        capabilities: Capability::all(),
        trust: mymesh_core::TrustState::Trusted,
        linked_at: now,
        last_seen: Some(now),
        endpoint_hint: None,
    })?;
    guest_store.upsert(mymesh_core::DeviceRecord {
        id: host_id.device_id(),
        label: mymesh_core::DeviceLabel::new("host"),
        fingerprint: mymesh_core::NodeFingerprint::from_device_id(&host_id.device_id())
            .as_str()
            .into(),
        capabilities: Capability::all(),
        trust: mymesh_core::TrustState::Trusted,
        linked_at: now,
        last_seen: Some(now),
        endpoint_hint: None,
    })?;

    let host_ep = fabric.endpoint(host_id.device_id());
    let guest_ep = fabric.endpoint(guest_id.device_id());

    let accept = tokio::spawn(async move { host_ep.accept().await });
    let guest_conn = guest_ep.connect(host_id.device_id()).await?;
    let host_conn = accept.await??;

    // Asymmetric handshake on fabric: guest dials, host accepts
    let host_hs = Session::handshake_acceptor(
        host_conn,
        &host_id,
        "host",
        &host_store,
        Capability::all(),
    );
    let guest_hs = Session::handshake_dialer(
        guest_conn,
        &guest_id,
        "guest",
        &guest_store,
        Capability::all(),
    );
    let (host_sess, guest_sess) = tokio::join!(host_hs, guest_hs);
    let host_sess = host_sess?;
    let guest_sess = guest_sess?;

    guest_sess
        .send_raw(
            ChannelId::terminal(1),
            encode_msg(&TerminalMessage::Open {
                cols: 80,
                rows: 24,
                shell: None,
                env: vec![],
            })?,
        )
        .await?;
    let frame = host_sess.recv().await?;
    println!(
        "{} session handshake + terminal open frame ({} bytes payload)",
        style("ok").green().bold(),
        frame.payload.len()
    );
    let _ = guest_sess;
    Ok(())
}

fn tempfile_dir() -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!("mymesh-demo-{}", std::process::id()));
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

fn sub_paths(root: &std::path::Path, name: &str) -> Result<Paths> {
    let p = Paths {
        config_dir: root.join(name).join("config"),
        data_dir: root.join(name).join("data"),
        cache_dir: root.join(name).join("cache"),
    };
    p.ensure()?;
    Ok(p)
}

fn print_install_notes() {
    println!(
        r#"# MyMesh install (Linux)

## From source
curl -fsSL https://raw.githubusercontent.com/jtwolfe/MyMesh/main/install.sh | bash

## Pair two machines
# optional: shared HTTP mailbox
mymesh mailbox --bind 0.0.0.0:9876
export MYMESH_MAILBOX=http://YOUR_HOST:9876

# machine A
mymesh init --label desktop
mymesh link
# machine B
mymesh init --label laptop
mymesh link <code-from-A>

# both machines
mymesh serve --foreground

# laptop → desktop
mymesh shell desktop
mymesh cp ./file desktop:~/file

## systemd user service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/mymesh.service <<'UNIT'
[Unit]
Description=MyMesh peer agent
After=network-online.target

[Service]
ExecStart=%h/.local/bin/mymesh serve --foreground
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now mymesh.service
"#
    );
}
