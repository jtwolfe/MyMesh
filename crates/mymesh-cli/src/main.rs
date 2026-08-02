//! MyMesh CLI + TUI entrypoint.
mod install;
mod probe;
mod tui_app;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use console::style;
use mymesh_core::{
    ArmState, Capability, Config, DeviceStore, JoinDecision, JoinStore, Paths,
};
use mymesh_crypto::{
    device_id_to_words, device_join_uri, parse_device_id, Identity,
};
use mymesh_net::{
    run_mailbox_server, FsMailbox, HttpMailbox, IrohTransport, LocalFabric, LocalRendezvous,
    Rendezvous, Transport,
};
use mymesh_protocol::{
    decode_msg, encode_msg, ChannelId, FileMessage, Frame, TerminalMessage,
};
use mymesh_session::{
    run_guest_pair, run_host_pair_code, run_join_as_guest, Agent, Session,
};
use mymesh_terminal::TerminalClient;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "mymesh",
    version,
    about = "Peer-to-peer remote access — pair like Signal, connect like Syncthing"
)]
pub struct Cli {
    #[arg(long, global = true, env = "MYMESH_HOME")]
    home: Option<PathBuf>,

    /// Force CLI help path even with no subcommand (default: open TUI)
    #[arg(long, global = true)]
    no_tui: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Open the TUI dashboard (default when no command is given)
    Tui,
    Status,
    Id {
        #[arg(long)]
        qr: bool,
        #[arg(long)]
        words: bool,
        #[arg(long)]
        uri: bool,
    },
    Init {
        #[arg(long)]
        label: Option<String>,
    },
    Link {
        target: Option<String>,
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        nameplate: Option<u16>,
        #[arg(long, env = "MYMESH_MAILBOX_DIR")]
        mailbox_dir: Option<PathBuf>,
        #[arg(long, env = "MYMESH_MAILBOX")]
        mailbox: Option<String>,
        #[arg(long)]
        local: bool,
    },
    ConnectRequest {
        #[command(subcommand)]
        action: ConnectRequestCmd,
    },
    Requests {
        #[command(subcommand)]
        action: RequestsCmd,
    },
    Devices {
        #[arg(long)]
        json: bool,
    },
    Unlink { device: String },
    Shell {
        device: String,
        #[arg(long)]
        shell: Option<String>,
    },
    Cp { src: String, dst: String },
    /// Ping a peer and record RTT history
    Ping { device: String },
    /// Bandwidth test (push) to a peer
    Bw {
        device: String,
        #[arg(long, default_value_t = 1_048_576)]
        bytes: u64,
    },
    /// Probe all trusted peers once
    ProbeAll,
    Desktop {
        device: String,
        #[arg(long, default_value_t = 30)]
        fps: u8,
    },
    Serve {
        #[arg(long)]
        foreground: bool,
    },
    Mailbox {
        #[arg(long, default_value = "0.0.0.0:9876")]
        bind: String,
    },
    /// Install agent + systemd unit + completions
    Install {
        /// System-wide unit (requires root). Prefer user install.
        #[arg(long)]
        system: bool,
        /// Allow agent to run as root (dangerous)
        #[arg(long)]
        i_accept_root_agent: bool,
        /// Runtime OS user for system install (default: mymesh)
        #[arg(long)]
        runtime_user: Option<String>,
    },
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
    Reset {
        #[arg(long)]
        links: bool,
        #[arg(long)]
        identity: bool,
    },
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    Completions {
        shell: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Demo {
        #[command(subcommand)]
        scenario: DemoCmd,
    },
    InstallNotes,
}

#[derive(Subcommand, Debug)]
enum ConnectRequestCmd {
    Allow {
        #[arg(long)]
        secs: Option<u64>,
    },
    Deny,
    Status,
}

#[derive(Subcommand, Debug)]
enum RequestsCmd {
    List,
    Accept { device: String },
    Deny {
        device: String,
        #[arg(long, default_value = "denied by operator")]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceCmd {
    Status {
        #[arg(long)]
        system: bool,
    },
    Start {
        #[arg(long)]
        system: bool,
    },
    Stop {
        #[arg(long)]
        system: bool,
    },
    Restart {
        #[arg(long)]
        system: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DemoCmd {
    Pair,
    Session,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = resolve_paths(cli.home.as_ref())?;

    // Default: TUI when no subcommand
    let command = match cli.command {
        None if !cli.no_tui && std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            Some(Commands::Tui)
        }
        None => {
            Cli::command().print_help()?;
            println!();
            return Ok(());
        }
        other => other,
    };

    // Reduce log noise in TUI
    let is_tui = matches!(command, Some(Commands::Tui));
    if !is_tui {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("mymesh=info".parse()?))
            .with_target(false)
            .init();
    }

    match command.expect("command") {
        Commands::Tui => tui_app::run_tui(paths).await?,
        Commands::Init { label } => cmd_init(&paths, label).await?,
        Commands::Status => cmd_status(&paths).await?,
        Commands::Id { qr, words, uri } => cmd_id(&paths, qr, words, uri).await?,
        Commands::Link {
            target,
            code,
            nameplate,
            mailbox_dir,
            mailbox,
            local,
        } => {
            if code.is_some() || mailbox_dir.is_some() || mailbox.is_some() || local || nameplate.is_some()
            {
                if let Some(c) = code {
                    cmd_link_spake_guest(&paths, &c, mailbox_dir, mailbox, local).await?;
                } else if target.is_none() {
                    cmd_link_spake_host(&paths, nameplate, mailbox_dir, mailbox, local).await?;
                } else {
                    bail!("use `mymesh link <device-id>` or SPAKE flags without a target id");
                }
            } else if let Some(t) = target {
                cmd_link_join(&paths, &t).await?;
            } else {
                cmd_link_help(&paths).await?;
            }
        }
        Commands::ConnectRequest { action } => match action {
            ConnectRequestCmd::Allow { secs } => cmd_arm(&paths, secs).await?,
            ConnectRequestCmd::Deny => {
                ArmState::disarm(paths.arm_file())?;
                println!("{} disarmed", style("ok").green().bold());
            }
            ConnectRequestCmd::Status => cmd_arm_status(&paths).await?,
        },
        Commands::Requests { action } => match action {
            RequestsCmd::List => cmd_requests_list(&paths).await?,
            RequestsCmd::Accept { device } => {
                cmd_requests_decide(&paths, &device, true, "").await?
            }
            RequestsCmd::Deny { device, reason } => {
                cmd_requests_decide(&paths, &device, false, &reason).await?
            }
        },
        Commands::Devices { json } => cmd_devices(&paths, json).await?,
        Commands::Unlink { device } => cmd_unlink(&paths, &device).await?,
        Commands::Shell { device, shell } => cmd_shell(&paths, &device, shell).await?,
        Commands::Cp { src, dst } => cmd_cp(&paths, &src, &dst).await?,
        Commands::Ping { device } => {
            let ms = probe::probe_ping(&paths, &device).await?;
            println!("{} {} ms", style("pong").green().bold(), ms);
        }
        Commands::Bw { device, bytes } => {
            let r = probe::probe_bandwidth(&paths, &device, bytes).await?;
            println!(
                "{} {:.2} Mbps ({} bytes in {} ms)",
                style("ok").green().bold(),
                r.mbps,
                r.bytes,
                r.elapsed_ms
            );
        }
        Commands::ProbeAll => {
            for (label, r) in probe::probe_all(&paths).await? {
                match r {
                    Ok(ms) => println!("{label}: {ms} ms"),
                    Err(e) => println!("{label}: ERR {e}"),
                }
            }
        }
        Commands::Desktop { .. } => {
            println!("{}", style("desktop: deferred").yellow());
        }
        Commands::Serve { .. } => cmd_serve(&paths).await?,
        Commands::Mailbox { bind } => {
            let addr: SocketAddr = bind.parse().context("invalid --bind")?;
            run_mailbox_server(addr).await?;
        }
        Commands::Install {
            system,
            i_accept_root_agent,
            runtime_user,
        } => install::cmd_install(&paths, system, i_accept_root_agent, runtime_user)?,
        Commands::Uninstall { purge } => install::cmd_uninstall(&paths, purge)?,
        Commands::Reset { links, identity } => install::cmd_reset(&paths, links, identity)?,
        Commands::Service { action } => match action {
            ServiceCmd::Status { system } => install::cmd_service("status", system)?,
            ServiceCmd::Start { system } => install::cmd_service("start", system)?,
            ServiceCmd::Stop { system } => install::cmd_service("stop", system)?,
            ServiceCmd::Restart { system } => install::cmd_service("restart", system)?,
        },
        Commands::Completions { shell, out } => install::cmd_completions(&shell, out)?,
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
    let words = device_id_to_words(&id.device_id())?;
    println!("{} identity {}", style("ok").green().bold(), id.device_id());
    println!(
        "  fingerprint  {}",
        mymesh_core::NodeFingerprint::from_device_id(&id.device_id())
    );
    println!("  words        {words}");
    println!("  config       {}", paths.config_file().display());
    Ok(())
}

async fn cmd_id(paths: &Paths, qr: bool, words_only: bool, uri: bool) -> Result<()> {
    let id = Identity::load_or_create(paths.identity_file())?;
    let did = id.device_id();
    let words = device_id_to_words(&did)?;
    if uri {
        println!("{}", device_join_uri(&did)?);
        return Ok(());
    }
    if words_only {
        println!("{words}");
        return Ok(());
    }
    println!("{}", style("MyMesh device id").bold());
    println!("  hex     {did}");
    println!(
        "  short   {}  fingerprint {}",
        did.short(),
        mymesh_core::NodeFingerprint::from_device_id(&did)
    );
    println!("  words   {words}");
    println!("  uri     {}", device_join_uri(&did)?);
    if qr {
        if let Ok(code) = qrcode::QrCode::new(device_join_uri(&did)?.as_bytes()) {
            let qr = code.render::<char>().quiet_zone(false).module_dimensions(1, 1).build();
            println!("\n{qr}");
        }
    }
    Ok(())
}

async fn cmd_status(paths: &Paths) -> Result<()> {
    let id = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let arm = ArmState::load(paths.arm_file())?;
    let words = device_id_to_words(&id.device_id())?;
    println!("{}", style("MyMesh").bold());
    println!("  version      {}", env!("CARGO_PKG_VERSION"));
    println!("  label        {}", cfg.device_label);
    println!("  device id    {}", id.device_id());
    println!("  short        {}", id.device_id().short());
    println!(
        "  fingerprint  {}",
        mymesh_core::NodeFingerprint::from_device_id(&id.device_id())
    );
    println!(
        "  words        {}…",
        words
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("  linked       {}", store.list().len());
    if arm.is_effectively_armed() {
        println!(
            "  join arm     {} until {:?}",
            style("ARMED").green().bold(),
            arm.until
        );
    } else {
        println!("  join arm     {}", style("disarmed").dim());
    }
    println!(
        "  service      {}",
        if install::service_is_active(false) {
            "user unit active"
        } else {
            "user unit inactive"
        }
    );
    Ok(())
}

async fn cmd_link_help(paths: &Paths) -> Result<()> {
    let id = Identity::load_or_create(paths.identity_file())?;
    let words = device_id_to_words(&id.device_id())?;
    println!("{}", style("Link a device").bold());
    println!("Host:  mymesh serve  &&  mymesh connect-request allow");
    println!("Join:  mymesh link <host-hex-or-24-words>");
    println!("Host:  mymesh requests accept <id>");
    println!();
    println!("Your hex:   {}", id.device_id());
    println!("Your words: {words}");
    Ok(())
}

async fn cmd_arm(paths: &Paths, secs: Option<u64>) -> Result<()> {
    let cfg = Config::load(paths.config_file())?;
    let ttl = secs.unwrap_or(cfg.limits.arm_timeout_secs);
    let state = ArmState::arm(paths.arm_file(), ttl)?;
    let id = Identity::load_or_create(paths.identity_file())?;
    let words = device_id_to_words(&id.device_id())?;
    println!(
        "{} until {:?}",
        style("ARMED").green().bold(),
        state.until
    );
    println!("  hex   {}", id.device_id());
    println!("  words {words}");
    Ok(())
}

async fn cmd_arm_status(paths: &Paths) -> Result<()> {
    let arm = ArmState::load(paths.arm_file())?;
    if arm.is_effectively_armed() {
        println!("armed until {:?}", arm.until);
    } else {
        println!("disarmed");
    }
    Ok(())
}

async fn cmd_requests_list(paths: &Paths) -> Result<()> {
    let joins = JoinStore::open(paths.join_dir())?;
    let list = joins.list_pending()?;
    if list.is_empty() {
        println!("No pending join requests.");
        return Ok(());
    }
    for p in list {
        println!(
            "{}  {}  fp={}",
            p.device_id.short(),
            p.label,
            p.fingerprint
        );
        println!("    {}", p.device_id);
    }
    Ok(())
}

async fn cmd_requests_decide(
    paths: &Paths,
    device: &str,
    accept: bool,
    reason: &str,
) -> Result<()> {
    let joins = JoinStore::open(paths.join_dir())?;
    let pending = joins.list_pending()?;
    let id = resolve_pending(&pending, device)?;
    if accept {
        joins.write_decision(&id, JoinDecision::Accept)?;
        println!("{} accept {}", style("ok").green().bold(), id.short());
    } else {
        joins.write_decision(
            &id,
            JoinDecision::Deny {
                reason: reason.to_string(),
            },
        )?;
        println!("{} deny {}", style("ok").green().bold(), id.short());
    }
    Ok(())
}

fn resolve_pending(
    pending: &[mymesh_core::PendingJoin],
    q: &str,
) -> Result<mymesh_core::DeviceId> {
    if let Ok(id) = parse_device_id(q) {
        return Ok(id);
    }
    let matches: Vec<_> = pending
        .iter()
        .filter(|p| {
            p.label.starts_with(q)
                || p.device_id.short().starts_with(q)
                || p.device_id.to_string().starts_with(q)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.device_id),
        [] => bail!("no pending request matched '{q}'"),
        _ => bail!("ambiguous pending device '{q}'"),
    }
}

async fn cmd_link_join(paths: &Paths, target: &str) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let host_id = parse_device_id(target)?;
    println!("requesting link to {}…", style(host_id.short()).cyan());
    let transport = IrohTransport::bind(&identity).await?;
    let conn = transport.connect(host_id).await?;
    let peer = run_join_as_guest(
        conn,
        &identity,
        &cfg.device_label,
        &mut store,
        Capability::all(),
    )
    .await?;
    println!(
        "{} linked to {} ({})",
        style("ok").green().bold(),
        peer.label,
        peer.id.short()
    );
    transport.shutdown().await;
    Ok(())
}

enum BoxBackend {
    Fs(FsMailbox),
    Http(HttpMailbox),
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
        }
    }
}

fn pick_mailbox(
    paths: &Paths,
    mailbox_dir: Option<PathBuf>,
    mailbox: Option<String>,
    local: bool,
) -> Result<BoxBackend> {
    let cfg = Config::load(paths.config_file())?;
    if let Some(url) = mailbox.or(cfg.rendezvous_url.clone()) {
        return Ok(BoxBackend::Http(HttpMailbox::new(url)));
    }
    let dir = if local {
        mymesh_net::default_local_mailbox_dir()
    } else {
        mailbox_dir
            .or(cfg.mailbox_dir.clone())
            .unwrap_or_else(mymesh_net::default_local_mailbox_dir)
    };
    Ok(BoxBackend::Fs(FsMailbox::new(dir)?))
}

async fn cmd_link_spake_host(
    paths: &Paths,
    nameplate: Option<u16>,
    mailbox_dir: Option<PathBuf>,
    mailbox: Option<String>,
    local: bool,
) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let rendezvous = pick_mailbox(paths, mailbox_dir, mailbox, local)?;
    let np = nameplate.unwrap_or_else(|| rand::random::<u16>() % 900 + 100);
    let code = mymesh_crypto::code_from_entropy(np);
    println!("SPAKE code {}", style(code.as_string()).cyan().bold());
    let outcome = run_host_pair_code(
        &identity,
        &cfg.device_label,
        Capability::all(),
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
    Ok(())
}

async fn cmd_link_spake_guest(
    paths: &Paths,
    code: &str,
    mailbox_dir: Option<PathBuf>,
    mailbox: Option<String>,
    local: bool,
) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let rendezvous = pick_mailbox(paths, mailbox_dir, mailbox, local)?;
    let outcome = run_guest_pair(
        &identity,
        &cfg.device_label,
        Capability::all(),
        &mut store,
        &rendezvous,
        code,
    )
    .await?;
    println!(
        "{} linked {} ({})",
        style("ok").green().bold(),
        outcome.peer.label,
        outcome.peer.id.short()
    );
    Ok(())
}

async fn cmd_devices(paths: &Paths, json: bool) -> Result<()> {
    let store = DeviceStore::open(paths.devices_file())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&store.list())?);
        return Ok(());
    }
    if store.list().is_empty() {
        println!("No linked devices.");
        return Ok(());
    }
    for d in store.list() {
        let m = mymesh_core::PeerMetrics::load(paths.metrics_dir(), &d.id).ok();
        let rtt = m
            .as_ref()
            .and_then(|x| x.latest_rtt())
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "—".into());
        println!(
            "{}  {}  {:?}  rtt={rtt}",
            d.id.short(),
            d.label,
            d.trust
        );
        println!("    {}", d.id);
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

pub(crate) fn resolve_device(store: &DeviceStore, q: &str) -> Result<mymesh_core::DeviceId> {
    if let Ok(id) = parse_device_id(q) {
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
    let transport = IrohTransport::bind(&identity).await?;
    let agent = Agent::new(
        &identity,
        cfg.device_label.clone(),
        paths.devices_file(),
        paths.arm_file(),
        paths.join_dir(),
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

async fn cmd_shell(paths: &Paths, device: &str, shell: Option<String>) -> Result<()> {
    let (session, transport, _) = open_session_to(paths, device).await?;
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
                if !client.handle_host_msg(msg)? { break; }
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

enum CpSide {
    Local(PathBuf),
    Remote { device: String, path: String },
}

fn parse_cp_side(s: &str) -> CpSide {
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
    match (parse_cp_side(src), parse_cp_side(dst)) {
        (CpSide::Local(local), CpSide::Remote { device, path }) => {
            push_file(paths, &local, &device, &path).await
        }
        (CpSide::Remote { device, path }, CpSide::Local(local)) => {
            pull_file(paths, &device, &path, &local).await
        }
        _ => bail!("use device:path on exactly one side"),
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
    }
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Done {
            path: remote.to_string(),
            bytes: size,
        })?,
    })
    .await?;
    let frame = conn.recv_frame().await?;
    let msg: FileMessage = decode_msg(&frame.payload)?;
    match msg {
        FileMessage::Done { bytes, .. } => {
            println!(
                "{} pushed {} → {device}:{remote} ({bytes} bytes)",
                style("ok").green().bold(),
                local.display()
            );
        }
        FileMessage::Error { message } => bail!("{message}"),
        other => bail!("unexpected {other:?}"),
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
    loop {
        let frame = conn.recv_frame().await?;
        let msg: FileMessage = decode_msg(&frame.payload)?;
        match msg {
            FileMessage::Chunk { data, .. } => {
                use std::io::Write;
                file.write_all(&data)?;
            }
            FileMessage::Done { bytes, .. } => {
                println!(
                    "{} pulled {device}:{remote} → {} ({bytes} bytes)",
                    style("ok").green().bold(),
                    local.display()
                );
                break;
            }
            FileMessage::Error { message } => bail!("{message}"),
            other => bail!("unexpected {other:?}"),
        }
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

async fn demo_pair() -> Result<()> {
    let dir = tempfile_dir()?;
    let host_paths = sub_paths(&dir, "host")?;
    let guest_paths = sub_paths(&dir, "guest")?;
    let host_id = Identity::load_or_create(host_paths.identity_file())?;
    let guest_id = Identity::load_or_create(guest_paths.identity_file())?;
    let mut host_store = DeviceStore::open(host_paths.devices_file())?;
    let mut guest_store = DeviceStore::open(guest_paths.devices_file())?;
    let rendezvous = LocalRendezvous::new();
    let caps = Capability::all();
    let code_str = "42-maple-orbit";
    let code = mymesh_crypto::parse_code(code_str)?;
    let host_fut = run_host_pair_code(
        &host_id,
        "host-demo",
        caps.clone(),
        &mut host_store,
        &rendezvous,
        &code,
    );
    let guest_fut = run_guest_pair(
        &guest_id,
        "guest-demo",
        caps,
        &mut guest_store,
        &rendezvous,
        code_str,
    );
    let (h, g) = tokio::join!(host_fut, guest_fut);
    let h = h?;
    let g = g?;
    println!("{} SPAKE2 pairing succeeded", style("ok").green().bold());
    println!("  host  linked {} ({})", h.peer.label, h.peer.id.short());
    println!("  guest linked {} ({})", g.peer.label, g.peer.id.short());
    Ok(())
}

async fn demo_session() -> Result<()> {
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
    let (h, g) = tokio::join!(host_hs, guest_hs);
    let _ = (h?, g?);
    println!("{} session handshake ok", style("ok").green().bold());
    Ok(())
}

fn tempfile_dir() -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!("mymesh-demo-{}", std::process::id()));
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

fn sub_paths(root: &Path, name: &str) -> Result<Paths> {
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
        r#"MyMesh alpha.2 install

  mymesh install                 # user systemd unit (default)
  mymesh uninstall [--purge]
  mymesh reset --links|--identity
  mymesh service status|start|stop|restart
  mymesh completions bash
  mymesh                         # TUI
  mymesh install --system        # root + warning; --i-accept-root-agent if needed
"#
    );
}
