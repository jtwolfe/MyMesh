//! MyMesh CLI + TUI entrypoint.
mod firewall;
mod install;
mod magic_cmd;
mod mesh_conn;
mod pair_cmd;
mod probe;
mod term_pane;
mod tui_app;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use console::style;
use mymesh_core::{
    ArmState, Capability, Config, DeviceStore, JoinDecision, JoinStore, MeshState, Paths,
};
use mymesh_crypto::{device_id_to_words, device_join_uri, parse_device_id, Identity};
use mymesh_net::{
    run_mailbox_server, FsMailbox, HttpMailbox, IrohTransport, LocalFabric, LocalRendezvous,
    Rendezvous, Transport,
};
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, FileMessage, Frame, TerminalMessage};
use mymesh_session::{
    apply_kick_target, apply_membership, build_announce, run_guest_pair, run_host_pair_code,
    run_join_as_guest, sign_kick, Agent, Session,
};
use mymesh_terminal::TerminalClient;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "mymesh",
    version,
    about = "Peer-to-peer remote access — pair like Signal, connect like Syncthing",
    propagate_version = true,
    arg_required_else_help = false,
    after_help = "Tips:
  mymesh install · mymesh serve · mymesh hosts · mymesh firewall help
  mymesh completions bash|zsh|fish   # regenerate shell autocomplete"
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
    /// Open the interactive TUI (default when run with no subcommand)
    Tui,
    /// Show local identity, arm state, and user-service status
    Status,
    /// Print this device id (hex / words / QR / join URI)
    Id {
        /// Print QR code of the join URI
        #[arg(long)]
        qr: bool,
        /// Print BIP39-style 24-word id
        #[arg(long)]
        words: bool,
        /// Print mymesh:// join URI
        #[arg(long)]
        uri: bool,
    },
    /// Create local identity + config (first-run)
    Init {
        /// Human-readable device label (default: hostname)
        #[arg(long)]
        label: Option<String>,
    },
    /// Link devices (join by id/words, or SPAKE2 local mailbox)
    Link {
        /// Peer hex id or 24-word id (Syncthing-style join)
        #[arg(value_name = "DEVICE")]
        target: Option<String>,
        /// SPAKE2 guest: pairing code from host
        #[arg(long)]
        code: Option<String>,
        /// SPAKE2 host: fixed nameplate id
        #[arg(long)]
        nameplate: Option<u16>,
        /// Shared directory mailbox (SPAKE2)
        #[arg(long, env = "MYMESH_MAILBOX_DIR")]
        mailbox_dir: Option<PathBuf>,
        /// HTTP mailbox base URL (SPAKE2)
        #[arg(long, env = "MYMESH_MAILBOX")]
        mailbox: Option<String>,
        /// Use in-process local rendezvous (same machine only)
        #[arg(long)]
        local: bool,
    },
    /// Arm / disarm accepting new connection requests
    #[command(visible_alias = "arm")]
    ConnectRequest {
        #[command(subcommand)]
        action: ConnectRequestCmd,
    },
    /// List / accept / deny pending join requests
    Requests {
        #[command(subcommand)]
        action: RequestsCmd,
    },
    /// List linked devices
    Devices {
        /// Machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Revoke trust for a linked device
    Unlink {
        #[arg(value_name = "DEVICE")]
        device: String,
    },
    /// Open an interactive remote shell on a peer
    Shell {
        #[arg(value_name = "DEVICE")]
        device: String,
        /// Remote shell binary (default: peer $SHELL)
        #[arg(long)]
        shell: Option<String>,
    },
    /// Copy files (local path or device:path)
    Cp {
        #[arg(value_name = "SRC")]
        src: String,
        #[arg(value_name = "DST")]
        dst: String,
    },
    /// Ping a peer and record RTT history
    Ping {
        #[arg(value_name = "DEVICE")]
        device: String,
    },
    /// Bandwidth test (push) to a peer
    #[command(visible_alias = "bandwidth")]
    Bw {
        #[arg(value_name = "DEVICE")]
        device: String,
        /// Payload size in bytes
        #[arg(long, default_value_t = 1_048_576)]
        bytes: u64,
    },
    /// Probe all trusted peers once (RTT)
    ProbeAll,
    /// Remote desktop (deferred / stub)
    Desktop {
        #[arg(value_name = "DEVICE")]
        device: String,
        #[arg(long, default_value_t = 30)]
        fps: u8,
    },
    /// Run the mesh agent (sessions + magic plane)
    Serve {
        /// Keep in foreground (default for CLI)
        #[arg(long)]
        foreground: bool,
    },
    /// Run a standalone HTTP SPAKE2 mailbox
    Mailbox {
        #[arg(long, default_value = "0.0.0.0:9876")]
        bind: String,
    },
    /// Install agent binary, systemd unit, and shell completions
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
    /// Remove installed unit/binary (optional purge of state)
    Uninstall {
        /// Also delete identity, devices, and config
        #[arg(long)]
        purge: bool,
    },
    /// Reset local state (links and/or identity)
    Reset {
        /// Drop linked devices / mesh roster
        #[arg(long)]
        links: bool,
        /// Delete local identity key (re-init required)
        #[arg(long)]
        identity: bool,
    },
    /// Control the systemd mymesh service
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Generate shell completion scripts (bash|zsh|fish)
    Completions {
        /// Target shell
        shell: CompletionShell,
        /// Write to file instead of stdout
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Built-in demos (pair / session)
    Demo {
        #[command(subcommand)]
        scenario: DemoCmd,
    },
    /// Show mesh id + roster / force gossip sync
    Mesh {
        #[command(subcommand)]
        action: MeshCmd,
    },
    /// Kick a device from the mesh (double confirmation required)
    Kick {
        #[arg(value_name = "DEVICE")]
        device: String,
        /// Force: remove immediately mesh-wide; still queues notice if offline
        #[arg(long)]
        force: bool,
        /// Skip interactive prompts (must pass both confirm flags)
        #[arg(long)]
        yes_kick_from_mesh: bool,
        #[arg(long)]
        yes_i_am_sure: bool,
    },
    /// Print install policy / notes
    InstallNotes,
    /// List mesh hostnames, mesh IPs, aliases, groups
    #[command(visible_alias = "host")]
    Hosts {
        /// Filter by group tag
        #[arg(long)]
        group: Option<String>,
    },
    /// Rename a device label
    Label {
        #[arg(value_name = "DEVICE")]
        device: String,
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Add or remove a DNS/ssh alias for a device
    Alias {
        #[arg(value_name = "DEVICE")]
        device: String,
        #[arg(value_name = "ALIAS")]
        name: String,
        /// Remove the alias instead of adding
        #[arg(long)]
        remove: bool,
    },
    /// Add or remove a group tag on a device
    Group {
        #[arg(value_name = "DEVICE")]
        device: String,
        #[arg(value_name = "GROUP")]
        name: String,
        /// Remove the group instead of adding
        #[arg(long)]
        remove: bool,
    },
    /// Resolve a name / alias / id to device + mesh-ip
    Resolve {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Print OpenSSH config for Host *.mym (ProxyCommand)
    #[command(visible_alias = "ssh-conf")]
    SshConfig {
        /// Override magic domain (default: mym)
        #[arg(long)]
        domain: Option<String>,
    },
    /// OpenSSH ProxyCommand helper (stdio → peer:22)
    ProxySsh {
        #[arg(value_name = "HOST")]
        host: String,
    },
    /// Listen locally and tunnel TCP to peer:port
    Expose {
        #[arg(value_name = "DEVICE")]
        device: String,
        /// Remote port on the peer
        port: u16,
        /// Local listen port (default: same as remote)
        #[arg(long)]
        local: Option<u16>,
    },
    /// Connect-by-carrier (phone QR page; phone is not a mesh node)
    Carrier {
        /// HTTP listen port (default 17878)
        #[arg(long, default_value_t = 17878)]
        port: u16,
    },
    /// Pair v2 dual-scan + confirm-on-machine (no carrier process required)
    Pair {
        #[command(subcommand)]
        action: PairCmd,
    },
    /// Print magic-plane help (DNS / SOCKS / *.mym)
    Magic,
    /// Host firewall helpers (explicit only; never auto-open)
    Firewall {
        #[command(subcommand)]
        action: FirewallCmd,
    },
}

/// Shells supported by `mymesh completions`
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionShell {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

#[derive(Subcommand, Debug)]
enum MeshCmd {
    /// Show mesh id and trusted roster
    Status,
    /// Pull/push membership with all trusted peers (gossip sync)
    Sync,
}

#[derive(Subcommand, Debug)]
enum FirewallCmd {
    /// Explain which ports to open and how (not named "help" — reserved by clap)
    #[command(name = "explain", visible_alias = "ports")]
    Explain,
    /// Detect ufw/firewalld and show current state
    Status,
    /// Ubuntu/Debian UFW backend
    Ufw {
        #[command(subcommand)]
        action: FirewallAction,
    },
    /// Fedora/RHEL firewalld backend
    Firewalld {
        #[command(subcommand)]
        action: FirewallAction,
    },
}

#[derive(Subcommand, Debug)]
enum FirewallAction {
    /// Show MyMesh-related rules / ports
    Status,
    /// Open MyMesh LAN ports (requires root)
    Allow,
    /// Remove MyMesh LAN rules (requires root)
    Deny,
}

#[derive(Subcommand, Debug)]
enum ConnectRequestCmd {
    /// Temporarily accept new join requests
    Allow {
        /// Arm duration in seconds
        #[arg(long)]
        secs: Option<u64>,
    },
    /// Stop accepting join requests
    Deny,
    /// Show whether join requests are armed
    Status,
}

#[derive(Subcommand, Debug)]
enum RequestsCmd {
    /// List pending join requests
    List,
    /// Accept a pending device
    Accept {
        #[arg(value_name = "DEVICE")]
        device: String,
    },
    /// Deny a pending device
    Deny {
        #[arg(value_name = "DEVICE")]
        device: String,
        #[arg(long, default_value = "denied by operator")]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceCmd {
    /// systemctl status mymesh
    Status {
        /// Use system unit instead of user unit
        #[arg(long)]
        system: bool,
    },
    /// systemctl start mymesh
    Start {
        #[arg(long)]
        system: bool,
    },
    /// systemctl stop mymesh
    Stop {
        #[arg(long)]
        system: bool,
    },
    /// systemctl restart mymesh
    Restart {
        #[arg(long)]
        system: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DemoCmd {
    /// SPAKE2 pair demo (two local identities)
    Pair,
    /// Local fabric session demo
    Session,
}

#[derive(Subcommand, Debug)]
enum PairCmd {
    /// Resident: arm + mint PairSession + print QR_A v2 (required nonce).
    /// Joiner: `dual --join --resident <id>`.
    Dual {
        /// Join as guest toward this resident (hex or 24 words)
        #[arg(long)]
        join: bool,
        /// Resident device id / words (required with --join)
        #[arg(long, value_name = "DEVICE")]
        resident: Option<String>,
        /// Optional direct host base URL for ep=direct (`http://ip:port`)
        #[arg(long)]
        host: Option<String>,
        /// Arm / session TTL seconds (default: config arm_timeout_secs)
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Verify confirm code (HMAC Crockford 4-4); write JoinStore decision
    Confirm {
        /// Accept or deny code from phone (hyphens optional)
        code: String,
        /// Pair session id (default: unique active session)
        #[arg(long)]
        sid: Option<String>,
        /// Joiner device id when multiple pending
        #[arg(long)]
        joiner: Option<String>,
    },
    /// Show active pair session status
    Status {
        #[arg(long)]
        sid: Option<String>,
    },
    /// Expire previous session and arm a fresh dual
    Retry {
        /// Session to expire (default: active)
        sid: Option<String>,
    },
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

    // Reduce log noise in TUI. Never log to stdout: ProxyCommand / pipes need a clean stream.
    let is_tui = matches!(command, Some(Commands::Tui));
    let is_proxy = matches!(command, Some(Commands::ProxySsh { .. }));
    if !is_tui {
        let filter = if is_proxy {
            // ssh ProxyCommand: keep stderr quiet unless user sets RUST_LOG
            EnvFilter::from_default_env()
        } else {
            EnvFilter::from_default_env().add_directive("mymesh=info".parse()?)
        };
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
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
            if code.is_some()
                || mailbox_dir.is_some()
                || mailbox.is_some()
                || local
                || nameplate.is_some()
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
        Commands::Completions { shell, out } => install::cmd_completions(shell.as_str(), out)?,
        Commands::Demo { scenario } => match scenario {
            DemoCmd::Pair => demo_pair().await?,
            DemoCmd::Session => demo_session().await?,
        },
        Commands::Mesh { action } => match action {
            MeshCmd::Status => cmd_mesh_status(&paths).await?,
            MeshCmd::Sync => cmd_mesh_sync(&paths).await?,
        },
        Commands::Kick {
            device,
            force,
            yes_kick_from_mesh,
            yes_i_am_sure,
        } => cmd_kick(&paths, &device, force, yes_kick_from_mesh, yes_i_am_sure).await?,
        Commands::InstallNotes => print_install_notes(),
        Commands::Hosts { group } => magic_cmd::cmd_hosts(&paths, group).await?,
        Commands::Label { device, name } => magic_cmd::cmd_label(&paths, &device, &name).await?,
        Commands::Alias {
            device,
            name,
            remove,
        } => magic_cmd::cmd_alias(&paths, &device, &name, remove).await?,
        Commands::Group {
            device,
            name,
            remove,
        } => magic_cmd::cmd_group(&paths, &device, &name, remove).await?,
        Commands::Resolve { name } => magic_cmd::cmd_resolve(&paths, &name).await?,
        Commands::SshConfig { domain } => magic_cmd::cmd_ssh_config(&paths, domain)?,
        Commands::ProxySsh { host } => magic_cmd::cmd_proxy_ssh(&paths, &host).await?,
        Commands::Expose {
            device,
            port,
            local,
        } => magic_cmd::cmd_expose(&paths, &device, port, local).await?,
        Commands::Carrier { port } => magic_cmd::cmd_carrier(&paths, port).await?,
        Commands::Pair { action } => match action {
            PairCmd::Dual {
                join,
                resident,
                host,
                ttl,
            } => {
                if join {
                    let r = resident.ok_or_else(|| {
                        anyhow::anyhow!("--join requires --resident <device-id-or-words>")
                    })?;
                    pair_cmd::cmd_pair_dual_join(&paths, &r).await?
                } else {
                    pair_cmd::cmd_pair_dual(&paths, host, ttl).await?
                }
            }
            PairCmd::Confirm { code, sid, joiner } => {
                pair_cmd::cmd_pair_confirm(&paths, &code, sid, joiner).await?
            }
            PairCmd::Status { sid } => pair_cmd::cmd_pair_status(&paths, sid).await?,
            PairCmd::Retry { sid } => pair_cmd::cmd_pair_retry(&paths, sid).await?,
        },
        Commands::Magic => magic_cmd::print_magic_help(),
        Commands::Firewall { action } => match action {
            FirewallCmd::Explain => firewall::print_help(),
            FirewallCmd::Status => firewall::cmd_status()?,
            FirewallCmd::Ufw { action } => match action {
                FirewallAction::Status => firewall::ufw_status()?,
                FirewallAction::Allow => firewall::ufw_allow()?,
                FirewallAction::Deny => firewall::ufw_deny()?,
            },
            FirewallCmd::Firewalld { action } => match action {
                FirewallAction::Status => firewall::firewalld_status()?,
                FirewallAction::Allow => firewall::firewalld_allow()?,
                FirewallAction::Deny => firewall::firewalld_deny()?,
            },
        },
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
            let qr = code
                .render::<char>()
                .quiet_zone(false)
                .module_dimensions(1, 1)
                .build();
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

pub(crate) async fn cmd_arm(paths: &Paths, secs: Option<u64>) -> Result<()> {
    let cfg = Config::load(paths.config_file())?;
    let ttl = secs.unwrap_or(cfg.limits.arm_timeout_secs);
    let state = ArmState::arm(paths.arm_file(), ttl)?;
    let id = Identity::load_or_create(paths.identity_file())?;
    let words = device_id_to_words(&id.device_id())?;
    println!("{} until {:?}", style("ARMED").green().bold(), state.until);
    println!("  hex   {}", id.device_id());
    println!("  words {words}");
    Ok(())
}

pub(crate) async fn cmd_arm_status(paths: &Paths) -> Result<()> {
    let arm = ArmState::load(paths.arm_file())?;
    if arm.is_effectively_armed() {
        println!("armed until {:?}", arm.until);
    } else {
        println!("disarmed");
    }
    Ok(())
}

pub(crate) async fn cmd_requests_list(paths: &Paths) -> Result<()> {
    let joins = JoinStore::open(paths.join_dir())?;
    let list = joins.list_pending()?;
    if list.is_empty() {
        println!("No pending join requests.");
        return Ok(());
    }
    for p in list {
        println!("{}  {}  fp={}", p.device_id.short(), p.label, p.fingerprint);
        println!("    {}", p.device_id);
    }
    Ok(())
}

pub(crate) async fn cmd_requests_decide(
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

fn resolve_pending(pending: &[mymesh_core::PendingJoin], q: &str) -> Result<mymesh_core::DeviceId> {
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

pub(crate) async fn cmd_link_join(paths: &Paths, target: &str) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let host_id = parse_device_id(target)?;
    println!("requesting link to {}…", style(host_id.short()).cyan());
    let (conn, transport) = mesh_conn::connect_raw(&identity, &cfg, host_id).await?;
    let peer = run_join_as_guest(
        conn,
        &identity,
        &cfg.device_label,
        &mut store,
        &paths.mesh_file(),
        Capability::all(),
    )
    .await?;
    println!(
        "{} linked to {} ({})",
        style("ok").green().bold(),
        peer.label,
        peer.id.short()
    );
    mesh_conn::shutdown_opt(transport).await;
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
        println!("{}  {}  {:?}  rtt={rtt}", d.id.short(), d.label, d.trust);
        println!("    {}", d.id);
    }
    Ok(())
}

pub(crate) async fn cmd_unlink(paths: &Paths, device: &str) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device(&store, device)?;
    store.revoke(&id)?;
    println!("{} revoked {}", style("ok").green().bold(), id);
    Ok(())
}

pub(crate) fn resolve_device(store: &DeviceStore, q: &str) -> Result<mymesh_core::DeviceId> {
    resolve_device_pub(store, q)
}

pub(crate) fn resolve_device_pub(store: &DeviceStore, q: &str) -> Result<mymesh_core::DeviceId> {
    if let Ok(id) = parse_device_id(q) {
        return Ok(id);
    }
    store.resolve_query(q).map_err(|e| anyhow::anyhow!("{e}"))
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
    let transport = std::sync::Arc::new(IrohTransport::bind(&identity).await?);
    let agent = Agent::from_paths(&identity, paths, cfg.clone())?;
    // Single iroh endpoint: dial proxy so CLI/TUI never re-bind the same identity.
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    {
        let t = transport.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Err(e) = mymesh_net::serve_dial_proxy(sock, t).await {
                tracing::error!(%e, "dial proxy exited");
            }
        });
    }
    println!("  dial proxy  {}", sock.display());
    // Magic plane: DNS, SOCKS5, mesh-IP auto ports, reconnect probes (shared transport)
    mymesh_session::MagicPlane::new(
        paths.clone(),
        &identity,
        cfg.device_label.clone(),
        &cfg,
        Some(transport.clone()),
    )
    .spawn()
    .await;
    if cfg.magic.enabled {
        println!(
            "  magic DNS {}  SOCKS5 {}  domain *.{}",
            cfg.magic.dns_bind, cfg.magic.socks_bind, cfg.magic.domain
        );
    }
    agent.run(transport.as_ref()).await?;
    Ok(())
}

async fn open_session_to(
    paths: &Paths,
    device: &str,
) -> Result<(Session, Option<IrohTransport>, mymesh_core::DeviceId)> {
    mesh_conn::open_trusted_session(paths, device).await
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
    // stdin reader: exits when channel closes or stdin EOF
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut buf) {
                Ok(0) => break, // real stdin EOF
                Ok(n) => {
                    if tx_in.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let mut remote_exit = false;
    loop {
        tokio::select! {
            frame = conn.recv_frame() => {
                match frame {
                    Ok(frame) => {
                        if frame.channel.kind != mymesh_protocol::ChannelKind::Terminal {
                            continue;
                        }
                        let msg: TerminalMessage = decode_msg(&frame.payload)?;
                        if !client.handle_host_msg(msg)? {
                            remote_exit = true;
                            break;
                        }
                    }
                    Err(e) => {
                        // Normal after remote shell Ctrl+D / hangup
                        eprintln!("\r\n[mymesh] session closed ({e})\r");
                        remote_exit = true;
                        break;
                    }
                }
            }
            input = rx_in.recv() => {
                match input {
                    Some(data) => {
                        if conn
                            .send_frame(Frame {
                                channel: ChannelId::terminal(1),
                                payload: encode_msg(&TerminalMessage::Input(data))?,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    drop(client); // restore raw mode before further prints
    let _ = conn.close().await;
    mesh_conn::shutdown_opt(transport).await;
    if remote_exit {
        eprintln!("[mymesh] shell session ended cleanly");
    }
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
    mesh_conn::shutdown_opt(transport).await;
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
    mesh_conn::shutdown_opt(transport).await;
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
        mesh_id: None,

        aliases: Vec::new(),
        groups: Vec::new(),
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
        mesh_id: None,

        aliases: Vec::new(),
        groups: Vec::new(),
    })?;
    let host_ep = fabric.endpoint(host_id.device_id());
    let guest_ep = fabric.endpoint(guest_id.device_id());
    let accept = tokio::spawn(async move { host_ep.accept().await });
    let guest_conn = guest_ep.connect(host_id.device_id()).await?;
    let host_conn = accept.await??;
    let host_hs =
        Session::handshake_acceptor(host_conn, &host_id, "host", &host_store, Capability::all());
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

async fn cmd_mesh_status(paths: &Paths) -> Result<()> {
    let mesh = MeshState::load(paths.mesh_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let id = Identity::load_or_create(paths.identity_file())?;
    println!("{}", style("Mesh").bold());
    println!("  mesh id   {}", mesh.mesh_id);
    println!(
        "  self      {} ({})",
        id.device_id().short(),
        Config::load(paths.config_file())?.device_label
    );
    if let Some(k) = &mesh.last_kick_notice {
        println!(
            "  last kick notice: you were kicked by {} — {}",
            k.by_label, k.message
        );
    }
    println!("  members:");
    let trusted: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| matches!(d.trust, mymesh_core::TrustState::Trusted))
        .collect();
    if trusted.is_empty() {
        println!("    (none yet — link devices to form a mesh)");
    } else {
        for d in trusted {
            println!("    {}  {}  {:?}", d.id.short(), d.label, d.mesh_id);
            println!("      {}", d.id);
        }
    }
    let pending = mymesh_core::PendingKickStore::open(paths.pending_kicks_file())?;
    let kicks = pending.list();
    if !kicks.is_empty() {
        println!("  pending kicks:");
        for k in kicks {
            println!(
                "    {}  {}  force={} delivered={} acks={}/{}",
                k.target_id.short(),
                k.target_label,
                k.force,
                k.delivered_to_target,
                k.acks.len(),
                k.expected.len()
            );
        }
    }
    Ok(())
}

async fn cmd_mesh_sync(paths: &Paths) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let mesh = MeshState::load(paths.mesh_file())?;
    let peers: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| matches!(d.trust, mymesh_core::TrustState::Trusted))
        .map(|d| d.id)
        .collect();
    if peers.is_empty() {
        println!("no trusted peers to sync with");
        return Ok(());
    }
    let mut total_added = 0usize;
    for peer in peers {
        println!("sync {}…", peer.short());
        match sync_with_peer(paths, &identity, &cfg, &mesh, peer).await {
            Ok(n) => {
                total_added += n;
                println!("  ok (+{n} members)");
            }
            Err(e) => println!("  err: {e}"),
        }
    }
    println!(
        "{} mesh sync complete (learned {total_added} new members)",
        style("ok").green().bold()
    );
    Ok(())
}

async fn sync_with_peer(
    paths: &Paths,
    identity: &Identity,
    cfg: &Config,
    mesh: &MeshState,
    peer: mymesh_core::DeviceId,
) -> Result<usize> {
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame};
    let store = DeviceStore::open(paths.devices_file())?;
    let (conn, transport) = mesh_conn::connect_raw(identity, cfg, peer).await?;
    let session =
        Session::handshake_dialer(conn, identity, &cfg.device_label, &store, Capability::all())
            .await?;
    let conn = session.into_conn();
    // request their roster
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&ControlMessage::MembershipRequest { nonce: 1 })?,
    })
    .await?;
    // also push ours
    let announce = build_announce(identity, &cfg.device_label, &store, mesh);
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&announce)?,
    })
    .await?;

    let mut added = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv_frame()).await {
            Ok(Ok(frame)) => {
                if frame.channel.kind != mymesh_protocol::ChannelKind::Control {
                    continue;
                }
                let msg: ControlMessage = decode_msg(&frame.payload)?;
                match msg {
                    ControlMessage::MembershipSnapshot {
                        mesh_id,
                        from_id,
                        members,
                        ts,
                        signature,
                        ..
                    }
                    | ControlMessage::MembershipAnnounce {
                        mesh_id,
                        from_id,
                        members,
                        ts,
                        signature,
                        ..
                    } => {
                        mymesh_session::verify_membership(
                            &from_id, &mesh_id, ts, &members, &signature,
                        )?;
                        let mut store = DeviceStore::open(paths.devices_file())?;
                        added += apply_membership(
                            &mut store,
                            &paths.mesh_file(),
                            &from_id,
                            &mesh_id,
                            &members,
                            identity.device_id(),
                        )?;
                        break;
                    }
                    ControlMessage::Ping { nonce } => {
                        conn.send_frame(Frame {
                            channel: ChannelId::control(),
                            payload: encode_msg(&ControlMessage::Pong { nonce })?,
                        })
                        .await?;
                    }
                    _ => {}
                }
            }
            _ => break,
        }
    }
    let _ = conn.close().await;
    mesh_conn::shutdown_opt(transport).await;
    Ok(added)
}

async fn cmd_kick(
    paths: &Paths,
    device: &str,
    force: bool,
    yes_kick: bool,
    yes_sure: bool,
) -> Result<()> {
    use mymesh_core::{PendingKick, PendingKickStore};
    use mymesh_protocol::ControlMessage;
    use mymesh_session::bump_mesh_dirty;
    use std::io::{self, Write};

    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let target = resolve_device(&store, device)?;
    let rec = store
        .get(&target)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("device not found"))?;
    if !matches!(rec.trust, mymesh_core::TrustState::Trusted) {
        bail!("device is not trusted");
    }

    let label = rec.label.as_str().to_string();
    if force {
        println!(
            "{}",
            style("FORCE KICK — immediate mesh removal; notice delivered when online")
                .red()
                .bold()
        );
    }
    if !(yes_kick && yes_sure) {
        print!(
            "Type {} to kick {} ({}): ",
            style("KICK FROM MESH").red().bold(),
            style(&label).cyan(),
            target.short()
        );
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim() != "KICK FROM MESH" {
            bail!("aborted — first confirmation failed");
        }
        print!(
            "Type {} if you are sure you want to kick the device: ",
            style("I AM SURE").red().bold()
        );
        io::stdout().flush()?;
        line.clear();
        io::stdin().read_line(&mut line)?;
        if line.trim() != "I AM SURE" {
            bail!("aborted — second confirmation failed");
        }
    }

    let mesh = MeshState::load(paths.mesh_file())?;
    let ts = chrono::Utc::now().timestamp();
    let by_id = identity.device_id();
    let by_label = cfg.device_label.clone();
    let message = format!("you were kicked from the mesh by {by_label} host");
    let signature = sign_kick(&identity, &mesh.mesh_id, &target, ts);

    let expected: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| matches!(d.trust, mymesh_core::TrustState::Trusted) && d.id != target)
        .map(|d| d.id)
        .collect();

    let mut pending = PendingKickStore::open(paths.pending_kicks_file())?;
    pending.upsert(PendingKick {
        target_id: target,
        target_label: label.clone(),
        by_id,
        by_label: by_label.clone(),
        mesh_id: mesh.mesh_id.clone(),
        message: message.clone(),
        ts,
        signature,
        force,
        created_at: chrono::Utc::now(),
        delivered_to_target: false,
        acks: vec![],
        expected: expected.clone(),
    })?;

    let notice = ControlMessage::KickNotice {
        mesh_id: mesh.mesh_id.clone(),
        by_id,
        by_label: by_label.clone(),
        message: message.clone(),
        ts,
        force,
        signature,
    };
    println!("notifying kicked device {}…", target.short());
    match notify_peer(paths, &identity, &cfg, target, notice).await {
        Ok(()) => {
            println!("  notice delivered");
            pending.mark_delivered(&target)?;
        }
        Err(e) => println!("  offline — queued as pending kick ({e})"),
    }

    let announce = ControlMessage::KickAnnounce {
        mesh_id: mesh.mesh_id.clone(),
        target_id: target,
        target_label: label.clone(),
        by_id,
        by_label: by_label.clone(),
        message: message.clone(),
        ts,
        force,
        expected: expected.clone(),
        signature: sign_kick(&identity, &mesh.mesh_id, &target, ts),
    };
    for peer in &expected {
        print!("announcing kick to {}… ", peer.short());
        match notify_peer(paths, &identity, &cfg, *peer, announce.clone()).await {
            Ok(()) => println!("ok"),
            Err(e) => println!("err {e}"),
        }
    }

    // Local remove (force and normal both remove locally)
    apply_kick_target(&mut store, &target)?;
    bump_mesh_dirty(&paths.mesh_file(), &paths.mesh_dirty_file())?;
    println!(
        "{} {}kicked {} ({}) from mesh {}",
        style("ok").green().bold(),
        if force { "force-" } else { "" },
        label,
        target.short(),
        mesh.mesh_id
    );
    println!("  message: {message}");
    println!("  pending kicks: mymesh mesh status  (agents deliver when online)");
    Ok(())
}

async fn notify_peer(
    paths: &Paths,
    identity: &Identity,
    cfg: &Config,
    peer: mymesh_core::DeviceId,
    msg: mymesh_protocol::ControlMessage,
) -> Result<()> {
    use mymesh_protocol::{encode_msg, ChannelId, Frame};
    let store = DeviceStore::open(paths.devices_file())?;
    let (conn, transport) = mesh_conn::connect_raw(identity, cfg, peer).await?;
    let session =
        Session::handshake_dialer(conn, identity, &cfg.device_label, &store, Capability::all())
            .await
            .map_err(|e| anyhow::anyhow!("session handshake failed: {e}"))?;
    let conn = session.into_conn();
    conn.send_frame(Frame {
        channel: ChannelId::control(),
        payload: encode_msg(&msg)?,
    })
    .await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), conn.recv_frame()).await;
    let _ = conn.close().await;
    mesh_conn::shutdown_opt(transport).await;
    Ok(())
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
