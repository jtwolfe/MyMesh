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
use mymesh_core::wire::EnrollWriteBody;
use mymesh_core::{
    not_after_days, parse_capabilities, parse_enroll_facet, read_enroll_sig_hex,
    status_pack as continuity_status_pack, wipe_pack as continuity_wipe_pack, ArmState, Capability,
    Config, DeviceStore, EnrollmentStore, GrantStore, IssuedBy, JoinDecision, JoinStore, MeshState,
    Paths,
};
use mymesh_crypto::{
    accept_owner_claim, admin_verifying_key_bytes, check_claim_authorized, device_id_to_words,
    device_join_uri, mesh_init, mesh_recover_with_code, mesh_rotate_password, mesh_unlock_password,
    parse_device_id, resolve_claim_fingerprint, seal_owner_backup, sign_mrk_proof_ed25519,
    unseal_owner_backup, ClaimAuthMethod, ClaimWindowFile, Identity, MeshMasterFile, MeshOwnerFile,
    MmkRuntime, OwnerBackupSealed, OwnerClaimRequest, RecoveryCode,
};
use mymesh_net::{
    run_mailbox_server, serve_control_socket, FsMailbox, HttpMailbox, IrohTransport, LocalFabric,
    LocalRendezvous, Rendezvous, Transport,
};
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, FileMessage, Frame, TerminalMessage};
use mymesh_session::{
    apply_kick_target, apply_membership, build_announce, run_guest_pair, run_host_pair_code,
    run_join_as_guest, sign_kick, Agent, PairArmAdmin, Session, PAIR_HTTP_PORT,
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
    /// List linked devices / manage remote Admin capability (KD15)
    Devices {
        #[command(subcommand)]
        action: Option<DevicesCmd>,
        /// Machine-readable JSON (list mode)
        #[arg(long)]
        json: bool,
    },
    /// Guest grants: create / list / revoke (S5; docs/GRANTS.md)
    Grant {
        #[command(subcommand)]
        action: GrantCmd,
    },
    /// Person drive bindings on this node (Wave F; host-local)
    Enroll {
        #[command(subcommand)]
        action: EnrollCmd,
    },
    /// Continuity pack status / wipe (S8; host-local)
    Continuity {
        #[command(subcommand)]
        action: ContinuityCmd,
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
    /// Run the mesh agent (sessions, magic plane, pair/v2 + mesh/v1 HTTP)
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
    /// Person owner claim + sealed backup (S4; MMK is policy root)
    Owner {
        #[command(subcommand)]
        action: OwnerCmd,
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
    /// Lab-only pair HTTP if serve is down (serve owns :17878 after F4p)
    Carrier {
        /// HTTP listen port (default 17878)
        #[arg(long, default_value_t = 17878)]
        port: u16,
        /// Emit pair/v1 LAN QR instead of default v2 (compat escape; KD23/D5)
        #[arg(long = "pair-v1")]
        pair_v1: bool,
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
enum DevicesCmd {
    /// Grant remote Admin capability to a Trusted member (host-local CLI; KD15)
    #[command(name = "grant-admin")]
    GrantAdmin {
        #[arg(value_name = "DEVICE")]
        device: String,
    },
    /// Revoke remote Admin capability (host-local CLI)
    #[command(name = "revoke-admin")]
    RevokeAdmin {
        #[arg(value_name = "DEVICE")]
        device: String,
    },
}

#[derive(Subcommand, Debug)]
enum GrantCmd {
    /// Create a guest grant (subject → object device, host-local)
    Create {
        /// Guest subject device id (hex) or linked name/alias
        #[arg(long = "to", value_name = "GUEST")]
        to: String,
        /// Object host device (default: this node)
        #[arg(long = "on", value_name = "DEVICE")]
        on: Option<String>,
        /// Comma-separated caps: terminal,files,desktop,tcp (no admin)
        #[arg(long = "caps", default_value = "terminal,files")]
        caps: String,
        /// Optional expiry in days (`constraints.not_after`)
        #[arg(long = "days")]
        days: Option<u64>,
    },
    /// List grants in grants.json
    List {
        /// Machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Include revoked grants
        #[arg(long)]
        all: bool,
    },
    /// Revoke a grant by id (sets revoked_at)
    Revoke {
        #[arg(value_name = "GRANT_ID")]
        grant_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum EnrollCmd {
    /// List verified person drive bindings
    List,
    /// Revoke drive for a person (filesystem root)
    Revoke {
        #[arg(value_name = "PERSON_ID")]
        person_id: String,
    },
    /// Airgap add: verify carrier-enroll-v1, then write enrollments.json
    Add {
        #[arg(long = "person-id")]
        person_id: String,
        /// `personal` or `work`
        #[arg(long)]
        facet: String,
        /// RFC3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) or unix seconds
        #[arg(long)]
        ts: String,
        /// 16-byte nonce as base64url
        #[arg(long)]
        nonce: String,
        /// Person Ed25519 public key (64 hex chars)
        #[arg(long = "person-pubkey")]
        person_pubkey: String,
        /// Signature: 128 hex chars or raw 64 bytes
        #[arg(long = "sig-file", value_name = "PATH")]
        sig_file: PathBuf,
        /// Optional phone / person label
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ContinuityCmd {
    /// Show pack status: present | wiped | absent
    Status {
        #[arg(value_name = "PACK_ID")]
        pack_id: String,
        /// Machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Wipe pack secrets (host-local; no wipe_token required — filesystem trust)
    Wipe {
        #[arg(value_name = "PACK_ID")]
        pack_id: String,
        /// Confirm wipe (required)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum MeshCmd {
    /// Initialize mesh master key (password wrap + recovery codes once)
    Init {
        /// Read password from file (otherwise prompt; or MYMESH_MMK_PASSWORD)
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Overwrite existing mesh-master.json (destructive)
        #[arg(long)]
        force: bool,
    },
    /// Unlock MMK into host-local runtime cache (re-prompt after lock; not OS keyring)
    Unlock {
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
    },
    /// Clear host-local unlock cache (MRK no longer available without re-prompt)
    Lock,
    /// Show mesh id, roster, and mesh master key status
    Status,
    /// Pull/push membership with all trusted peers (gossip sync)
    Sync,
    /// Sign an MRK admin proof over a challenge (requires unlock; B2 / mesh API prep)
    Prove {
        /// Challenge as hex (random 32 bytes if omitted)
        #[arg(long)]
        challenge: Option<String>,
    },
    /// Re-wrap MRK with a new password (requires current password)
    #[command(name = "rotate-master")]
    RotateMaster {
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        new_password_file: Option<PathBuf>,
    },
    /// Recover master with a one-time recovery code (new MRK + new password)
    #[command(name = "recover-master")]
    RecoverMaster {
        /// One-time recovery code (256-bit hex printed at mesh init)
        #[arg(long)]
        code: Option<String>,
        /// Owner-proof recovery (S4; not yet implemented)
        #[arg(long)]
        owner_proof: bool,
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum OwnerCmd {
    /// Open a claim window (MMK unlocked; phone may claim without live unlock)
    #[command(name = "allow-claim")]
    AllowClaim {
        /// Window lifetime in seconds (default 300, max 86400)
        #[arg(long, default_value_t = 300)]
        secs: u64,
    },
    /// Accept a person-signed claim on this host (requires MMK unlock or claim window)
    Claim {
        #[arg(long)]
        person_id: String,
        /// Person Ed25519 public key (64 hex chars)
        #[arg(long)]
        person_pubkey: String,
        /// File containing claim signature hex over S0 preimage
        #[arg(long, value_name = "PATH")]
        sig_file: PathBuf,
        /// Unix timestamp signed in preimage (default: now)
        #[arg(long)]
        ts: Option<i64>,
        #[arg(long)]
        display_name: Option<String>,
        /// Replace existing owner (requires live MMK unlock)
        #[arg(long)]
        replace: bool,
    },
    /// Show current owner claim + backup slot
    Show,
    /// Clear owner claim (requires MMK unlocked — mesh-destructive)
    Clear {
        #[arg(long)]
        yes: bool,
    },
    /// Sealed owner backup export / import / seal-store
    Backup {
        #[command(subcommand)]
        action: OwnerBackupCmd,
    },
}

#[derive(Subcommand, Debug)]
enum OwnerBackupCmd {
    /// Copy on-disk sealed blob to a path
    Export {
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Import a sealed blob file into owner-backup.sealed
    Import {
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
    },
    /// Seal a 32-byte seed hex under a password and store (test / air-gap helper)
    Store {
        #[arg(long)]
        person_id: String,
        /// 32-byte person seed as hex
        #[arg(long)]
        seed_hex: String,
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        #[arg(long)]
        hint: Option<String>,
    },
    /// Attempt password unwrap of the stored sealed backup (S9 rate-limited).
    ///
    /// Prints person_id + seed hex on success. Wrong passwords count against
    /// the 5 / 15 min / person_id budget.
    Unwrap {
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Optional path to a sealed blob (default: on-disk owner-backup.sealed)
        #[arg(long, value_name = "PATH")]
        input: Option<PathBuf>,
    },
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
        /// Guest grant id — accepted joiners get Guest role, no full roster (GUEST.md)
        #[arg(long = "guest-grant", value_name = "GRANT_ID")]
        guest_grant: Option<String>,
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
        /// Optional direct host base URL for ep=direct (`http://ip:port` or `https://…`)
        #[arg(long)]
        host: Option<String>,
        /// Optional TLS SPKI pin (`sha256/<base64>`) for direct HTTPS host (requires `--host https://…`)
        #[arg(long, value_name = "PIN")]
        tlspin: Option<String>,
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
            ConnectRequestCmd::Allow { secs, guest_grant } => {
                cmd_arm(&paths, secs, guest_grant.as_deref()).await?
            }
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
        Commands::Devices { action, json } => match action {
            None => cmd_devices(&paths, json).await?,
            Some(DevicesCmd::GrantAdmin { device }) => cmd_grant_admin(&paths, &device)?,
            Some(DevicesCmd::RevokeAdmin { device }) => cmd_revoke_admin(&paths, &device)?,
        },
        Commands::Grant { action } => match action {
            GrantCmd::Create { to, on, caps, days } => {
                cmd_grant_create(&paths, &to, on.as_deref(), &caps, days)?
            }
            GrantCmd::List { json, all } => cmd_grant_list(&paths, json, all)?,
            GrantCmd::Revoke { grant_id } => cmd_grant_revoke(&paths, &grant_id)?,
        },
        Commands::Enroll { action } => match action {
            EnrollCmd::List => cmd_enroll_list(&paths)?,
            EnrollCmd::Revoke { person_id } => cmd_enroll_revoke(&paths, &person_id)?,
            EnrollCmd::Add {
                person_id,
                facet,
                ts,
                nonce,
                person_pubkey,
                sig_file,
                label,
            } => cmd_enroll_add(
                &paths,
                &person_id,
                &facet,
                &ts,
                &nonce,
                &person_pubkey,
                &sig_file,
                label,
            )?,
        },
        Commands::Continuity { action } => match action {
            ContinuityCmd::Status { pack_id, json } => {
                cmd_continuity_status(&paths, &pack_id, json)?
            }
            ContinuityCmd::Wipe { pack_id, yes } => cmd_continuity_wipe(&paths, &pack_id, yes)?,
        },
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
            MeshCmd::Init {
                password_file,
                force,
            } => cmd_mesh_init(&paths, password_file, force)?,
            MeshCmd::Unlock { password_file } => cmd_mesh_unlock(&paths, password_file)?,
            MeshCmd::Lock => cmd_mesh_lock(&paths)?,
            MeshCmd::Status => cmd_mesh_status(&paths).await?,
            MeshCmd::Sync => cmd_mesh_sync(&paths).await?,
            MeshCmd::Prove { challenge } => cmd_mesh_prove(&paths, challenge)?,
            MeshCmd::RotateMaster {
                password_file,
                new_password_file,
            } => cmd_mesh_rotate_master(&paths, password_file, new_password_file)?,
            MeshCmd::RecoverMaster {
                code,
                owner_proof,
                password_file,
            } => cmd_mesh_recover_master(&paths, code, owner_proof, password_file)?,
        },
        Commands::Owner { action } => match action {
            OwnerCmd::AllowClaim { secs } => cmd_owner_allow_claim(&paths, secs)?,
            OwnerCmd::Claim {
                person_id,
                person_pubkey,
                sig_file,
                ts,
                display_name,
                replace,
            } => cmd_owner_claim(
                &paths,
                &person_id,
                &person_pubkey,
                &sig_file,
                ts,
                display_name,
                replace,
            )?,
            OwnerCmd::Show => cmd_owner_show(&paths)?,
            OwnerCmd::Clear { yes } => cmd_owner_clear(&paths, yes)?,
            OwnerCmd::Backup { action } => match action {
                OwnerBackupCmd::Export { out } => cmd_owner_backup_export(&paths, &out)?,
                OwnerBackupCmd::Import { input } => cmd_owner_backup_import(&paths, &input)?,
                OwnerBackupCmd::Store {
                    person_id,
                    seed_hex,
                    password_file,
                    hint,
                } => cmd_owner_backup_store(&paths, &person_id, &seed_hex, password_file, hint)?,
                OwnerBackupCmd::Unwrap {
                    password_file,
                    input,
                } => cmd_owner_backup_unwrap(&paths, password_file, input)?,
            },
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
        Commands::Carrier { port, pair_v1 } => {
            magic_cmd::cmd_carrier(&paths, port, pair_v1).await?
        }
        Commands::Pair { action } => match action {
            PairCmd::Dual {
                join,
                resident,
                host,
                tlspin,
                ttl,
            } => {
                if join {
                    let r = resident.ok_or_else(|| {
                        anyhow::anyhow!("--join requires --resident <device-id-or-words>")
                    })?;
                    pair_cmd::cmd_pair_dual_join(&paths, &r).await?
                } else {
                    pair_cmd::cmd_pair_dual(&paths, host, ttl, tlspin).await?
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

pub(crate) async fn cmd_arm(
    paths: &Paths,
    secs: Option<u64>,
    guest_grant: Option<&str>,
) -> Result<()> {
    let cfg = Config::load(paths.config_file())?;
    let ttl = secs.unwrap_or(cfg.limits.arm_timeout_secs);
    let state = if let Some(gid) = guest_grant {
        let gid = gid.trim();
        if gid.is_empty() {
            bail!("--guest-grant requires a non-empty grant id");
        }
        let grants = GrantStore::open(paths.grants_file())?;
        let g = grants.get(gid).ok_or_else(|| {
            anyhow::anyhow!("grant {gid} not found — create with: mymesh grant create")
        })?;
        if g.role != mymesh_core::GrantRole::Guest {
            bail!("grant {gid} is not a guest grant");
        }
        if !g.is_active(chrono::Utc::now()) {
            bail!("grant {gid} is revoked or expired");
        }
        if g.capabilities.is_empty() {
            bail!("grant {gid} has no capabilities");
        }
        if g.capabilities.contains(&Capability::Admin) {
            bail!("Admin is not allowed on guest grants");
        }
        let identity = Identity::load_or_create(paths.identity_file())?;
        let local = identity.device_id();
        if !g.covers_object(&local) {
            bail!("grant {gid} object is not this host");
        }
        let state = ArmState::arm_with_guest_grant(paths.arm_file(), ttl, gid)?;
        let words = device_id_to_words(&local)?;
        println!("{} until {:?}", style("ARMED").green().bold(), state.until);
        println!("  guest-grant {gid}");
        println!("  subject {}", g.subject_device_id.short());
        println!("  hex   {local}");
        println!("  words {words}");
        println!("  join path: guest (no full membership snapshot)");
        return Ok(());
    } else {
        ArmState::arm(paths.arm_file(), ttl)?
    };
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
        print!("armed until {:?}", arm.until);
        if let Some(ref g) = arm.guest_grant_id {
            print!("  guest-grant {g}");
        }
        println!();
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
        println!("  host-local admin: always (this node)");
        println!("  remote Admin: mymesh devices grant-admin <id>");
        return Ok(());
    }
    for d in store.list() {
        let m = mymesh_core::PeerMetrics::load(paths.metrics_dir(), &d.id).ok();
        let rtt = m
            .as_ref()
            .and_then(|x| x.latest_rtt())
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "—".into());
        let admin = if d.capabilities.contains(&Capability::Admin) {
            " admin"
        } else {
            ""
        };
        println!(
            "{}  {}  {:?}{admin}  rtt={rtt}",
            d.id.short(),
            d.label,
            d.trust
        );
        println!("    {}", d.id);
    }
    Ok(())
}

/// Host-local: create guest grant (S5). Writes grants.json mode 0600.
fn cmd_grant_create(
    paths: &Paths,
    to: &str,
    on: Option<&str>,
    caps: &str,
    days: Option<u64>,
) -> Result<()> {
    let _auth = mymesh_core::AdminAuthority::host_local();
    debug_assert!(_auth.may_mutate_local_store());

    // S9: grant mutate 30 / min / session (file-backed; host-local CLI key).
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        paths.metrics_dir(),
        mymesh_core::LimitKind::GrantMutate,
        mymesh_core::HOST_LOCAL_SESSION,
    ) {
        bail!(
            "rate_limited: grant mutate; retry after {}s",
            rl.retry_after_secs
        );
    }

    let identity = Identity::load_or_create(paths.identity_file())?;
    let local_id = identity.device_id();
    let mesh = MeshState::load(paths.mesh_file())?;
    let store = DeviceStore::open(paths.devices_file())?;

    let subject = resolve_device_or_hex(&store, to)?;
    let object = match on {
        Some(q) => resolve_device_or_hex(&store, q)?,
        None => local_id,
    };
    let capabilities = parse_capabilities(caps).map_err(|e| anyhow::anyhow!("{e}"))?;
    if capabilities.contains(&Capability::Admin) {
        bail!("Admin is not allowed on guest grants (product policy)");
    }

    let mut grants = GrantStore::open(paths.grants_file())?;
    let grant = grants
        .create_guest(
            mesh.mesh_id.clone(),
            subject,
            object,
            capabilities,
            not_after_days(days),
            IssuedBy::device(&local_id),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    mymesh_core::record_grant_mutate(paths.metrics_dir());

    println!(
        "{} grant {}  guest {} → object {}",
        style("ok").green().bold(),
        grant.grant_id,
        subject.short(),
        object.short()
    );
    println!(
        "  caps: {}",
        grant
            .capabilities
            .iter()
            .map(|c| format!("{c:?}").to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    );
    if let Some(na) = grant.constraints.not_after {
        println!("  not_after: {}", na.to_rfc3339());
    }
    println!("  role: guest  mesh: {}", grant.mesh_id);
    println!("  revoke: mymesh grant revoke {}", grant.grant_id);
    Ok(())
}

fn cmd_grant_list(paths: &Paths, json: bool, all: bool) -> Result<()> {
    let grants = GrantStore::open(paths.grants_file())?;
    let now = chrono::Utc::now();
    let list: Vec<_> = grants
        .list()
        .into_iter()
        .filter(|g| all || g.is_active(now))
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }
    if list.is_empty() {
        println!("No grants.");
        println!("  mymesh grant create --to <guest> --caps terminal,files --days 7");
        return Ok(());
    }
    for g in list {
        let status = if g.revoked_at.is_some() {
            "revoked"
        } else if !g.is_active(now) {
            "expired"
        } else {
            "active"
        };
        let obj = g
            .object
            .as_device_id()
            .map(|d| d.short())
            .unwrap_or_else(|| "?".into());
        let caps = g
            .capabilities
            .iter()
            .map(|c| format!("{c:?}").to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}  {}  {} → {}  [{}]  {}",
            g.grant_id,
            status,
            g.subject_device_id.short(),
            obj,
            caps,
            g.role.as_str()
        );
    }
    Ok(())
}

fn cmd_continuity_status(paths: &Paths, pack_id: &str, json: bool) -> Result<()> {
    let status =
        continuity_status_pack(paths, pack_id.trim()).map_err(|e| anyhow::anyhow!("{e}"))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "pack_id": pack_id.trim(),
                "status": status.as_str(),
            })
        );
    } else {
        println!(
            "{} continuity {}  {}",
            style("ok").green().bold(),
            pack_id.trim(),
            status.as_str()
        );
    }
    Ok(())
}

fn cmd_continuity_wipe(paths: &Paths, pack_id: &str, yes: bool) -> Result<()> {
    if !yes {
        bail!("refusing to wipe without --yes (removes continuity pack secrets)");
    }
    let status = continuity_wipe_pack(paths, pack_id.trim()).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} wiped continuity {} → {}",
        style("ok").green().bold(),
        pack_id.trim(),
        status.as_str()
    );
    Ok(())
}

fn cmd_enroll_list(paths: &Paths) -> Result<()> {
    let store =
        EnrollmentStore::open(paths.enrollments_file()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let list = store.list();
    if list.is_empty() {
        println!("No enrollments.");
        println!(
            "  mymesh enroll add --person-id … --facet personal --ts … --nonce … --person-pubkey … --sig-file …"
        );
        return Ok(());
    }
    for e in list {
        let drive = if e.can_drive { "drive" } else { "revoked" };
        let label = e.label.as_deref().unwrap_or("");
        println!(
            "{}  {}  {}  {}  {}  {}",
            e.enrollment_id,
            e.person_id,
            e.facet.as_str(),
            drive,
            e.enrolled_at,
            label
        );
    }
    Ok(())
}

fn cmd_enroll_revoke(paths: &Paths, person_id: &str) -> Result<()> {
    let _auth = mymesh_core::AdminAuthority::host_local();
    debug_assert!(_auth.may_mutate_local_store());
    let pid = person_id.trim();
    if pid.is_empty() {
        bail!("person_id is required");
    }
    let mut store =
        EnrollmentStore::open(paths.enrollments_file()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let rec = store.revoke(pid).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} revoked enrollment {} ({})",
        style("ok").green().bold(),
        rec.person_id,
        rec.enrollment_id
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_enroll_add(
    paths: &Paths,
    person_id: &str,
    facet: &str,
    ts: &str,
    nonce: &str,
    person_pubkey: &str,
    sig_file: &Path,
    label: Option<String>,
) -> Result<()> {
    let _auth = mymesh_core::AdminAuthority::host_local();
    debug_assert!(_auth.may_mutate_local_store());

    let person_id = person_id.trim();
    if person_id.is_empty() {
        bail!("--person-id is required");
    }
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        paths.metrics_dir(),
        mymesh_core::LimitKind::EnrollWrite,
        person_id,
    ) {
        bail!(
            "rate_limited: enroll write; retry after {}s",
            rl.retry_after_secs
        );
    }

    let identity = Identity::load(paths.identity_file())
        .with_context(|| "no identity — run mymesh init first")?;
    let target = identity.device_id();
    let facet = parse_enroll_facet(facet).map_err(|e| anyhow::anyhow!("{e}"))?;
    let ts = parse_enroll_ts(ts)?;
    let sig_hex = read_enroll_sig_hex(sig_file).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = EnrollWriteBody {
        person_id: person_id.to_string(),
        facet,
        target_device_id_hex: target.to_string(),
        ts,
        nonce: nonce.trim().to_string(),
        person_public_key_hex: person_pubkey.trim().to_string(),
        sig_hex,
        label: label.filter(|s| !s.trim().is_empty()),
    };

    let mut store =
        EnrollmentStore::open(paths.enrollments_file()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let rec = store
        .add(&target, &body)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} enrolled {}  {}  {}",
        style("ok").green().bold(),
        rec.person_id,
        rec.facet.as_str(),
        rec.enrollment_id
    );
    println!("  can_drive  {}", rec.can_drive);
    println!("  file       {}", paths.enrollments_file().display());
    println!("  revoke     mymesh enroll revoke {}", rec.person_id);
    Ok(())
}

fn parse_enroll_ts(ts: &str) -> Result<String> {
    let t = ts.trim();
    if mymesh_core::wire::parse_rfc3339_unix(t).is_ok() {
        return Ok(t.to_string());
    }
    if let Ok(unix) = t.parse::<i64>() {
        let dt = chrono::DateTime::from_timestamp(unix, 0)
            .ok_or_else(|| anyhow::anyhow!("invalid --ts unix timestamp"))?;
        return Ok(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    bail!("--ts must be YYYY-MM-DDTHH:MM:SSZ or unix seconds");
}

fn cmd_grant_revoke(paths: &Paths, grant_id: &str) -> Result<()> {
    let _auth = mymesh_core::AdminAuthority::host_local();
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        paths.metrics_dir(),
        mymesh_core::LimitKind::GrantMutate,
        mymesh_core::HOST_LOCAL_SESSION,
    ) {
        bail!(
            "rate_limited: grant mutate; retry after {}s",
            rl.retry_after_secs
        );
    }
    let mut grants = GrantStore::open(paths.grants_file())?;
    let g = grants
        .revoke(grant_id.trim())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    mymesh_core::record_grant_mutate(paths.metrics_dir());
    println!(
        "{} revoked grant {} (subject {} → object)",
        style("ok").green().bold(),
        g.grant_id,
        g.subject_device_id.short()
    );
    if let Some(at) = g.revoked_at {
        println!("  revoked_at: {}", at.to_rfc3339());
    }
    println!("  active sessions subject→object should be killed by agent (≤60s target; C1b wire)");
    Ok(())
}

/// Resolve linked device name/alias/prefix, or accept full hex DeviceId.
fn resolve_device_or_hex(store: &DeviceStore, q: &str) -> Result<mymesh_core::DeviceId> {
    match store.resolve_query(q) {
        Ok(id) => Ok(id),
        Err(_) => {
            // bare hex device id (guest may not be linked yet)
            q.trim()
                .parse::<mymesh_core::DeviceId>()
                .map_err(|_| anyhow::anyhow!("no device matched '{q}' (name or 64-hex id)"))
        }
    }
}

/// Host-local CLI: grant remote Admin on a Trusted peer (KD15).
fn cmd_grant_admin(paths: &Paths, device: &str) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device(&store, device)?;
    // Host-local authority: data dir access is sufficient (no Admin required on caller).
    let _auth = mymesh_core::AdminAuthority::host_local();
    debug_assert!(_auth.may_mutate_local_store());
    store.grant_admin(&id)?;
    let rec = store
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("device vanished after grant"))?;
    println!(
        "{} granted remote Admin to {} ({})",
        style("ok").green().bold(),
        rec.label,
        id.short()
    );
    println!("  host-local CLI always administers this node without Admin cap");
    println!("  remote/API admin now allowed for this Trusted member");
    Ok(())
}

/// Host-local CLI: revoke remote Admin.
fn cmd_revoke_admin(paths: &Paths, device: &str) -> Result<()> {
    let mut store = DeviceStore::open(paths.devices_file())?;
    let id = resolve_device(&store, device)?;
    store.revoke_admin(&id)?;
    println!(
        "{} revoked remote Admin from {}",
        style("ok").green().bold(),
        id.short()
    );
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
    // KD-F16: serve owns pair/v2 + mesh/v1 (do not require `mymesh carrier`).
    let host_base = match agent.spawn_pair_http(paths, PAIR_HTTP_PORT).await {
        Ok(h) => {
            println!("  pair HTTP   0.0.0.0:{PAIR_HTTP_PORT}  /pair/v2 /mesh/v1");
            h.host_base
        }
        Err(e) => {
            eprintln!("  pair HTTP   bind :{PAIR_HTTP_PORT} failed: {e}");
            tracing::error!(%e, "pair/mesh HTTP bind failed");
            format!("http://127.0.0.1:{PAIR_HTTP_PORT}")
        }
    };
    // Single iroh endpoint: dial proxy so CLI/TUI never re-bind the same identity.
    // MMA1 arm_pair_qr shares this socket; MMD1 dial is unchanged after 4-byte magic.
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    let admin = std::sync::Arc::new(PairArmAdmin {
        paths: paths.clone(),
        secret: identity.to_secret_bytes(),
        host_base: std::sync::Arc::new(tokio::sync::Mutex::new(host_base)),
    });
    {
        let t: std::sync::Arc<dyn Transport> = transport.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_control_socket(sock, t, Some(admin)).await {
                tracing::error!(%e, "dial proxy exited");
            }
        });
    }
    println!("  dial proxy  {}  (MMD1 dial, MMA1 admin)", sock.display());
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
        mesh_role: mymesh_core::MeshRole::Member,
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
        mesh_role: mymesh_core::MeshRole::Member,
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
    if let Some(c) = &mesh.creator_device_id {
        let mark = if *c == id.device_id() {
            " (this node)"
        } else {
            ""
        };
        println!("  creator   {}{mark}", c.short());
    }
    if let Some(fp) = &mesh.mrk_fingerprint {
        println!("  mesh fp   {fp} (from mesh.json mirror)");
    }
    // Mesh master key (MMK / MRK)
    print_mmk_status(paths)?;
    println!("  admin     host-local=yes  remote=Admin cap | MRK proof | owner (S4)");
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
            let admin = if d.capabilities.contains(&Capability::Admin) {
                " Admin"
            } else {
                ""
            };
            println!("    {}  {}  {:?}{admin}", d.id.short(), d.label, d.mesh_id);
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

fn print_mmk_status(paths: &Paths) -> Result<()> {
    match MeshMasterFile::try_load(paths.mesh_master_file())? {
        None => {
            println!("  master    not initialized (mymesh mesh init)");
            println!("  unlock    policy=re-prompt (default; no OS keyring)");
        }
        Some(mf) => {
            let rt = MmkRuntime::load(paths.mmk_runtime_file())?;
            let unlocked = rt
                .as_ref()
                .map(|r| r.mrk_fingerprint == mf.mrk_fingerprint)
                .unwrap_or(false);
            println!(
                "  master    initialized  fingerprint={}  recovery_codes={}",
                mf.mrk_fingerprint,
                mf.recovery_code_hashes.len()
            );
            println!(
                "  unlock    {}  policy=re-prompt (host-local cache; not OS keyring)",
                if unlocked {
                    style("unlocked").green()
                } else {
                    style("locked").yellow()
                }
            );
            if unlocked {
                if let Some(rt) = rt {
                    if let Ok(mrk) = rt.to_mrk() {
                        let vk = admin_verifying_key_bytes(&mrk);
                        println!(
                            "  admin-vk  {}…  (MRK proof ready; mymesh mesh prove)",
                            hex::encode(&vk[..4])
                        );
                    }
                }
            }
            if let Some(rot) = mf.rotated_at {
                println!("  rotated   {}", rot.to_rfc3339());
            }
        }
    }
    Ok(())
}

fn cmd_mesh_init(paths: &Paths, password_file: Option<PathBuf>, force: bool) -> Result<()> {
    paths.ensure()?;
    let path = paths.mesh_master_file();
    if MeshMasterFile::exists(&path) && !force {
        bail!(
            "mesh-master.json already exists at {} (pass --force to overwrite)",
            path.display()
        );
    }
    let password = read_mmk_password(password_file.as_deref(), "New mesh master password", true)?;
    let init = mesh_init(password.as_bytes(), None)?;
    init.file.save(&path)?;

    // Migration (KD15): record creator + fingerprint. Existing Trusted peers keep
    // stored capabilities (no Admin auto-grant). Host-local CLI always node-admin.
    let identity = Identity::load_or_create(paths.identity_file())?;
    let mut mesh = MeshState::load(paths.mesh_file())?;
    mesh.mrk_fingerprint = Some(init.file.mrk_fingerprint.clone());
    mesh.creator_device_id = Some(identity.device_id());
    mesh.save(paths.mesh_file())?;

    // Existing Trusted devices: leave capabilities as stored (no Admin auto-grant).
    let store = DeviceStore::open(paths.devices_file())?;
    let trusted_no_admin: usize = store
        .list()
        .into_iter()
        .filter(|d| {
            matches!(d.trust, mymesh_core::TrustState::Trusted)
                && !d.capabilities.contains(&Capability::Admin)
        })
        .count();

    // Default re-prompt: do not leave runtime unlocked unless user runs unlock.
    let _ = MmkRuntime::clear(paths.mmk_runtime_file());

    println!("{}", style("Mesh master key initialized").green().bold());
    println!("  file          {}", path.display());
    println!("  fingerprint   {}", init.file.mrk_fingerprint);
    println!(
        "  creator       {} (host-local admin on this node)",
        identity.device_id().short()
    );
    println!(
        "  kdf           argon2id m={} t={} p={}",
        init.file.kdf_params.m, init.file.kdf_params.t, init.file.kdf_params.p
    );
    println!("  unlock policy re-prompt (default; OS keyring not enabled)");
    println!("  remote Admin  not auto-granted to existing peers (default grant has no Admin)");
    if trusted_no_admin > 0 {
        println!(
            "  note          {trusted_no_admin} Trusted peer(s) without Admin — use: mymesh devices grant-admin <id>"
        );
    }
    println!();
    println!(
        "{}",
        style("RECOVERY CODES — save these now; they are shown once")
            .red()
            .bold()
    );
    println!("  Each code is 256-bit hex. One code recovers the master (new MRK + password).");
    for (i, code) in init.recovery_codes.iter().enumerate() {
        println!("  {:2}.  {}", i + 1, code.display_hex());
    }
    println!();
    println!("Next: mymesh mesh unlock   # then mymesh mesh prove  (admin proof)");
    println!("      mymesh devices grant-admin <id>   # remote Admin for a Trusted peer");
    Ok(())
}

/// Sign challenge with unlocked MRK (Ed25519 admin proof). Demonstrates B2 without Carrier.
fn cmd_mesh_prove(paths: &Paths, challenge_hex: Option<String>) -> Result<()> {
    let file = MeshMasterFile::load(paths.mesh_master_file())?;
    let rt = MmkRuntime::load(paths.mmk_runtime_file())?
        .ok_or_else(|| anyhow::anyhow!("MMK locked — run `mymesh mesh unlock` first"))?;
    if rt.mrk_fingerprint != file.mrk_fingerprint {
        bail!("runtime fingerprint mismatch — re-run mesh unlock");
    }
    let mrk = rt.to_mrk()?;
    let challenge = if let Some(h) = challenge_hex {
        hex::decode(h.trim()).context("challenge hex")?
    } else {
        let mut b = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.to_vec()
    };
    let proof = sign_mrk_proof_ed25519(&mrk, &challenge);
    let ok = mymesh_crypto::verify_mrk_admin_proof(&mrk, &challenge, &proof);
    if !ok {
        bail!("internal: admin proof failed self-verify");
    }
    println!("{}", style("mrk_proof").green().bold());
    println!("  method      ed25519");
    println!("  challenge   {}", hex::encode(&challenge));
    println!(
        "  public_key  {}",
        proof.public_key_hex.as_deref().unwrap_or("")
    );
    println!("  signature   {}", proof.proof_hex);
    println!("  verify      ok (agent-local; mesh/v1 challenge auth is B3)");
    Ok(())
}

fn cmd_mesh_unlock(paths: &Paths, password_file: Option<PathBuf>) -> Result<()> {
    let file = MeshMasterFile::load(paths.mesh_master_file())?;
    let password = read_mmk_password(password_file.as_deref(), "Mesh master password", false)?;
    let mrk = mesh_unlock_password(&file, password.as_bytes())?;
    let rt = MmkRuntime::from_mrk(&mrk);
    rt.save(paths.mmk_runtime_file())?;
    println!(
        "{} fingerprint={}",
        style("unlocked").green().bold(),
        mrk.fingerprint()
    );
    println!(
        "  host-local cache {} (mode 0600; cleared by mesh lock / not OS keyring)",
        paths.mmk_runtime_file().display()
    );
    Ok(())
}

fn cmd_mesh_lock(paths: &Paths) -> Result<()> {
    let cleared = MmkRuntime::clear(paths.mmk_runtime_file())?;
    if cleared {
        println!("{}", style("locked").yellow().bold());
        println!("  cleared host-local unlock cache; re-prompt required");
    } else {
        println!("already locked (no host-local unlock cache)");
    }
    Ok(())
}

fn cmd_mesh_rotate_master(
    paths: &Paths,
    password_file: Option<PathBuf>,
    new_password_file: Option<PathBuf>,
) -> Result<()> {
    let file = MeshMasterFile::load(paths.mesh_master_file())?;
    let current = read_mmk_password(
        password_file.as_deref(),
        "Current mesh master password",
        false,
    )?;
    let new_pass = read_mmk_password(
        new_password_file.as_deref(),
        "New mesh master password",
        true,
    )?;
    let (new_file, mrk) =
        mesh_rotate_password(&file, current.as_bytes(), new_pass.as_bytes(), None)?;
    new_file.save(paths.mesh_master_file())?;
    // Keep unlocked if we were unlocked, with same MRK under new wrap.
    if MmkRuntime::load(paths.mmk_runtime_file())?.is_some() {
        MmkRuntime::from_mrk(&mrk).save(paths.mmk_runtime_file())?;
    }
    println!(
        "{} fingerprint={} (same MRK, new wrap)",
        style("rotated").green().bold(),
        new_file.mrk_fingerprint
    );
    Ok(())
}

fn cmd_mesh_recover_master(
    paths: &Paths,
    code: Option<String>,
    owner_proof: bool,
    password_file: Option<PathBuf>,
) -> Result<()> {
    if owner_proof {
        bail!(
            "--owner-proof recovery: challenge/sign flow not yet wired; use --code recovery for now"
        );
    }
    let code_str = code
        .ok_or_else(|| anyhow::anyhow!("pass --code <recovery-hex> (printed once at mesh init)"))?;
    let file = MeshMasterFile::load(paths.mesh_master_file())?;
    let recovery = RecoveryCode::parse(&code_str)?;
    let new_pass = read_mmk_password(password_file.as_deref(), "New mesh master password", true)?;
    let (new_file, mrk) = mesh_recover_with_code(&file, &recovery, new_pass.as_bytes(), None)?;
    new_file.save(paths.mesh_master_file())?;
    // KD28: update owner claim fingerprint without clearing person binding.
    if let Some(mut owner) = MeshOwnerFile::try_load(paths.mesh_owner_file())? {
        owner.bump_mrk_fingerprint(&new_file.mrk_fingerprint);
        owner.save(paths.mesh_owner_file())?;
        println!(
            "  owner claim retained; mrk_fingerprint → {} (epoch {})",
            owner.mrk_fingerprint, owner.mrk_epoch
        );
    }
    // Force re-unlock after recovery (new MRK).
    let _ = MmkRuntime::clear(paths.mmk_runtime_file());
    println!(
        "{} new fingerprint={}  remaining recovery codes={}",
        style("recovered").green().bold(),
        new_file.mrk_fingerprint,
        new_file.recovery_code_hashes.len()
    );
    println!("  old MRK invalidated; run mymesh mesh unlock with the new password");
    let _ = mrk; // zeroized on drop
    Ok(())
}

fn cmd_owner_allow_claim(paths: &Paths, secs: u64) -> Result<()> {
    if !MeshMasterFile::exists(paths.mesh_master_file()) {
        bail!("mesh master not initialized — run mymesh mesh init first");
    }
    // Requires unlocked MMK (or we could accept recovery at mint — unlocked is the S0 path).
    let rt = MmkRuntime::load(paths.mmk_runtime_file())?
        .ok_or_else(|| anyhow::anyhow!("MMK locked — run mymesh mesh unlock before allow-claim"))?;
    let _mrk = rt.to_mrk()?;
    let win = ClaimWindowFile::mint(&rt.mrk_fingerprint, secs);
    win.save(paths.claim_window_file())?;
    println!("{}", style("claim window open").green().bold());
    println!("  until           {}", win.until.to_rfc3339());
    println!("  secs            {}", win.secs);
    println!("  mrk_fingerprint {}", win.mrk_fingerprint);
    println!("  nonce           {}", win.nonce);
    println!(
        "  file            {} (mode 0600; phone may POST person-signed claim)",
        paths.claim_window_file().display()
    );
    println!("  note            phone never receives MMK/MRK — person sig only");
    Ok(())
}

fn cmd_owner_claim(
    paths: &Paths,
    person_id: &str,
    person_pubkey: &str,
    sig_file: &Path,
    ts: Option<i64>,
    display_name: Option<String>,
    replace: bool,
) -> Result<()> {
    let auth = check_claim_authorized(paths.mmk_runtime_file(), paths.claim_window_file())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mrk_fp = resolve_claim_fingerprint(
        auth,
        paths.mmk_runtime_file(),
        paths.claim_window_file(),
        paths.mesh_master_file(),
    )?;
    let mesh = MeshState::load(paths.mesh_file())?;
    let ts_unix = ts.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let sig_hex = std::fs::read_to_string(sig_file)
        .with_context(|| format!("read sig file {}", sig_file.display()))?;
    let sig_hex = sig_hex.trim().to_string();

    let identity = Identity::load(paths.identity_file())?;
    let existing = MeshOwnerFile::try_load(paths.mesh_owner_file())?;
    let req = OwnerClaimRequest {
        mesh_id: mesh.mesh_id,
        person_id: person_id.to_string(),
        person_public_key_hex: person_pubkey.trim().to_string(),
        display_name: display_name.unwrap_or_default(),
        ts_unix,
        claim_sig_hex: sig_hex,
        claimed_from_device_id: Some(identity.device_id().to_string()),
        replace,
    };
    let file = accept_owner_claim(
        &req,
        &mrk_fp,
        auth,
        existing.as_ref(),
        paths.mesh_owner_file(),
    )?;
    if auth == ClaimAuthMethod::ClaimWindow {
        let _ = ClaimWindowFile::clear(paths.claim_window_file());
    }
    println!("{}", style("owner claimed").green().bold());
    println!("  person_id       {}", file.person_id);
    println!("  display_name    {}", file.display_name);
    println!("  mrk_fingerprint {}", file.mrk_fingerprint);
    println!("  claimed_at      {}", file.claimed_at.to_rfc3339());
    println!(
        "  auth            {}",
        match auth {
            ClaimAuthMethod::MrkUnlocked => "agent_cosign (MMK unlocked)",
            ClaimAuthMethod::ClaimWindow => "claim_window",
        }
    );
    println!("  file            {}", paths.mesh_owner_file().display());
    Ok(())
}

fn cmd_owner_show(paths: &Paths) -> Result<()> {
    match MeshOwnerFile::try_load(paths.mesh_owner_file())? {
        Some(o) => {
            println!("{}", style("owner claim").green().bold());
            println!("  person_id       {}", o.person_id);
            println!("  display_name    {}", o.display_name);
            println!("  person_pk       {}", o.person_public_key_hex);
            println!("  mesh_id         {}", o.mesh_id);
            println!("  mrk_fingerprint {}", o.mrk_fingerprint);
            println!("  mrk_epoch       {}", o.mrk_epoch);
            println!("  claimed_at      {}", o.claimed_at.to_rfc3339());
            if let Some(d) = &o.claimed_from_device_id {
                println!("  claimed_from    {d}");
            }
            let backup = paths.owner_backup_file().exists();
            println!(
                "  backup_slot     {}",
                if backup {
                    format!("stored ({})", paths.owner_backup_file().display())
                } else if o.backup_stored_at.is_some() {
                    "marked but file missing".into()
                } else {
                    "empty".into()
                }
            );
        }
        None => {
            println!("{}", style("no owner claim").yellow().bold());
            println!("  claim with MMK unlocked or: mymesh owner allow-claim");
            println!("  then: mymesh owner claim --person-id … --person-pubkey … --sig-file …");
        }
    }
    if let Some(win) = ClaimWindowFile::try_load(paths.claim_window_file())? {
        if win.is_valid_now() {
            println!(
                "  claim_window    open until {} (nonce {})",
                win.until.to_rfc3339(),
                &win.nonce[..8.min(win.nonce.len())]
            );
        } else {
            println!("  claim_window    expired");
        }
    }
    Ok(())
}

fn cmd_owner_clear(paths: &Paths, yes: bool) -> Result<()> {
    if !yes {
        bail!("refusing to clear owner without --yes (mesh-destructive; requires MMK unlock)");
    }
    // Live MRK required for clear (policy root).
    let _rt = MmkRuntime::load(paths.mmk_runtime_file())?
        .ok_or_else(|| anyhow::anyhow!("MMK locked — unlock before clearing owner claim"))?;
    let cleared = MeshOwnerFile::clear(paths.mesh_owner_file())?;
    let _ = std::fs::remove_file(paths.owner_backup_file());
    let _ = ClaimWindowFile::clear(paths.claim_window_file());
    if cleared {
        println!("{}", style("owner cleared").yellow().bold());
    } else {
        println!("no owner claim present");
    }
    Ok(())
}

fn cmd_owner_backup_export(paths: &Paths, out: &Path) -> Result<()> {
    let sealed = OwnerBackupSealed::load(paths.owner_backup_file())?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    sealed.save(out)?;
    println!("{} → {}", style("exported").green().bold(), out.display());
    Ok(())
}

fn cmd_owner_backup_import(paths: &Paths, input: &Path) -> Result<()> {
    let raw =
        std::fs::read_to_string(input).with_context(|| format!("read {}", input.display()))?;
    let sealed: OwnerBackupSealed = serde_json::from_str(&raw)?;
    OwnerBackupSealed::store_blob(paths.owner_backup_file(), &sealed)?;
    if let Some(mut owner) = MeshOwnerFile::try_load(paths.mesh_owner_file())? {
        owner.mark_backup_stored();
        owner.save(paths.mesh_owner_file())?;
    }
    println!(
        "{} person_id={} → {}",
        style("imported").green().bold(),
        sealed.person_id,
        paths.owner_backup_file().display()
    );
    Ok(())
}

fn cmd_owner_backup_store(
    paths: &Paths,
    person_id: &str,
    seed_hex: &str,
    password_file: Option<PathBuf>,
    hint: Option<String>,
) -> Result<()> {
    let cleaned: String = seed_hex.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned).context("seed_hex")?;
    if bytes.len() != 32 {
        bail!("seed must be 32 bytes (64 hex chars), got {}", bytes.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    // Reuse MMK password helper but prefer MYMESH_BACKUP_PASSWORD when set.
    let password = if let Ok(env) = std::env::var("MYMESH_BACKUP_PASSWORD") {
        if !env.is_empty() {
            env
        } else {
            read_mmk_password(password_file.as_deref(), "Owner backup password", true)?
        }
    } else {
        read_mmk_password(password_file.as_deref(), "Owner backup password", true)?
    };
    let sealed = seal_owner_backup(
        password.as_bytes(),
        person_id,
        &seed,
        "",
        hint.as_deref(),
        None,
    )?;
    OwnerBackupSealed::store_blob(paths.owner_backup_file(), &sealed)?;
    if let Some(mut owner) = MeshOwnerFile::try_load(paths.mesh_owner_file())? {
        owner.mark_backup_stored();
        owner.save(paths.mesh_owner_file())?;
    }
    // Smoke-check roundtrip under S9 unwrap rate limit (5 / 15 min / person_id).
    let (out, _) =
        rate_limited_unseal_owner_backup(paths, person_id, password.as_bytes(), &sealed)?;
    if out != seed {
        bail!("internal: backup roundtrip mismatch");
    }
    println!(
        "{} person_id={} → {}",
        style("backup stored").green().bold(),
        person_id,
        paths.owner_backup_file().display()
    );
    Ok(())
}

/// S9: rate-limit backup unwrap attempts (5 / 15 min / person_id) and record metrics.
///
/// File-backed under metrics_dir so multiple CLI processes share the budget.
fn rate_limited_unseal_owner_backup(
    paths: &Paths,
    person_id: &str,
    password: &[u8],
    sealed: &OwnerBackupSealed,
) -> Result<([u8; 32], String)> {
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        paths.metrics_dir(),
        mymesh_core::LimitKind::OwnerBackupUnwrap,
        person_id,
    ) {
        mymesh_core::record_owner_backup_unwrap(paths.metrics_dir(), "rate_limited");
        bail!(
            "rate_limited: owner backup unwrap; retry after {}s",
            rl.retry_after_secs
        );
    }
    match unseal_owner_backup(password, sealed) {
        Ok(v) => {
            mymesh_core::record_owner_backup_unwrap(paths.metrics_dir(), "ok");
            Ok(v)
        }
        Err(e) => {
            mymesh_core::record_owner_backup_unwrap(paths.metrics_dir(), "fail");
            Err(e.into())
        }
    }
}

/// Real password-attempt path for sealed owner backup (S9 unwrap rate limit).
fn cmd_owner_backup_unwrap(
    paths: &Paths,
    password_file: Option<PathBuf>,
    input: Option<PathBuf>,
) -> Result<()> {
    let sealed = if let Some(p) = input {
        let raw = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        serde_json::from_str::<OwnerBackupSealed>(&raw).context("parse sealed backup")?
    } else {
        OwnerBackupSealed::load(paths.owner_backup_file())
            .with_context(|| format!("load {}", paths.owner_backup_file().display()))?
    };
    let password = if let Ok(env) = std::env::var("MYMESH_BACKUP_PASSWORD") {
        if !env.is_empty() {
            env
        } else {
            read_mmk_password(password_file.as_deref(), "Owner backup password", false)?
        }
    } else {
        read_mmk_password(password_file.as_deref(), "Owner backup password", false)?
    };
    let (seed, person_id) =
        rate_limited_unseal_owner_backup(paths, &sealed.person_id, password.as_bytes(), &sealed)?;
    println!(
        "{} person_id={}",
        style("unwrapped").green().bold(),
        person_id
    );
    println!("  seed_hex {}", hex::encode(seed));
    Ok(())
}

/// Read MMK password from (in order): `--password-file`, `MYMESH_MMK_PASSWORD`, interactive prompt.
fn read_mmk_password(password_file: Option<&Path>, prompt: &str, confirm: bool) -> Result<String> {
    if let Some(p) = password_file {
        let s = std::fs::read_to_string(p)
            .with_context(|| format!("read password file {}", p.display()))?;
        let pass = s.trim_end_matches(['\n', '\r']).to_string();
        if pass.is_empty() {
            bail!("password file is empty");
        }
        return Ok(pass);
    }
    if let Ok(env) = std::env::var("MYMESH_MMK_PASSWORD") {
        if !env.is_empty() {
            return Ok(env);
        }
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("no TTY for password prompt; set MYMESH_MMK_PASSWORD or --password-file");
    }
    let pass = rpassword::prompt_password(format!("{prompt}: ")).context("read password")?;
    if pass.is_empty() {
        bail!("password must not be empty");
    }
    if confirm {
        let again = rpassword::prompt_password("Confirm password: ").context("confirm password")?;
        if pass != again {
            bail!("passwords do not match");
        }
    }
    Ok(pass)
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
