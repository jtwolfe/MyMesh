//! MyMesh CLI — pair devices, open shells, copy files, control desktops.
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use console::style;
use mymesh_core::{Capability, Config, DeviceStore, Paths};
use mymesh_crypto::Identity;
use std::path::PathBuf;
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
    /// Config directory override
    #[arg(long, global = true, env = "MYMESH_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show this node identity and fingerprint
    Status,
    /// Initialize identity + config (safe to re-run)
    Init {
        /// Device label
        #[arg(long)]
        label: Option<String>,
    },
    /// Link a new device (Signal-style pairing code)
    Link {
        /// If omitted, this device hosts and prints a code
        code: Option<String>,
        /// Nameplate number when hosting (random if omitted)
        #[arg(long)]
        nameplate: Option<u16>,
    },
    /// List linked devices
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Revoke a linked device
    Unlink {
        /// Device id (hex) or unique label prefix
        device: String,
    },
    /// Open a remote terminal on a linked device
    Shell {
        /// Device id or label
        device: String,
        /// Shell to execute on the remote
        #[arg(long)]
        shell: Option<String>,
    },
    /// Copy files to/from a linked device (`src` / `dst` use device:path syntax)
    Cp { src: String, dst: String },
    /// Remote desktop session
    Desktop {
        device: String,
        #[arg(long, default_value_t = 30)]
        fps: u8,
    },
    /// Run the background service (pair + accept sessions)
    Serve {
        #[arg(long)]
        foreground: bool,
    },
    /// In-process pairing demo (no network) — validates crypto + protocol
    Demo {
        #[command(subcommand)]
        scenario: DemoCmd,
    },
    /// Print install notes for systemd / service mode
    InstallNotes,
}

#[derive(Subcommand, Debug)]
enum DemoCmd {
    /// Two in-process identities complete SPAKE2 pairing
    Pair,
    /// Pair then open a framed terminal message exchange
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
        Commands::Link { code, nameplate } => cmd_link(&paths, code, nameplate).await?,
        Commands::Devices { json } => cmd_devices(&paths, json).await?,
        Commands::Unlink { device } => cmd_unlink(&paths, &device).await?,
        Commands::Shell { device, shell } => {
            let _ = (device, shell);
            println!(
                "{}",
                style("shell: WAN transport (iroh) wires in next milestone — use `mymesh demo session` locally")
                    .yellow()
            );
        }
        Commands::Cp { src, dst } => {
            let _ = (src, dst);
            println!(
                "{}",
                style("cp: file engine is implemented; pair + iroh dial ships next").yellow()
            );
        }
        Commands::Desktop { device, fps } => {
            let _ = (device, fps);
            println!(
                "{}",
                style(
                    "desktop: controller + null capture ready; platform capture is feature-gated"
                )
                .yellow()
            );
        }
        Commands::Serve { foreground } => {
            let _ = foreground;
            cmd_serve(&paths).await?;
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
    Ok(())
}

async fn cmd_link(paths: &Paths, code: Option<String>, nameplate: Option<u16>) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = DeviceStore::open(paths.devices_file())?;
    let rendezvous = mymesh_net::LocalRendezvous::new();
    let caps = Capability::all();

    if let Some(code) = code {
        println!("Linking with code {} …", style(&code).cyan().bold());
        // Guest path requires a live host on same rendezvous — for WAN this is
        // the public mailbox. Local demo: run two processes is not possible on
        // LocalRendezvous across processes; instruct demo pair.
        println!(
            "{}",
            style(
                "Note: cross-process rendezvous needs the mailbox service.\n\
                 Run `mymesh demo pair` to verify the full SPAKE2 link ceremony in-process."
            )
            .dim()
        );
        let outcome = mymesh_session::run_guest_pair(
            &identity,
            &cfg.device_label,
            caps,
            &mut store,
            &rendezvous,
            &code,
        )
        .await;
        match outcome {
            Ok(o) => {
                println!("{} linked {}", style("ok").green().bold(), o.peer.label);
            }
            Err(e) => {
                bail!("link failed: {e}\nHint: start a host with `mymesh link` on the other machine sharing a mailbox, or use `mymesh demo pair`.");
            }
        }
    } else {
        let np = nameplate.unwrap_or_else(|| rand::random::<u16>() % 900 + 100);
        println!("{}", style("Hosting a link session…").bold());
        println!(
            "{}",
            style("On the other device run:  mymesh link <code>").dim()
        );
        // Generate and display code immediately by starting host ceremony in background
        // For UX we pre-generate via crypto helper
        let code = mymesh_crypto::code_from_entropy(np);
        println!();
        println!("  ┌─────────────────────────────────────────┐");
        println!(
            "  │  pairing code   {}  │",
            style(code.as_string()).cyan().bold()
        );
        println!("  └─────────────────────────────────────────┘");
        println!();
        println!("Waiting for peer (timeout / ctrl-c to cancel)…");
        println!(
            "{}",
            style("Local mailbox is in-process only — use `mymesh demo pair` for a full local walkthrough.")
                .yellow()
        );
        // Still run host so API is exercised when a peer appears on same rendezvous
        let mut store2 = DeviceStore::open(paths.devices_file())?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            mymesh_session::run_host_pair(
                &identity,
                &cfg.device_label,
                caps,
                &mut store2,
                &rendezvous,
                np,
            ),
        )
        .await;
        match result {
            Ok(Ok(o)) => {
                println!("{} linked {}", style("ok").green().bold(), o.peer.label);
            }
            Ok(Err(e)) => bail!("{e}"),
            Err(_) => {
                println!(
                    "{}",
                    style("no peer joined local rendezvous (expected without a second process)")
                        .dim()
                );
            }
        }
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
    println!("  control socket  {}", cfg.daemon.control_socket);
    println!(
        "  caps            terminal={} files={} desktop={}",
        cfg.daemon.enable_terminal, cfg.daemon.enable_files, cfg.daemon.enable_desktop
    );
    println!(
        "{}",
        style("Service loop ready — accept path binds when iroh transport is enabled.").dim()
    );
    // Keep process alive as a stub service.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn demo_pair() -> Result<()> {
    use mymesh_net::LocalRendezvous;
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

    // Deterministic in-process SPAKE2 ceremony with a known code.
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

/// Host pair that uses an exact code string (demo helper).
async fn run_host_pair_with_code(
    identity: &Identity,
    label: &str,
    capabilities: Vec<Capability>,
    store: &mut DeviceStore,
    rendezvous: &impl mymesh_net::Rendezvous,
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
                fingerprint: NodeFingerprint::from_device_id(&peer_id)
                    .as_str()
                    .to_string(),
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
    use mymesh_net::{LocalFabric, Transport};
    use mymesh_protocol::{encode_msg, ChannelId, TerminalMessage};
    use mymesh_session::Session;

    demo_pair().await?;

    let fabric = LocalFabric::new();
    let host_id = Identity::generate();
    let guest_id = Identity::generate();
    // Build trust stores
    let dir = tempfile_dir()?;
    let host_paths = sub_paths(&dir, "host2")?;
    let guest_paths = sub_paths(&dir, "guest2")?;
    let mut host_store = DeviceStore::open(host_paths.devices_file())?;
    let mut guest_store = DeviceStore::open(guest_paths.devices_file())?;

    // Manually trust each other
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

    let host_hs = Session::handshake(host_conn, &host_id, "host", &host_store, Capability::all());
    let guest_hs = Session::handshake(
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

## One-liner (eventually)
curl -fsSL https://raw.githubusercontent.com/jtwolfe/MyMesh/main/install.sh | sh

## From source
cargo install --path crates/mymesh-cli

## systemd user service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/mymesh.service <<'UNIT'
[Unit]
Description=MyMesh peer agent
After=network-online.target

[Service]
ExecStart=%h/.cargo/bin/mymesh serve --foreground
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now mymesh.service

## Pairing
# on machine A
mymesh link
# on machine B
mymesh link 42-maple-orbit

## Use
mymesh shell <device>
mymesh cp ./file <device>:~/file
mymesh desktop <device>
"#
    );
}
