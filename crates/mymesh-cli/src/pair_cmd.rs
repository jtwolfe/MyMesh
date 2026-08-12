//! Pair v2 CLI: dual-scan + confirm-on-machine (PAIR-V2.md / A3b+A5).
//!
//! ```text
//! mymesh pair dual [--host <url>] [--tlspin sha256/…] [--ttl N]
//! mymesh pair dual --join --resident <id|words>
//! mymesh pair confirm <code> [--sid] [--joiner]
//! mymesh pair status [--sid]
//! mymesh pair retry [sid]
//! ```
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use console::style;
use mymesh_core::{
apply_pair_confirm, parse_tls_pin, record_pair_decide, require_https_when_pinned, ArmState,
    Config, JoinDecision, JoinStore, MeshState, NodeFingerprint, PairEndpointClass, PairPhase,
    PairSessionStore, Paths,
};
use mymesh_crypto::{parse_device_id, Identity};
use mymesh_session::{build_pair_qr_v2_checked, run_join_as_guest, PairQrV2Params};
use qrcode::QrCode;

use crate::mesh_conn;

/// Resident: arm join window, mint PairSession, print QR_A v2 (required nonce).
///
/// Optional `--tlspin` (SPKI pin) requires `--host https://…` (fail closed **before** arm).
pub async fn cmd_pair_dual(
    paths: &Paths,
    host: Option<String>,
    ttl: Option<u64>,
    tlspin: Option<String>,
) -> Result<()> {
    paths.ensure()?;
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file()).unwrap_or_default();
    let ttl = ttl.unwrap_or(cfg.limits.arm_timeout_secs);

    // Fail closed before arming: pin format + HTTPS policy (no orphan session / arm TTL burn).
    let pin_parsed = match tlspin.as_deref() {
        Some(raw) if !raw.is_empty() => {
            Some(parse_tls_pin(raw).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        Some(_) => bail!("tls pin is empty"),
        None => None,
    };
    require_https_when_pinned(pin_parsed.as_ref(), host.as_deref())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pin_wire = pin_parsed.as_ref().map(|p| p.to_wire());

    // Arm join window so serve accepts JoinRequest.
    let arm = ArmState::arm(paths.arm_file(), ttl)?;
    let mesh = MeshState::load(paths.mesh_file())?;
    let store = PairSessionStore::open(paths.pair_sessions_dir())?;

    let ep = if host.is_some() {
        PairEndpointClass::Direct
    } else {
        PairEndpointClass::Confirm
    };
    let mut armed = store.arm_new(mesh.mesh_id.clone(), identity.device_id(), ttl, ep)?;

    let token_b64 = URL_SAFE_NO_PAD.encode(armed.token_raw);
    let did = identity.device_id().to_string();
    let fp = NodeFingerprint::from_device_id(&identity.device_id())
        .as_str()
        .to_string();
    // Checked emit (format already validated; re-checks HTTPS + emits canonical pin).
    let qr = build_pair_qr_v2_checked(&PairQrV2Params {
        sid: &armed.session.sid,
        did: &did,
        token: &token_b64,
        nonce: &armed.session.nonce,
        fp: &fp,
        mesh: Some(&mesh.mesh_id),
        host: host.as_deref(),
        ep: Some(ep),
        relay: None,
        tlspin: pin_wire.as_deref(),
    })
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Persist pin only after successful QR emit (session advertises what the QR carried).
    if let Some(ref pin) = pin_wire {
        armed.session.tls_pin = Some(pin.clone());
        store.save(&armed.session)?;
    }

    println!("{}", style("pair dual — resident QR_A (v2)").bold());
    println!("  sid     {}", armed.session.sid);
    println!("  did     {}", identity.device_id().short());
    println!("  fp      {fp}");
    println!("  ep      {}", ep.as_str());
    println!("  until   {:?}", arm.until);
    println!("  phase   {}", armed.session.phase.as_str());
    if let Some(h) = &host {
        println!("  host    {h}");
    } else {
        println!(
            "  mode    confirm-on-machine (no host) — after joiner dials: mymesh pair confirm <code>"
        );
    }
    if let Some(ref pin) = pin_wire {
        println!("  tlspin  {pin}");
    }
    println!();
    println!("  {}", qr);
    if let Ok(code) = QrCode::new(qr.as_bytes()) {
        let rendered = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{rendered}");
    }
    println!();
    println!("Ensure `mymesh serve` is running on this machine.");
    println!(
        "Joiner:  mymesh pair dual --join --resident {}",
        identity.device_id()
    );
    println!("Then:    mymesh pair confirm <code>   # code from phone after dual-scan");
    Ok(())
}

/// Joiner: print QR_B and dial resident join path.
pub async fn cmd_pair_dual_join(paths: &Paths, resident: &str) -> Result<()> {
    paths.ensure()?;
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let mut store = mymesh_core::DeviceStore::open(paths.devices_file())?;
    let host_id = parse_device_id(resident).context("parse --resident")?;

    let did = identity.device_id().to_string();
    let fp = NodeFingerprint::from_device_id(&identity.device_id())
        .as_str()
        .to_string();
    let label = cfg.device_label.clone();
    // Phone-only peer QR (not pair HTTP bootstrap).
    let qr_b = format!(
        "mymesh://pair-peer?v=1&did={}&fp={}&label={}",
        percent_encode(&did),
        percent_encode(&fp),
        percent_encode(&label),
    );

    println!("{}", style("pair dual — joiner QR_B").bold());
    println!("  did     {}", identity.device_id().short());
    println!("  fp      {fp}");
    println!("  label   {label}");
    println!("  toward  {}", host_id.short());
    println!();
    println!("  {qr_b}");
    if let Ok(code) = QrCode::new(qr_b.as_bytes()) {
        let rendered = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{rendered}");
    }
    println!();
    println!("dialing join to {}…", style(host_id.short()).cyan());

    let (conn, transport) = mesh_conn::connect_raw(&identity, &cfg, host_id).await?;
    let peer = run_join_as_guest(
        conn,
        &identity,
        &cfg.device_label,
        &mut store,
        &paths.mesh_file(),
        mymesh_core::Capability::all(),
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

/// Confirm-on-machine: verify HMAC code, write JoinStore decision (fail-closed).
pub async fn cmd_pair_confirm(
    paths: &Paths,
    code: &str,
    sid: Option<String>,
    joiner: Option<String>,
) -> Result<()> {
    paths.ensure()?;
    let store = PairSessionStore::open(paths.pair_sessions_dir())?;
    let joins = JoinStore::open(paths.join_dir())?;

    let joiner_id = if let Some(j) = joiner.as_deref() {
        Some(parse_device_id(j).context("--joiner")?)
    } else {
        None
    };

    match apply_pair_confirm(&store, &joins, code, sid.as_deref(), joiner_id) {
        Ok(res) => {
            let kind = match &res.decision {
                JoinDecision::Accept => "accept",
                JoinDecision::Deny { .. } => "deny",
            };
            record_pair_decide(paths.metrics_dir(), kind);
            println!(
                "{} pair confirm {kind} for joiner {} (sid {})",
                style("ok").green().bold(),
                res.joiner.short(),
                res.session.sid
            );
            println!("  phase {}", res.session.phase.as_str());
            if matches!(res.decision, JoinDecision::Accept) {
                println!("  join host loop will complete Trusted + membership");
            }
            Ok(())
        }
        Err(e) => {
            // S9 metrics: bad_code / rate_limited results on decide/confirm path.
            let code = e.code();
            if matches!(code, "bad_code" | "rate_limited") {
                record_pair_decide(paths.metrics_dir(), code);
            }
            eprintln!("{} {}", style("error").red().bold(), e);
            // Map to process exit via bail so main returns non-zero.
            bail!("{}", code);
        }
    }
}

/// Show active pair session status.
pub async fn cmd_pair_status(paths: &Paths, sid: Option<String>) -> Result<()> {
    paths.ensure()?;
    let store = PairSessionStore::open(paths.pair_sessions_dir())?;
    let sess = if let Some(sid) = sid.as_deref() {
        store
            .load(sid)?
            .with_context(|| format!("pair session {sid}"))?
    } else if let Some(s) = store.active_session()? {
        s
    } else {
        println!("No active pair session.");
        return Ok(());
    };

    let phase = sess.effective_phase();
    println!("{}", style("pair session").bold());
    println!("  sid       {}", sess.sid);
    println!("  phase     {}", phase.as_str());
    println!("  ep        {}", sess.ep.as_str());
    println!("  mesh      {}", sess.mesh_id);
    println!("  resident  {}", sess.resident_device_id.short());
    println!("  until     {}", sess.until);
    if let Some(j) = sess.joiner_device_id {
        println!("  joiner    {} ({})", j.short(), j);
        if let Some(l) = &sess.joiner_label {
            println!("  label     {l}");
        }
    } else {
        println!("  joiner    (not bound)");
    }
    println!("  confirm   consumed={}", sess.confirm_consumed);
    if let Some(pin) = &sess.tls_pin {
        println!("  tlspin    {pin}");
    }
    if let Some(d) = &sess.decision {
        println!("  decision  {d:?}");
    }

    let joins = JoinStore::open(paths.join_dir())?;
    let pending = joins.list_pending()?;
    if !pending.is_empty() {
        println!("  pending joins:");
        for p in pending {
            println!("    {}  {}", p.device_id.short(), p.label);
        }
    }
    Ok(())
}

/// Expire a failed/stale session and arm a fresh dual (retry).
pub async fn cmd_pair_retry(paths: &Paths, sid: Option<String>) -> Result<()> {
    paths.ensure()?;
    let store = PairSessionStore::open(paths.pair_sessions_dir())?;
    let target = if let Some(sid) = sid.as_deref() {
        store.load(sid)?
    } else {
        store.active_session()?
    };
    if let Some(mut s) = target {
        s.phase = PairPhase::Expired;
        s.updated_at = chrono::Utc::now();
        store.save(&s)?;
        let _ = store.clear_token_raw(&s.sid);
        println!(
            "{} expired previous session {}",
            style("ok").green().bold(),
            s.sid
        );
    }
    // Fresh dual arm (confirm ep, no host).
    cmd_pair_dual(paths, None, None, None).await
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
