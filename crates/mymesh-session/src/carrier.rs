//! Connect-by-carrier: local web page + pair/v1 + pair/v2 + mesh/v1 HTTP.
//!
//! Port 17878 (default). After F4p / KD-F16, **`mymesh serve` binds this router**
//! in-process. `mymesh carrier` is lab-only if serve is down.
//! Serves deprecated HTML (`/`, `/api/*`) and machine API under `/pair/v1`
//! (status / pending / decide), `/pair/v2`, and `/mesh/v1` (auth challenge +
//! topology) using the same `Paths` as serve.
//! PairSessionStore is source of truth for v2 (PAIR-V2.md).
//!
//! **Default bootstrap QR is pair/v2** (KD23 / D5) with LAN `host` + `ep=direct`.
//! Pass `pair_v1: true` (`mymesh carrier --pair-v1`) for the alpha.1 LAN v1 QR escape.
//! TUI arms QR via MMA1 (`arm_pair_qr`) when serve owns the port.
use axum::extract::{ConnectInfo, FromRequestParts, Query, State};
use axum::http::{header, request::Parts, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use mymesh_core::wire::{EnrollWriteBody, PersonFacet};
use mymesh_core::{
    client_ip_key, hash_pair_token, record_pair_decide, record_pair_status, ArmState, Config,
    DeviceId, EnrollmentStore, JoinDecision, JoinStore, LimitKind, MeshState, NodeFingerprint,
    PairEndpointClass, PairPhase, PairSessionFile, PairSessionStore, Paths, PendingJoin,
    RateLimitState,
};
use mymesh_crypto::{device_id_to_words, device_join_uri, Identity};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::join::spawn_join_as_guest_to_resident;
use crate::mesh_api::{self, MeshApiState, MeshAuthStore};
use async_trait::async_trait;
use mymesh_net::LocalAdmin;

/// Pair HTTP listen port (matches `CARRIER_TCP` / PAIR-HTTP.md).
pub const PAIR_HTTP_PORT: u16 = 17878;
/// Path prefix for the machine pair API (v1, alpha.1).
pub const PAIR_V1_PREFIX: &str = "/pair/v1";
/// Path prefix for pair control plane v2.
pub const PAIR_V2_PREFIX: &str = "/pair/v2";
/// Timestamp skew allowed for SessionDecision.ts (±5 minutes).
const DECIDE_TS_SKEW_SECS: i64 = 5 * 60;

#[derive(Clone)]
struct CarrierState {
    paths: Paths,
    secret: [u8; 32],
    label: String,
    pending_peer: Arc<Mutex<Option<String>>>,
    status: Arc<Mutex<String>>,
    /// Arm-scoped bootstrap secret (raw 32 bytes). None when disarmed/expired.
    bootstrap: Arc<Mutex<Option<BootstrapToken>>>,
    /// In-memory mesh/v1 auth challenges + sessions.
    mesh_auth: Arc<Mutex<MeshAuthStore>>,
    /// S9 in-process rate limits (IP-scoped status/challenge; isolated per process).
    rate_limits: Arc<RateLimitState>,
}

#[derive(Clone)]
struct BootstrapToken {
    raw: [u8; 32],
    until: DateTime<Utc>,
}

impl CarrierState {
    fn identity(&self) -> Identity {
        Identity::from_secret_bytes(self.secret)
    }
}

#[derive(Deserialize)]
struct PeerBody {
    uri: String,
}

#[derive(Serialize)]
struct StatusBody {
    status: String,
    local_uri: String,
    local_label: String,
}

// --- pair/v1 wire types (MyMesh-local; match carrier-core::wire::pair) ---

#[derive(Serialize)]
struct HostPairStatus {
    protocol_version: u32,
    mesh_id: String,
    host_label: String,
    host_device_id_hex: String,
    host_fingerprint: String,
    host_short_id: String,
    armed: bool,
    arm_until: String,
    auth_mode: &'static str,
}

#[derive(Serialize)]
struct PendingJoinWire {
    device_id_hex: String,
    short_id: String,
    label: String,
    fingerprint: String,
    words: String,
    capabilities: Vec<mymesh_core::Capability>,
    received_at: String,
}

#[derive(Serialize)]
struct PendingListResponse {
    pending: Vec<PendingJoinWire>,
}

#[derive(Debug, Deserialize)]
struct DecideRequest {
    device_id_hex: String,
    decision: DecideKind,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DecideKind {
    Accept,
    Deny,
}

#[derive(Serialize)]
struct DecideResponse {
    ok: bool,
    state: &'static str,
}

#[derive(Serialize)]
struct PairErrorBody {
    error: String,
    code: &'static str,
}

#[derive(Serialize, Deserialize)]
struct BootstrapPersist {
    token: String,
    until: DateTime<Utc>,
}

/// Default arm / pair-session TTL used when carrier starts (seconds).
const CARRIER_ARM_TTL_SECS: u64 = 900;
/// MMA1 default TTL when the request omits `ttl_secs`.
const MMA1_ARM_TTL_SECS: u64 = 600;

pub struct PairHttpHandle {
    /// HTML page URL (deprecated fallback).
    pub url: String,
    pub bind: SocketAddr,
    /// Base `http://IP:port` for pair API (no trailing slash).
    pub host_base: String,
    /// Arm-scoped v1 bootstrap token if join is currently armed.
    pub v1_bootstrap_token: Option<String>,
}

pub struct CarrierHandle {
    /// HTML page URL (deprecated fallback).
    pub url: String,
    pub bind: SocketAddr,
    /// Base `http://IP:port` for pair API (no trailing slash).
    pub host_base: String,
    /// Bootstrap token embedded in `pair_qr` (base64url, no padding).
    ///
    /// For default v2 this is the PairSessionStore arm token; for `--pair-v1`
    /// it is the arm-scoped v1 bootstrap secret.
    pub bootstrap_token: String,
    /// Deep link for phone scan.
    ///
    /// Default (D5 / KD23): `carrier://pair?v=2&sid&did&token&nonce&fp&ep=direct&host&mesh?`
    /// Escape (`pair_v1`): `carrier://pair?v=1&host&token&fp&mesh?`
    pub pair_qr: String,
    /// Protocol version of `pair_qr` (`1` or `2`).
    pub pair_protocol_version: u32,
}

/// Bind pair/v2 + mesh/v1 (and compat pair/v1) without minting a QR.
///
/// Serve owns this listener (KD-F16). QR is armed later via [`arm_pair_qr`] / MMA1.
pub async fn start_pair_http(
    paths: Paths,
    identity: &Identity,
    label: String,
    port: u16,
    lan_ip: Option<String>,
) -> anyhow::Result<PairHttpHandle> {
    paths.ensure()?;

    let bootstrap = Arc::new(Mutex::new(None));
    let rate_limits = Arc::new(RateLimitState::new());
    let label_for_poller = label.clone();
    let st = CarrierState {
        paths: paths.clone(),
        secret: identity.to_secret_bytes(),
        label,
        pending_peer: Arc::new(Mutex::new(None)),
        status: Arc::new(Mutex::new("waiting for phone".into())),
        bootstrap: bootstrap.clone(),
        mesh_auth: Arc::new(Mutex::new(MeshAuthStore::default())),
        rate_limits,
    };

    // Keep arm-scoped v1 bootstrap if already armed (compat /pair/v1).
    let v1_bootstrap_token = {
        let mut guard = st.bootstrap.lock().await;
        ensure_bootstrap_locked(&st.paths, &mut guard).ok()
    };

    let app = build_router(st);

    let bind: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let actual = listener.local_addr()?;
    let host = lan_ip.unwrap_or_else(|| local_ipv4().unwrap_or_else(|| "127.0.0.1".into()));
    let url = format!("http://{host}:{}/", actual.port());
    let host_base = format!("http://{host}:{}", actual.port());

    info!(
        %url,
        %host_base,
        "pair/v2 + mesh/v1 listening (serve-owned)"
    );

    if let Ok(cfg) = mymesh_core::Config::load(paths.config_file()) {
        if let Some(mailbox_url) = cfg.admin_mailbox_url() {
            crate::spawn_admin_mailbox_poller(
                paths.clone(),
                identity.to_secret_bytes(),
                label_for_poller,
                mailbox_url,
            );
        }
    }

    tokio::spawn(async move {
        // ConnectInfo peer IP for S9 IP-scoped rate limits (not client-spoofable XFF).
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::warn!(%e, "pair/mesh HTTP server exit");
        }
    });

    Ok(PairHttpHandle {
        url,
        bind: actual,
        host_base,
        v1_bootstrap_token,
    })
}

/// Mint a pair/v2 session + QR_A (`host` is for the QR payload only — do not render).
pub fn arm_pair_qr(
    paths: &Paths,
    identity: &Identity,
    ttl_secs: u64,
    host_base: &str,
) -> anyhow::Result<ArmPairQr> {
    paths.ensure()?;
    let ttl = ttl_secs.clamp(1, 86_400);
    let _ = ArmState::arm(paths.arm_file(), ttl);
    let store = PairSessionStore::open(paths.pair_sessions_dir())?;
    let id = identity.device_id();
    let mesh_id = MeshState::load(paths.mesh_file())?.mesh_id;
    let armed = store.arm_new(mesh_id.clone(), id, ttl, PairEndpointClass::Direct)?;
    let token_b64 = URL_SAFE_NO_PAD.encode(armed.token_raw);
    let fp = NodeFingerprint::from_device_id(&id).as_str().to_string();
    let qr = build_pair_qr_v2(&PairQrV2Params {
        sid: &armed.session.sid,
        did: &id.to_string(),
        token: &token_b64,
        nonce: &armed.session.nonce,
        fp: &fp,
        mesh: Some(&mesh_id),
        host: Some(host_base),
        ep: Some(PairEndpointClass::Direct),
        relay: None,
        tlspin: None,
    });
    Ok(ArmPairQr {
        qr,
        sid: armed.session.sid,
        host_base: host_base.to_string(),
        token_b64,
    })
}

/// Result of [`arm_pair_qr`].
pub struct ArmPairQr {
    pub qr: String,
    pub sid: String,
    pub host_base: String,
    pub token_b64: String,
}

/// MMA1 handler used by `mymesh serve` (arm QR without a second HTTP bind).
pub struct PairArmAdmin {
    pub paths: Paths,
    pub secret: [u8; 32],
    pub host_base: Arc<Mutex<String>>,
}

#[async_trait]
impl LocalAdmin for PairArmAdmin {
    async fn handle(&self, request: serde_json::Value) -> serde_json::Value {
        match request.get("cmd").and_then(|c| c.as_str()) {
            Some("arm_pair_qr") => {
                let ttl = request
                    .get("ttl_secs")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(MMA1_ARM_TTL_SECS);
                let host_base = self.host_base.lock().await.clone();
                let identity = Identity::from_secret_bytes(self.secret);
                match arm_pair_qr(&self.paths, &identity, ttl, &host_base) {
                    Ok(armed) => serde_json::json!({
                        "ok": true,
                        "qr": armed.qr,
                        "sid": armed.sid,
                        "host_base": armed.host_base
                    }),
                    Err(e) => serde_json::json!({
                        "ok": false,
                        "code": "internal",
                        "error": e.to_string()
                    }),
                }
            }
            _ => serde_json::json!({
                "ok": false,
                "code": "bad_request",
                "error": "unknown cmd"
            }),
        }
    }
}

/// Start carrier HTTP facade + emit bootstrap QR.
///
/// * `pair_v1 == false` (default product path): mint a **pair/v2** PairSession
///   (`ep=direct`) and print a v2 QR that includes LAN `host`.
/// * `pair_v1 == true` (`mymesh carrier --pair-v1`): emit alpha.1 **v1** LAN QR
///   using the arm-scoped bootstrap token (escape hatch during compat window).
///
/// `/pair/v1/*` and `/pair/v2/*` endpoints are both served regardless of QR version.
/// Lab-only when serve is down — serve owns `:17878` after F4p.
pub async fn start_carrier(
    paths: Paths,
    identity: Identity,
    label: String,
    port: u16,
    lan_ip: Option<String>,
    pair_v1: bool,
) -> anyhow::Result<CarrierHandle> {
    paths.ensure()?;
    // Always refresh arm window so join arm TTL aligns with PairSession / QR.
    // Restart prints a new QR; residual short arms must not outlive the new session
    // (join host path requires ArmState; status.armed = arm && session open).
    let _ = ArmState::arm(paths.arm_file(), CARRIER_ARM_TTL_SECS);

    let http = start_pair_http(paths.clone(), &identity, label, port, lan_ip).await?;
    let id = identity.device_id();
    let fp = NodeFingerprint::from_device_id(&id).as_str().to_string();
    let mesh_id = MeshState::load(paths.mesh_file())?.mesh_id;

    let (pair_qr, bootstrap_token, pair_protocol_version) = if pair_v1 {
        let v1_token_b64 = http
            .v1_bootstrap_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("v1 bootstrap missing after arm"))?;
        (
            build_pair_qr(&http.host_base, &v1_token_b64, &fp, Some(&mesh_id)),
            v1_token_b64,
            1u32,
        )
    } else {
        let armed = arm_pair_qr(&paths, &identity, CARRIER_ARM_TTL_SECS, &http.host_base)?;
        (armed.qr, armed.token_b64, 2u32)
    };

    info!(
        url = %http.url,
        host_base = %http.host_base,
        pair_v = pair_protocol_version,
        "carrier + pair/v1 + pair/v2 + mesh/v1 listening"
    );

    Ok(CarrierHandle {
        url: http.url,
        bind: http.bind,
        host_base: http.host_base,
        bootstrap_token,
        pair_qr,
        pair_protocol_version,
    })
}

fn build_router(st: CarrierState) -> Router {
    let mesh_st = MeshApiState {
        paths: st.paths.clone(),
        secret: st.secret,
        label: st.label.clone(),
        auth: st.mesh_auth.clone(),
        rate_limits: st.rate_limits.clone(),
    };
    let pair_app = Router::new()
        // Deprecated HTML / phone-paste fallback
        .route("/", get(page))
        .route("/api/status", get(api_status))
        .route("/api/peer", post(api_peer))
        .route("/api/local", get(api_local))
        // pair/v1 machine API (compat window; QR escape via --pair-v1)
        .route("/pair/v1/status", get(pair_status))
        .route("/pair/v1/pending", get(pair_pending))
        .route("/pair/v1/decide", post(pair_decide))
        // pair/v2 control plane (PairSessionStore; default QR after D5)
        .route("/pair/v2/status", get(pair_v2_status))
        .route("/pair/v2/pending", get(pair_v2_pending))
        .route("/pair/v2/decide", post(pair_v2_decide))
        // Phone introducer: tell this node to dial a resident (same path as `mymesh link`).
        .route("/pair/v2/dial", post(pair_v2_dial))
        .with_state(st);
    // mesh/v1 auth challenge + topology (Issue 4 / B3) — separate state type, merge after
    pair_app
        .merge(mesh_api::mesh_v1_routes(mesh_st))
        .layer(CorsLayer::permissive())
}

/// Build `carrier://pair?v=1&host=…&token=…&fp=…&mesh?…` deep link.
pub fn build_pair_qr(host_base: &str, token: &str, fp: &str, mesh: Option<&str>) -> String {
    let mut q = format!(
        "carrier://pair?v=1&host={}&token={}&fp={}",
        percent_encode(host_base),
        percent_encode(token),
        percent_encode(fp)
    );
    if let Some(m) = mesh {
        if !m.is_empty() {
            q.push_str("&mesh=");
            q.push_str(&percent_encode(m));
        }
    }
    q
}

/// Parameters for a v2 pair bootstrap QR (`carrier://pair?v=2&…`).
///
/// `nonce` is **required** (16 raw bytes). `host` is optional — absent ⇒ `ep=confirm`.
/// Optional `tlspin` (SPKI pin) requires HTTPS host — validated by the **caller** or
/// [`build_pair_qr_v2_checked`] (the unchecked builder does not enforce pin policy).
#[derive(Clone, Debug)]
pub struct PairQrV2Params<'a> {
    pub sid: &'a str,
    pub did: &'a str,
    pub token: &'a str,
    /// 16 raw session nonce bytes (encoded as base64url no pad on the wire).
    pub nonce: &'a [u8; 16],
    pub fp: &'a str,
    pub mesh: Option<&'a str>,
    /// Optional direct host base URL (`http://ip:port` or `https://…`). When set, `ep` defaults to direct.
    pub host: Option<&'a str>,
    pub ep: Option<PairEndpointClass>,
    pub relay: Option<&'a str>,
    /// Optional TLS SPKI pin wire form (`sha256/…`). When set, host must be HTTPS.
    pub tlspin: Option<&'a str>,
}

/// Build v2 pair QR. Call sites must supply a real session nonce (KD27).
///
/// Does **not** validate `tlspin` policy — use [`build_pair_qr_v2_checked`] for
/// fail-closed HTTPS + pin format checks (CLI / product emit path).
///
/// ```text
/// carrier://pair?v=2&sid=…&did=…&token=…&nonce=…&fp=…
///              &ep=direct|confirm|relay
///              &host=<optional>
///              &mesh=<optional>
///              &relay=<optional>
///              &tlspin=<optional sha256/…>
/// ```
pub fn build_pair_qr_v2(p: &PairQrV2Params<'_>) -> String {
    let nonce_b64 = URL_SAFE_NO_PAD.encode(p.nonce);
    let ep = p.ep.unwrap_or(if p.host.is_some() {
        PairEndpointClass::Direct
    } else {
        PairEndpointClass::Confirm
    });
    let mut q = format!(
        "carrier://pair?v=2&sid={}&did={}&token={}&nonce={}&fp={}&ep={}",
        percent_encode(p.sid),
        percent_encode(p.did),
        percent_encode(p.token),
        percent_encode(&nonce_b64),
        percent_encode(p.fp),
        ep.as_str(),
    );
    if let Some(h) = p.host {
        if !h.is_empty() {
            q.push_str("&host=");
            q.push_str(&percent_encode(h));
        }
    }
    if let Some(m) = p.mesh {
        if !m.is_empty() {
            q.push_str("&mesh=");
            q.push_str(&percent_encode(m));
        }
    }
    if let Some(r) = p.relay {
        if !r.is_empty() {
            q.push_str("&relay=");
            q.push_str(&percent_encode(r));
        }
    }
    if let Some(pin) = p.tlspin {
        if !pin.is_empty() {
            q.push_str("&tlspin=");
            q.push_str(&percent_encode(pin));
        }
    }
    q
}

/// Build v2 QR after validating optional `tlspin` format and HTTPS policy.
///
/// Fail closed: invalid pin format or pin without `https://` host → `Err`.
pub fn build_pair_qr_v2_checked(
    p: &PairQrV2Params<'_>,
) -> std::result::Result<String, mymesh_core::TlsPinError> {
    let pin = match p.tlspin {
        Some(s) if !s.is_empty() => Some(mymesh_core::parse_tls_pin(s)?),
        _ => None,
    };
    mymesh_core::require_https_when_pinned(pin.as_ref(), p.host)?;
    // Re-emit canonical wire form when pin present.
    let wire;
    let mut params = p.clone();
    if let Some(ref pin) = pin {
        wire = pin.to_wire();
        params.tlspin = Some(wire.as_str());
    }
    Ok(build_pair_qr_v2(&params))
}

/// Encode 16B nonce as base64url (no padding) for status / SessionDecision wire.
pub fn encode_pair_nonce(nonce: &[u8; 16]) -> String {
    URL_SAFE_NO_PAD.encode(nonce)
}

/// Decode base64url nonce; must be exactly 16 bytes.
pub fn decode_pair_nonce(s: &str) -> Option<[u8; 16]> {
    let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&bytes);
    Some(a)
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

fn pair_bootstrap_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join("pair-bootstrap.json")
}

/// Sync in-memory bootstrap with ArmState; mint on re-arm, clear on disarm.
/// Returns current base64url token when armed.
fn ensure_bootstrap_locked(
    paths: &Paths,
    boot: &mut Option<BootstrapToken>,
) -> anyhow::Result<String> {
    let arm = ArmState::load(paths.arm_file())?;
    if !arm.is_effectively_armed() {
        *boot = None;
        let _ = std::fs::remove_file(pair_bootstrap_path(paths));
        anyhow::bail!("not armed");
    }
    let until = arm
        .until
        .ok_or_else(|| anyhow::anyhow!("armed without until"))?;

    // Keep existing token if same arm window.
    if let Some(t) = boot.as_ref() {
        if t.until == until {
            return Ok(URL_SAFE_NO_PAD.encode(t.raw));
        }
    }

    // Try restore from disk if still valid for this until.
    if let Ok(raw) = std::fs::read_to_string(pair_bootstrap_path(paths)) {
        if let Ok(p) = serde_json::from_str::<BootstrapPersist>(&raw) {
            if p.until == until {
                if let Ok(bytes) = URL_SAFE_NO_PAD.decode(p.token.as_bytes()) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        *boot = Some(BootstrapToken {
                            raw: arr,
                            until: p.until,
                        });
                        return Ok(p.token);
                    }
                }
            }
        }
    }

    // Mint fresh 32B token for this arm window.
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    *boot = Some(BootstrapToken { raw, until });
    let persist = BootstrapPersist {
        token: token.clone(),
        until,
    };
    let path = pair_bootstrap_path(paths);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(body) = serde_json::to_string_pretty(&persist) {
        let _ = std::fs::write(&path, body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(token)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let val = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = val
        .strip_prefix("Bearer ")
        .or_else(|| val.strip_prefix("bearer "))?;
    let t = rest.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Returns Ok(token_raw) if Bearer matches current arm-scoped secret.
/// Err response is ready-made HTTP error.
async fn require_bootstrap(st: &CarrierState, headers: &HeaderMap) -> Result<[u8; 32], Response> {
    let presented = match extract_bearer(headers) {
        Some(t) => t,
        None => {
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or malformed Authorization Bearer",
            ));
        }
    };
    let presented_bytes = match URL_SAFE_NO_PAD.decode(presented.as_bytes()) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        _ => {
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid bootstrap token encoding",
            ));
        }
    };

    let mut guard = st.bootstrap.lock().await;
    // Sync with arm (invalidate on disarm / mint on re-arm).
    match ensure_bootstrap_locked(&st.paths, &mut guard) {
        Ok(_) => {}
        Err(_) => {
            // Not armed → token invalidated → 401 (not not_armed).
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "bootstrap token invalidated (disarmed or expired)",
            ));
        }
    }
    let Some(boot) = guard.as_ref() else {
        return Err(pair_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "no bootstrap token",
        ));
    };
    if !ct_eq(&boot.raw, &presented_bytes) {
        return Err(pair_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "bootstrap token mismatch",
        ));
    }
    // Narrow race: token matches current secret but arm flipped off mid-check.
    let arm = ArmState::load(st.paths.arm_file()).unwrap_or_default();
    if !arm.is_effectively_armed() {
        *guard = None;
        let _ = std::fs::remove_file(pair_bootstrap_path(&st.paths));
        return Err(pair_err(
            StatusCode::FORBIDDEN,
            "not_armed",
            "host is not armed for accept",
        ));
    }
    Ok(boot.raw)
}

fn pair_err(status: StatusCode, code: &'static str, error: impl Into<String>) -> Response {
    (
        status,
        Json(PairErrorBody {
            error: error.into(),
            code,
        }),
    )
        .into_response()
}

fn pair_rate_limited(retry_after_secs: u64) -> Response {
    let mut resp = pair_err(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        format!("rate limit exceeded; retry after {retry_after_secs}s"),
    );
    let hv = header::HeaderValue::from_str(&retry_after_secs.to_string())
        .unwrap_or_else(|_| header::HeaderValue::from_static("60"));
    resp.headers_mut().insert(header::RETRY_AFTER, hv);
    resp
}

/// Optional TCP peer (present when served with `into_make_service_with_connect_info`).
struct OptionalPeer(Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalPeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(OptionalPeer(peer))
    }
}

/// IP rate-limit key: peer addr primary; XFF only if `MYMESH_TRUST_PROXY` (see core).
fn rate_limit_ip(peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let rip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    client_ip_key(peer, xff, rip)
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// --- pair/v1 handlers ---

async fn pair_status(
    State(st): State<CarrierState>,
    OptionalPeer(peer): OptionalPeer,
    headers: HeaderMap,
) -> Response {
    let ip = rate_limit_ip(peer, &headers);
    if let Err(rl) = st.rate_limits.check(LimitKind::PairStatus, &ip) {
        record_pair_status(st.paths.metrics_dir());
        return pair_rate_limited(rl.retry_after_secs);
    }
    record_pair_status(st.paths.metrics_dir());

    let id = st.identity().device_id();
    let mesh = match MeshState::load(st.paths.mesh_file()) {
        Ok(m) => m,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("mesh load: {e}"),
            );
        }
    };
    let cfg = Config::load(st.paths.config_file()).unwrap_or_else(|_| Config {
        device_label: st.label.clone(),
        ..Config::default()
    });
    let arm = ArmState::load(st.paths.arm_file()).unwrap_or_default();
    let armed = arm.is_effectively_armed();
    let arm_until = arm.until.map(rfc3339).unwrap_or_default();

    // Keep bootstrap in sync so re-arm from another process refreshes secret.
    {
        let mut guard = st.bootstrap.lock().await;
        let _ = ensure_bootstrap_locked(&st.paths, &mut guard);
    }

    Json(HostPairStatus {
        protocol_version: 1,
        mesh_id: mesh.mesh_id,
        host_label: cfg.device_label,
        host_device_id_hex: id.to_string(),
        host_fingerprint: NodeFingerprint::from_device_id(&id).as_str().to_string(),
        host_short_id: id.short(),
        armed,
        arm_until,
        auth_mode: "bootstrap_token",
    })
    .into_response()
}

async fn pair_pending(State(st): State<CarrierState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_bootstrap(&st, &headers).await {
        return resp;
    }
    let joins = match JoinStore::open(st.paths.join_dir()) {
        Ok(j) => j,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("join store: {e}"),
            );
        }
    };
    let list = match joins.list_pending() {
        Ok(p) => p,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("list pending: {e}"),
            );
        }
    };
    let pending: Vec<PendingJoinWire> = list
        .into_iter()
        .map(|p: PendingJoin| {
            // words derived at serialize time — not stored on PendingJoin
            let words = device_id_to_words(&p.device_id).unwrap_or_default();
            PendingJoinWire {
                device_id_hex: p.device_id.to_string(),
                short_id: p.device_id.short(),
                label: p.label,
                fingerprint: p.fingerprint,
                words,
                capabilities: p.capabilities,
                received_at: rfc3339(p.received_at),
            }
        })
        .collect();
    Json(PendingListResponse { pending }).into_response()
}

async fn pair_decide(
    State(st): State<CarrierState>,
    headers: HeaderMap,
    Json(body): Json<DecideRequest>,
) -> Response {
    let token_raw = match require_bootstrap(&st, &headers).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // S9: 10 / min / token — file-backed so CLI confirm shares budget.
    let token_key = hash_pair_token(&token_raw);
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        st.paths.metrics_dir(),
        LimitKind::PairDecide,
        &token_key,
    ) {
        record_pair_decide(st.paths.metrics_dir(), "rate_limited");
        return pair_rate_limited(rl.retry_after_secs);
    }

    let device_id: DeviceId = match body.device_id_hex.parse() {
        Ok(id) => id,
        Err(_) => {
            return pair_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "device_id_hex must be 64 hex chars",
            );
        }
    };

    let joins = match JoinStore::open(st.paths.join_dir()) {
        Ok(j) => j,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("join store: {e}"),
            );
        }
    };

    // not_found if no pending file for this id (no label rename on decide).
    let pending = match joins.list_pending() {
        Ok(p) => p,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("list pending: {e}"),
            );
        }
    };
    if !pending.iter().any(|p| p.device_id == device_id) {
        record_pair_decide(st.paths.metrics_dir(), "not_found");
        return Json(DecideResponse {
            ok: true,
            state: "not_found",
        })
        .into_response();
    }

    // JoinDecision is only Accept | Deny — host keeps joiner-supplied label.
    let (decision, state) = match body.decision {
        DecideKind::Accept => (JoinDecision::Accept, "accepted"),
        DecideKind::Deny => (
            JoinDecision::Deny {
                reason: body.reason.unwrap_or_else(|| "denied by carrier".into()),
            },
            "denied",
        ),
    };
    if let Err(e) = joins.write_decision(&device_id, decision) {
        return pair_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("write decision: {e}"),
        );
    }
    // Drop pending immediately so GET /pending no longer lists it (align mock;
    // prevents double-decide overwrite). take_decision still finds the decision file.
    let _ = std::fs::remove_file(joins.pending_path(&device_id));
    // fingerprint + short only — never log full words
    info!(
        peer = %device_id.short(),
        decision = state,
        "pair/v1 decide written to JoinStore"
    );
    record_pair_decide(st.paths.metrics_dir(), state);
    Json(DecideResponse { ok: true, state }).into_response()
}

// --- pair/v2 wire types (PAIR-V2.md) ---

#[derive(Debug, Deserialize)]
struct StatusQuery {
    /// Optional sid; when absent, most recent active session is used.
    sid: Option<String>,
}

#[derive(Serialize)]
struct PairStatusV2 {
    protocol_version: u32,
    sid: String,
    ep: &'static str,
    mesh_id: String,
    host_label: String,
    host_device_id_hex: String,
    host_fingerprint: String,
    host_short_id: String,
    armed: bool,
    arm_until: String,
    /// Session wall-clock TTL (RFC3339).
    until: String,
    phase: &'static str,
    /// base64url of 16B session nonce (echo of QR_A).
    nonce: String,
    auth_mode: &'static str,
    joiner_device_id_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionDecisionBody {
    sid: String,
    decision: DecideKind,
    joiner_device_id_hex: String,
    resident_device_id_hex: String,
    ts: String,
    /// base64url 16B — must match session nonce.
    nonce: String,
    #[serde(default)]
    person_id: Option<String>,
    #[serde(default)]
    sig_hex: Option<String>,
    #[serde(default)]
    facet: Option<PersonFacet>,
    #[serde(default)]
    person_public_key_hex: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

impl SessionDecisionBody {
    fn enroll_fields_present(&self) -> bool {
        self.person_id.is_some()
            && self.facet.is_some()
            && self.person_public_key_hex.is_some()
            && self.sig_hex.is_some()
    }
}

/// Write `enrollments.json` only when all four enroll fields verify.
/// Bad sig / target / facet never fail pair decide. Returns whether a row was written.
fn try_enroll_from_decide(paths: &Paths, host_id: &DeviceId, body: &SessionDecisionBody) -> bool {
    if !matches!(body.decision, DecideKind::Accept) || !body.enroll_fields_present() {
        return false;
    }
    let (Some(person_id), Some(facet), Some(pk_hex), Some(sig_hex)) = (
        body.person_id.as_deref(),
        body.facet,
        body.person_public_key_hex.as_deref(),
        body.sig_hex.as_deref(),
    ) else {
        return false;
    };
    if let Err(_rl) =
        mymesh_core::rate_limit_check_shared(paths.metrics_dir(), LimitKind::EnrollWrite, person_id)
    {
        info!(person_id, "enroll_write skipped rate_limited");
        return false;
    }
    let enroll = EnrollWriteBody {
        person_id: person_id.to_string(),
        facet,
        target_device_id_hex: body.resident_device_id_hex.clone(),
        ts: body.ts.clone(),
        nonce: body.nonce.clone(),
        person_public_key_hex: pk_hex.to_string(),
        sig_hex: sig_hex.to_string(),
        label: None,
    };
    let mut store = match EnrollmentStore::open_or_create(paths.enrollments_file()) {
        Ok(s) => s,
        Err(e) => {
            info!(error = %e, "enroll_write skipped store");
            return false;
        }
    };
    match store.add(host_id, &enroll) {
        Ok(rec) => {
            info!(
                person_id = %rec.person_id,
                facet = rec.facet.as_str(),
                device = %host_id.short(),
                source = "decide",
                "enroll_write"
            );
            true
        }
        Err(e) => {
            info!(error = %e, "enroll_write skipped; pair decide continues");
            false
        }
    }
}

/// `POST /pair/v2/dial` — phone tells this node to join a resident (24-word link path).
#[derive(Debug, Deserialize)]
struct DialRequest {
    /// Resident / host device id (64 hex), same target as `mymesh link <id>`.
    resident_did: String,
    #[serde(default)]
    resident_fp: Option<String>,
}

#[derive(Serialize)]
struct DialResponse {
    ok: bool,
    /// `dialing` — join started in the background (iroh JoinRequest).
    state: &'static str,
    resident_did: String,
}

#[derive(Serialize)]
struct DecideV2Response {
    ok: bool,
    state: &'static str,
    sid: String,
    phase: &'static str,
    /// True only when this decide wrote (or refreshed) `enrollments.json`.
    enroll_written: bool,
}

#[allow(clippy::result_large_err)] // axum Response as Err is intentional for early-return handlers
fn pair_sessions(paths: &Paths) -> Result<PairSessionStore, Response> {
    PairSessionStore::open(paths.pair_sessions_dir()).map_err(|e| {
        pair_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("pair session store: {e}"),
        )
    })
}

/// Resolve Bearer → raw token bytes (32) for v2 session auth.
#[allow(clippy::result_large_err)]
fn extract_bearer_token_raw(headers: &HeaderMap) -> Result<[u8; 32], Response> {
    let presented = match extract_bearer(headers) {
        Some(t) => t,
        None => {
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or malformed Authorization Bearer",
            ));
        }
    };
    match URL_SAFE_NO_PAD.decode(presented.as_bytes()) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Ok(a)
        }
        _ => Err(pair_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid bootstrap token encoding",
        )),
    }
}

/// Load session matching Bearer token (hash compare). Optional sid must match.
#[allow(clippy::result_large_err)]
fn require_v2_session(
    paths: &Paths,
    headers: &HeaderMap,
    sid_hint: Option<&str>,
) -> Result<(PairSessionStore, PairSessionFile, [u8; 32]), Response> {
    let raw = extract_bearer_token_raw(headers)?;
    let store = pair_sessions(paths)?;
    let sess = match store.find_by_token_raw(&raw) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "bootstrap token mismatch or unknown session",
            ));
        }
        Err(e) => {
            return Err(pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("session lookup: {e}"),
            ));
        }
    };
    if let Some(want) = sid_hint {
        if sess.sid != want {
            return Err(pair_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "token does not match sid",
            ));
        }
    }
    Ok((store, sess, raw))
}

#[allow(clippy::result_large_err)]
fn resolve_status_session(
    store: &PairSessionStore,
    sid: Option<&str>,
) -> Result<Option<PairSessionFile>, Response> {
    if let Some(sid) = sid {
        return store.load(sid).map_err(|e| {
            pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("session load: {e}"),
            )
        });
    }
    store.active_session().map_err(|e| {
        pair_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("session list: {e}"),
        )
    })
}

// --- pair/v2 handlers ---

async fn pair_v2_status(
    State(st): State<CarrierState>,
    OptionalPeer(peer): OptionalPeer,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Response {
    let ip = rate_limit_ip(peer, &headers);
    if let Err(rl) = st.rate_limits.check(LimitKind::PairStatus, &ip) {
        record_pair_status(st.paths.metrics_dir());
        return pair_rate_limited(rl.retry_after_secs);
    }
    record_pair_status(st.paths.metrics_dir());

    let id = st.identity().device_id();
    let store = match pair_sessions(&st.paths) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let sess = match resolve_status_session(&store, q.sid.as_deref()) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(sess) = sess else {
        return pair_err(StatusCode::NOT_FOUND, "not_found", "no active pair session");
    };

    let cfg = Config::load(st.paths.config_file()).unwrap_or_else(|_| Config {
        device_label: st.label.clone(),
        ..Config::default()
    });
    let arm = ArmState::load(st.paths.arm_file()).unwrap_or_default();
    // Prefer session TTL for until; arm for armed flag (join window).
    let armed = arm.is_effectively_armed() && !sess.is_expired_now() && sess.phase.is_open();
    let phase = sess.effective_phase();

    Json(PairStatusV2 {
        protocol_version: 2,
        sid: sess.sid.clone(),
        ep: sess.ep.as_str(),
        mesh_id: sess.mesh_id.clone(),
        host_label: cfg.device_label,
        host_device_id_hex: id.to_string(),
        host_fingerprint: NodeFingerprint::from_device_id(&id).as_str().to_string(),
        host_short_id: id.short(),
        armed,
        arm_until: arm
            .until
            .map(rfc3339)
            .unwrap_or_else(|| rfc3339(sess.until)),
        until: rfc3339(sess.until),
        phase: phase.as_str(),
        nonce: encode_pair_nonce(&sess.nonce),
        auth_mode: "bootstrap_token",
        joiner_device_id_hex: sess.joiner_device_id.map(|d| d.to_string()),
    })
    .into_response()
}

async fn pair_v2_pending(State(st): State<CarrierState>, headers: HeaderMap) -> Response {
    let (store, sess, _) = match require_v2_session(&st.paths, &headers, None) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if sess.is_expired_now() {
        return pair_err(StatusCode::GONE, "session_gone", "pair session expired");
    }

    let joins = match JoinStore::open(st.paths.join_dir()) {
        Ok(j) => j,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("join store: {e}"),
            );
        }
    };
    let list = match joins.list_pending() {
        Ok(p) => p,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("list pending: {e}"),
            );
        }
    };

    // Bound to this sid only: if joiner set, filter; if armed, list all candidates.
    let pending: Vec<PendingJoinWire> = list
        .into_iter()
        .filter(|p| match sess.joiner_device_id {
            Some(jid) => p.device_id == jid,
            None => sess.phase == PairPhase::Armed,
        })
        .map(|p: PendingJoin| {
            let words = device_id_to_words(&p.device_id).unwrap_or_default();
            PendingJoinWire {
                device_id_hex: p.device_id.to_string(),
                short_id: p.device_id.short(),
                label: p.label,
                fingerprint: p.fingerprint,
                words,
                capabilities: p.capabilities,
                received_at: rfc3339(p.received_at),
            }
        })
        .collect();
    // silence unused when only store was needed for auth
    let _ = store;
    Json(PendingListResponse { pending }).into_response()
}

async fn pair_v2_decide(
    State(st): State<CarrierState>,
    headers: HeaderMap,
    Json(body): Json<SessionDecisionBody>,
) -> Response {
    let (store, mut sess, raw) = match require_v2_session(&st.paths, &headers, Some(&body.sid)) {
        Ok(x) => x,
        Err(r) => return r,
    };
    // S9: 10 / min / token — file-backed under metrics_dir (shared with CLI confirm).
    let token_key = hash_pair_token(&raw);
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        st.paths.metrics_dir(),
        LimitKind::PairDecide,
        &token_key,
    ) {
        record_pair_decide(st.paths.metrics_dir(), "rate_limited");
        return pair_rate_limited(rl.retry_after_secs);
    }

    if sess.sid != body.sid {
        return pair_err(StatusCode::BAD_REQUEST, "bad_request", "sid mismatch");
    }

    // Nonce bind (anti-replay across sessions).
    let Some(presented_nonce) = decode_pair_nonce(&body.nonce) else {
        return pair_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "nonce must be base64url of 16 bytes",
        );
    };
    if !mymesh_core::ct_eq(&sess.nonce, &presented_nonce) {
        return pair_err(
            StatusCode::CONFLICT,
            "conflict",
            "nonce does not match session",
        );
    }

    // Resident must match session.
    let resident: DeviceId = match body.resident_device_id_hex.parse() {
        Ok(id) => id,
        Err(_) => {
            return pair_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "resident_device_id_hex must be 64 hex chars",
            );
        }
    };
    if resident != sess.resident_device_id {
        return pair_err(
            StatusCode::CONFLICT,
            "conflict",
            "resident_device_id does not match session",
        );
    }

    let joiner: DeviceId = match body.joiner_device_id_hex.parse() {
        Ok(id) => id,
        Err(_) => {
            return pair_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "joiner_device_id_hex must be 64 hex chars",
            );
        }
    };

    // ts skew ±5 min.
    let ts = match DateTime::parse_from_rfc3339(&body.ts) {
        Ok(t) => t.with_timezone(&Utc),
        Err(_) => {
            return pair_err(StatusCode::BAD_REQUEST, "bad_request", "ts must be RFC3339");
        }
    };
    let skew = (Utc::now() - ts).num_seconds().abs();
    if skew > DECIDE_TS_SKEW_SECS {
        return pair_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "ts outside allowed skew (±5 min)",
        );
    }

    if sess.is_expired_now() {
        return pair_err(StatusCode::GONE, "session_gone", "pair session expired");
    }

    let decision = match body.decision {
        DecideKind::Accept => JoinDecision::Accept,
        DecideKind::Deny => JoinDecision::Deny {
            reason: body
                .reason
                .clone()
                .unwrap_or_else(|| "denied by pair/v2".into()),
        },
    };

    // Idempotent: already decided with same decision+joiner → ok.
    if sess.phase.is_post_decide() {
        let same_joiner = sess.joiner_device_id == Some(joiner);
        let same_decision = matches!(
            (&sess.decision, &decision),
            (Some(JoinDecision::Accept), JoinDecision::Accept)
                | (Some(JoinDecision::Deny { .. }), JoinDecision::Deny { .. })
        );
        if same_joiner && same_decision {
            let enroll_written =
                try_enroll_from_decide(&st.paths, &st.identity().device_id(), &body);
            record_pair_decide(st.paths.metrics_dir(), "already_decided");
            return Json(DecideV2Response {
                ok: true,
                state: "already_decided",
                sid: sess.sid,
                phase: sess.phase.as_str(),
                enroll_written,
            })
            .into_response();
        }
        record_pair_decide(st.paths.metrics_dir(), "conflict");
        return pair_err(
            StatusCode::CONFLICT,
            "already_decided",
            "session already decided with different outcome",
        );
    }

    // Binding gate (same as confirm): armed + zero pending → 409 not_bound;
    // armed + single pending matching body joiner → bind; bound → verify match.
    let joins = match JoinStore::open(st.paths.join_dir()) {
        Ok(j) => j,
        Err(e) => {
            return pair_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("join store: {e}"),
            );
        }
    };

    match sess.phase {
        PairPhase::Bound => {
            if sess.joiner_device_id != Some(joiner) {
                return pair_err(
                    StatusCode::CONFLICT,
                    "conflict",
                    "joiner_device_id does not match bound session",
                );
            }
        }
        PairPhase::Armed => {
            let pending = match joins.list_pending() {
                Ok(p) => p,
                Err(e) => {
                    return pair_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal",
                        format!("list pending: {e}"),
                    );
                }
            };
            if pending.is_empty() {
                // Fail closed: stay armed, do not hang.
                return pair_err(
                    StatusCode::CONFLICT,
                    "not_bound",
                    "Joiner has not dialed yet — wait for JoinRequest / finish dual-scan order, then re-run decide.",
                );
            }
            // Prefer exact match on body joiner among pending; else single pending.
            let match_pending = pending.iter().find(|p| p.device_id == joiner);
            if let Some(p) = match_pending {
                match store.bind_joiner(
                    &sess.sid,
                    joiner,
                    Some(p.label.clone()),
                    Some(p.fingerprint.clone()),
                ) {
                    Ok(s) => sess = s,
                    Err(e) => {
                        return pair_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal",
                            format!("bind: {e}"),
                        );
                    }
                }
            } else if pending.len() == 1 {
                // Body joiner must equal the only pending (phone bound scan B).
                return pair_err(
                    StatusCode::CONFLICT,
                    "conflict",
                    "joiner_device_id does not match pending join",
                );
            } else {
                return pair_err(
                    StatusCode::CONFLICT,
                    "ambiguous_pending",
                    "multiple pending joins; bind joiner first",
                );
            }
        }
        other => {
            return pair_err(
                StatusCode::CONFLICT,
                "session_phase",
                format!("cannot decide in phase {}", other.as_str()),
            );
        }
    }

    // Write JoinStore decision for bound joiner only.
    if let Err(e) = joins.write_decision(&joiner, decision.clone()) {
        return pair_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("write decision: {e}"),
        );
    }
    let _ = std::fs::remove_file(joins.pending_path(&joiner));

    if let Err(e) = store.write_decision(&sess.sid, decision, false) {
        return pair_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("session decide: {e}"),
        );
    }

    let state = match body.decision {
        DecideKind::Accept => "accepted",
        DecideKind::Deny => "denied",
    };
    info!(
        sid = %sess.sid,
        peer = %joiner.short(),
        decision = state,
        "pair/v2 decide written to JoinStore + PairSessionStore"
    );
    record_pair_decide(st.paths.metrics_dir(), state);
    let enroll_written = try_enroll_from_decide(&st.paths, &st.identity().device_id(), &body);
    Json(DecideV2Response {
        ok: true,
        state,
        sid: sess.sid,
        phase: PairPhase::Decided.as_str(),
        enroll_written,
    })
    .into_response()
}

/// Phone introducer: this node is the **joiner**. Bearer is *this* machine's pair token.
///
/// Same iroh path as `mymesh link <resident>` / `pair dual --join`. Join runs in the
/// background so the HTTP call returns before host approval (up to 600s).
async fn pair_v2_dial(
    State(st): State<CarrierState>,
    headers: HeaderMap,
    Json(body): Json<DialRequest>,
) -> Response {
    let (_store, sess, raw) = match require_v2_session(&st.paths, &headers, None) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if sess.is_expired_now() {
        return pair_err(StatusCode::GONE, "session_gone", "pair session expired");
    }
    let token_key = hash_pair_token(&raw);
    if let Err(rl) = mymesh_core::rate_limit_check_shared(
        st.paths.metrics_dir(),
        LimitKind::PairDecide,
        &token_key,
    ) {
        record_pair_decide(st.paths.metrics_dir(), "rate_limited");
        return pair_rate_limited(rl.retry_after_secs);
    }

    let resident: DeviceId = match body.resident_did.parse() {
        Ok(id) => id,
        Err(_) => {
            return pair_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "resident_did must be 64 hex chars",
            );
        }
    };
    let self_id = st.identity().device_id();
    if resident == self_id {
        return pair_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "cannot dial self — scan the other machine as QR_B",
        );
    }
    if let Some(ref fp) = body.resident_fp {
        let want = NodeFingerprint::from_device_id(&resident);
        if !fp.is_empty() && fp != want.as_str() {
            return pair_err(
                StatusCode::CONFLICT,
                "conflict",
                "resident_fp does not match resident_did",
            );
        }
    }

    info!(
        resident = %resident.short(),
        "pair/v2 dial — joining resident (same path as mymesh link)"
    );
    spawn_join_as_guest_to_resident(st.identity(), st.label.clone(), st.paths.clone(), resident);

    Json(DialResponse {
        ok: true,
        state: "dialing",
        resident_did: resident.to_string(),
    })
    .into_response()
}

// --- deprecated HTML fallback ---

async fn page(State(st): State<CarrierState>) -> Html<String> {
    let local_uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    let label = html_escape(&st.label);
    let local = html_escape(&local_uri);
    let html = format!(
        concat!(
            "<!doctype html><html><head>",
            "<meta name=viewport content=\"width=device-width,initial-scale=1\"/>",
            "<title>MyMesh carrier</title>",
            "<style>body{{font-family:system-ui;background:#111;color:#eee;margin:1rem}}</style>",
            "</head><body>",
            "<h1>MyMesh connect by carrier</h1>",
            "<p>Phone is only a scanner. It does not join the mesh.</p>",
            "<p><b>Host:</b> {label}<br/><code>{local}</code></p>",
            "<p>Prefer Carrier app QR (<code>carrier://pair</code>). Paste URI fallback:</p>",
            "<input id=uri style=\"width:100%;padding:8px\"/>",
            "<button onclick=\"send()\" style=\"margin-top:8px;padding:8px 16px\">Link them</button>",
            "<p id=st>ready</p>",
            "<script>",
            "async function send(){{",
            "var uri=document.getElementById('uri').value.trim();",
            "if(!uri)return;",
            "document.getElementById('st').textContent='sending';",
            "var r=await fetch('/api/peer',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{uri:uri}})}});",
            "var j=await r.json().catch(function(){{return {{}}}});",
            "document.getElementById('st').textContent=j.status||r.statusText;",
            "}}",
            "</script></body></html>"
        ),
        label = label,
        local = local
    );
    Html(html)
}

async fn api_status(State(st): State<CarrierState>) -> Json<StatusBody> {
    let status = st.status.lock().await.clone();
    let local_uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    Json(StatusBody {
        status,
        local_uri,
        local_label: st.label.clone(),
    })
}

async fn api_local(State(st): State<CarrierState>) -> Json<serde_json::Value> {
    let uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    Json(serde_json::json!({ "uri": uri, "label": st.label }))
}

async fn api_peer(
    State(st): State<CarrierState>,
    Json(body): Json<PeerBody>,
) -> Json<serde_json::Value> {
    *st.pending_peer.lock().await = Some(body.uri.clone());
    *st.status.lock().await = format!("received peer ({} bytes) - host will dial", body.uri.len());
    // Do not re-arm when already armed: new until would invalidate pair/v1 bootstrap token/QR.
    let arm = ArmState::load(st.paths.arm_file()).unwrap_or_default();
    if !arm.is_effectively_armed() {
        let _ = ArmState::arm(st.paths.arm_file(), 600);
    }
    let path = carrier_pending_path(&st.paths);
    let _ = std::fs::write(&path, body.uri.as_bytes());
    Json(serde_json::json!({
        "status": "ok - keep page open; host completes join"
    }))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str(concat!("&", "amp;")),
            '<' => out.push_str(concat!("&", "lt;")),
            '>' => out.push_str(concat!("&", "gt;")),
            '"' => out.push_str(concat!("&", "quot;")),
            _ => out.push(c),
        }
    }
    out
}

fn local_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

pub fn carrier_pending_path(paths: &Paths) -> std::path::PathBuf {
    paths.data_dir.join("carrier-pending.txt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use mymesh_core::{apply_pair_confirm, Capability, DeviceId, NodeFingerprint};
    use tower::ServiceExt;

    fn tmp_paths() -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-pair-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        };
        paths.ensure().unwrap();
        paths
    }

    fn test_state(paths: Paths, secret: [u8; 32], label: &str) -> CarrierState {
        CarrierState {
            paths,
            secret,
            label: label.into(),
            pending_peer: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new("test".into())),
            bootstrap: Arc::new(Mutex::new(None)),
            mesh_auth: Arc::new(Mutex::new(MeshAuthStore::default())),
            rate_limits: Arc::new(RateLimitState::new()),
        }
    }

    async fn mint_token(st: &CarrierState) -> String {
        let mut g = st.bootstrap.lock().await;
        ensure_bootstrap_locked(&st.paths, &mut g).unwrap()
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn status_public_from_mesh_config_identity() {
        let paths = tmp_paths();
        let secret = [0x11u8; 32];
        let id = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();
        let cfg = Config {
            device_label: "studio-nuc".into(),
            ..Config::default()
        };
        cfg.save(paths.config_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();

        let st = test_state(paths, secret, "studio-nuc");
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["protocol_version"], 1);
        assert_eq!(v["mesh_id"], mesh.mesh_id);
        assert_eq!(v["host_label"], "studio-nuc");
        assert_eq!(v["host_device_id_hex"], id.device_id().to_string());
        assert_eq!(
            v["host_fingerprint"],
            NodeFingerprint::from_device_id(&id.device_id()).as_str()
        );
        assert_eq!(v["host_short_id"], id.device_id().short());
        assert_eq!(v["armed"], true);
        assert_eq!(v["auth_mode"], "bootstrap_token");
        assert!(v["arm_until"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn pending_requires_bearer_and_computes_words() {
        let paths = tmp_paths();
        let secret = [0x22u8; 32];
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let joiner = DeviceId::from_bytes([0xb2u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "laptop".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let st = test_state(paths, secret, "host");
        let token = mint_token(&st).await;
        let app = build_router(st.clone());

        // No auth → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/pending")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let err = json_body(resp).await;
        assert_eq!(err["code"], "unauthorized");

        // Bad token → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/pending")
                    .header(header::AUTHORIZATION, "Bearer notavalidtoken==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid bearer
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/pending")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        let p = &v["pending"][0];
        assert_eq!(p["device_id_hex"], joiner.to_string());
        assert_eq!(p["short_id"], joiner.short());
        assert_eq!(p["label"], "laptop");
        let words = p["words"].as_str().unwrap();
        assert_eq!(words, device_id_to_words(&joiner).unwrap());
        assert_eq!(words.split_whitespace().count(), 24);
        let caps = p["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 4);
        assert!(!caps.iter().any(|c| c == "admin"));
        // wire strings
        for want in ["terminal", "files", "desktop", "tcp"] {
            assert!(caps.iter().any(|c| c == want), "missing {want}");
        }
    }

    #[tokio::test]
    async fn decide_accept_deny_no_label_and_not_found() {
        let paths = tmp_paths();
        let secret = [0x33u8; 32];
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let joiner = DeviceId::from_bytes([0x44u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner-label".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let st = test_state(paths.clone(), secret, "host");
        let token = mint_token(&st).await;
        let app = build_router(st);

        // Accept (no device_label field allowed / needed)
        let body = serde_json::json!({
            "device_id_hex": joiner.to_string(),
            "decision": "accept"
        });
        assert!(body.get("device_label").is_none());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v1/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "accepted");

        // pending tombstoned immediately (no double-decide / list leak)
        assert!(joins.list_pending().unwrap().is_empty());
        // double-decide → not_found; decision still readable by host take_decision
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v1/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "device_id_hex": joiner.to_string(),
                            "decision": "deny",
                            "reason": "late"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(resp).await["state"], "not_found");

        let d = joins.take_decision(&joiner).unwrap().unwrap();
        assert!(matches!(d, JoinDecision::Accept));

        // not_found for unknown id — re-open router; bootstrap restored from disk
        let st2 = test_state(paths.clone(), secret, "host");
        let token2 = mint_token(&st2).await;
        assert_eq!(token, token2);
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "again".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();
        let app2 = build_router(st2);
        let resp = app2
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v1/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token2}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "device_id_hex": DeviceId::from_bytes([0x99u8; 32]).to_string(),
                            "decision": "deny"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = json_body(resp).await;
        assert_eq!(v["state"], "not_found");

        // Deny real pending
        let resp = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v1/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token2}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "device_id_hex": joiner.to_string(),
                            "decision": "deny",
                            "reason": "nope"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = json_body(resp).await;
        assert_eq!(v["state"], "denied");
        assert!(joins.list_pending().unwrap().is_empty());
        let d = joins.take_decision(&joiner).unwrap().unwrap();
        match d {
            JoinDecision::Deny { reason } => assert_eq!(reason, "nope"),
            _ => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn html_api_peer_does_not_rearm_when_armed() {
        let paths = tmp_paths();
        let secret = [0x66u8; 32];
        let first = ArmState::arm(paths.arm_file(), 900).unwrap();
        let until = first.until.expect("until set");
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let st = test_state(paths.clone(), secret, "host");
        let _token = mint_token(&st).await;
        let app = build_router(st);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/peer")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"uri":"mymesh://join/ab"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let arm = ArmState::load(paths.arm_file()).unwrap();
        assert!(arm.is_effectively_armed());
        assert_eq!(
            arm.until,
            Some(until),
            "HTML peer must not change arm.until"
        );
    }

    #[tokio::test]
    async fn disarm_invalidates_token() {
        let paths = tmp_paths();
        let secret = [0x55u8; 32];
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let st = test_state(paths.clone(), secret, "host");
        let token = mint_token(&st).await;
        let app = build_router(st);

        ArmState::disarm(paths.arm_file()).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/pending")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let err = json_body(resp).await;
        assert_eq!(err["code"], "unauthorized");
    }

    #[test]
    fn pair_qr_grammar() {
        let qr = build_pair_qr(
            "http://192.168.1.10:17878",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "a1b2-c3d4-e5f6-7890-abcd-ef01-2345-6789",
            Some("550e8400-e29b-41d4-a716-446655440000"),
        );
        assert!(qr.starts_with("carrier://pair?v=1&"));
        assert!(qr.contains("host=http%3A%2F%2F192.168.1.10%3A17878"));
        assert!(qr.contains("token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(qr.contains("fp=a1b2-c3d4-e5f6-7890-abcd-ef01-2345-6789"));
        assert!(qr.contains("mesh=550e8400-e29b-41d4-a716-446655440000"));
    }

    /// D5 / KD23: `start_carrier` default bootstrap QR is v2 with direct LAN host.
    #[tokio::test]
    async fn start_carrier_default_pair_qr_is_v2() {
        let paths = tmp_paths();
        let secret = [0xABu8; 32];
        let expected_did = Identity::from_secret_bytes(secret).device_id();
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();
        // Residual short arm must be refreshed to full carrier TTL (Issue 4).
        ArmState::arm(paths.arm_file(), 30).unwrap();

        let handle = start_carrier(
            paths.clone(),
            Identity::from_secret_bytes(secret),
            "host".into(),
            0, // ephemeral port
            Some("127.0.0.1".into()),
            false, // default product path
        )
        .await
        .expect("start_carrier");

        assert_eq!(handle.pair_protocol_version, 2);
        assert!(
            handle.pair_qr.starts_with("carrier://pair?v=2&"),
            "default QR must be v2: {}",
            handle.pair_qr
        );
        assert!(handle.pair_qr.contains("nonce="));
        assert!(handle.pair_qr.contains("sid="));
        assert!(
            handle.pair_qr.contains(&format!("did={}", expected_did)),
            "did= must be resident device id hex: {}",
            handle.pair_qr
        );
        assert!(handle.pair_qr.contains("ep=direct"));
        // Percent-encoded LAN host (same grammar as v1 escape).
        assert!(
            handle.pair_qr.contains("host=http%3A%2F%2F127.0.0.1%3A"),
            "host must be percent-encoded: {}",
            handle.pair_qr
        );
        assert!(
            handle.pair_qr.contains(&format!("mesh={}", mesh.mesh_id)),
            "mesh= required when mesh loaded: {}",
            handle.pair_qr
        );
        assert!(handle
            .pair_qr
            .contains(&format!("token={}", handle.bootstrap_token)));

        // PairSession was armed and is findable by the QR token.
        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let raw = URL_SAFE_NO_PAD
            .decode(handle.bootstrap_token.as_bytes())
            .unwrap();
        let mut tok = [0u8; 32];
        tok.copy_from_slice(&raw);
        let sess = store
            .find_by_token_raw(&tok)
            .unwrap()
            .expect("session for QR token");
        assert_eq!(sess.resident_device_id, expected_did);
        assert_eq!(sess.ep, PairEndpointClass::Direct);
        assert!(handle.pair_qr.contains(&format!("sid={}", sess.sid)));

        // Compat: default path still mints arm-scoped v1 bootstrap (distinct from session token).
        let v1_persist = std::fs::read_to_string(paths.data_dir.join("pair-bootstrap.json"))
            .expect("pair-bootstrap.json for /pair/v1 compat");
        let v1: serde_json::Value = serde_json::from_str(&v1_persist).unwrap();
        let v1_token = v1["token"].as_str().expect("v1 token field");
        assert_ne!(
            v1_token, handle.bootstrap_token,
            "v1 bootstrap must not be the PairSession QR token"
        );
        let v1_raw = URL_SAFE_NO_PAD.decode(v1_token.as_bytes()).unwrap();
        let mut v1_tok = [0u8; 32];
        v1_tok.copy_from_slice(&v1_raw);
        assert!(
            store.find_by_token_raw(&v1_tok).unwrap().is_none(),
            "v1 bootstrap must not resolve as a PairSession"
        );

        // Arm window refreshed to full carrier TTL (not residual 30s).
        let arm = ArmState::load(paths.arm_file()).unwrap();
        assert!(arm.is_effectively_armed());
        let until = arm.until.expect("arm until");
        let remaining = (until - Utc::now()).num_seconds();
        assert!(
            remaining > 800,
            "arm must be refreshed to ~{CARRIER_ARM_TTL_SECS}s, remaining={remaining}"
        );
    }

    /// D5 escape hatch: `--pair-v1` still emits alpha.1 LAN QR (no PairSession for that token).
    #[tokio::test]
    async fn start_carrier_pair_v1_escape_emits_v1_qr() {
        let paths = tmp_paths();
        let secret = [0xCDu8; 32];
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let handle = start_carrier(
            paths.clone(),
            Identity::from_secret_bytes(secret),
            "host".into(),
            0,
            Some("192.168.1.10".into()),
            true, // --pair-v1
        )
        .await
        .expect("start_carrier pair_v1");

        assert_eq!(handle.pair_protocol_version, 1);
        assert!(
            handle.pair_qr.starts_with("carrier://pair?v=1&"),
            "escape QR must be v1: {}",
            handle.pair_qr
        );
        assert!(!handle.pair_qr.contains("nonce="));
        assert!(!handle.pair_qr.contains("sid="));
        assert!(handle.pair_qr.contains("host=http%3A%2F%2F192.168.1.10%3A"));
        assert!(handle
            .pair_qr
            .contains(&format!("token={}", handle.bootstrap_token)));

        // Escape must not mint a PairSession for the v1 QR token.
        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let raw = URL_SAFE_NO_PAD
            .decode(handle.bootstrap_token.as_bytes())
            .unwrap();
        let mut tok = [0u8; 32];
        tok.copy_from_slice(&raw);
        assert!(
            store.find_by_token_raw(&tok).unwrap().is_none(),
            "v1 QR token must not resolve as a PairSession"
        );
        // Fresh home: no sessions created by escape path alone.
        assert!(
            store.list().unwrap().is_empty(),
            "escape path must not arm a PairSession"
        );
    }

    #[test]
    fn bootstrap_token_is_32b_base64url() {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let t = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(t.len(), 43);
        assert!(!t.contains('='));
        assert!(!t.contains('+'));
        assert!(!t.contains('/'));
    }

    #[test]
    fn arm_until_iso_format() {
        let t = Utc::now() + Duration::seconds(60);
        let s = rfc3339(t);
        assert!(s.ends_with('Z'));
        assert!(!s.contains('.'));
    }

    // --- pair/v2 ---

    use mymesh_core::{PairEndpointClass, PairSessionStore};

    fn arm_v2_session(
        paths: &Paths,
        resident: DeviceId,
        ep: PairEndpointClass,
    ) -> (String, String, [u8; 16], String) {
        let mesh = MeshState::load(paths.mesh_file()).unwrap_or_else(|_| {
            let m = MeshState::new_mesh();
            m.save(paths.mesh_file()).unwrap();
            m
        });
        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let armed = store.arm_new(&mesh.mesh_id, resident, 900, ep).unwrap();
        let token = URL_SAFE_NO_PAD.encode(armed.token_raw);
        (armed.session.sid, token, armed.session.nonce, mesh.mesh_id)
    }

    #[test]
    fn pair_qr_v2_requires_nonce_optional_host() {
        let nonce = [0x42u8; 16];
        let qr = build_pair_qr_v2(&PairQrV2Params {
            sid: "01HZXEXAMPLE00000000000000",
            did: "abababababababababababababababababababababababababababababababab",
            token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            nonce: &nonce,
            fp: "a1b2-c3d4-e5f6-7890-abcd-ef01-2345-6789",
            mesh: Some("mesh-1"),
            host: None,
            ep: None,
            relay: None,
            tlspin: None,
        });
        assert!(qr.starts_with("carrier://pair?v=2&"));
        assert!(qr.contains("sid=01HZXEXAMPLE00000000000000"));
        assert!(qr.contains(&format!("nonce={}", URL_SAFE_NO_PAD.encode(nonce))));
        assert!(qr.contains("ep=confirm"));
        assert!(!qr.contains("host="));
        assert!(qr.contains("mesh=mesh-1"));
        assert!(!qr.contains("tlspin="));

        let qr_host = build_pair_qr_v2(&PairQrV2Params {
            sid: "01HZXEXAMPLE00000000000000",
            did: "aa",
            token: "tok",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some("http://192.168.1.10:17878"),
            ep: None,
            relay: None,
            tlspin: None,
        });
        assert!(qr_host.contains("ep=direct"));
        assert!(qr_host.contains("host=http%3A%2F%2F192.168.1.10%3A17878"));
    }

    #[test]
    fn pair_qr_v2_optional_tlspin_https_only() {
        use mymesh_core::{parse_tls_pin, TlsPin, TlsPinError};

        let nonce = [0x7u8; 16];
        let pin = TlsPin::from_spki_der(&[0x30, 0x01, 0x02, 0x03]);
        let wire = pin.to_wire();

        let qr = build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "01HZXEXAMPLE00000000000000",
            did: "aa",
            token: "tok",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some("https://pair.example:8443"),
            ep: Some(PairEndpointClass::Direct),
            relay: None,
            tlspin: Some(&wire),
        })
        .unwrap();
        assert!(qr.contains("tlspin="));
        assert!(qr.contains(&percent_encode(&wire)) || qr.contains(&wire));
        // parsed pin round-trips
        assert_eq!(parse_tls_pin(&wire).unwrap(), pin);

        // pin + cleartext host → fail closed
        let err = build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "s",
            did: "d",
            token: "t",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some("http://192.168.1.10:17878"),
            ep: None,
            relay: None,
            tlspin: Some(&wire),
        })
        .unwrap_err();
        assert_eq!(err, TlsPinError::HttpsRequired);

        // pin without host → fail closed
        let err = build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "s",
            did: "d",
            token: "t",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: None,
            ep: None,
            relay: None,
            tlspin: Some(&wire),
        })
        .unwrap_err();
        assert_eq!(err, TlsPinError::HttpsRequired);

        // no pin + http still ok
        assert!(build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "s",
            did: "d",
            token: "t",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some("http://192.168.1.10:17878"),
            ep: None,
            relay: None,
            tlspin: None,
        })
        .is_ok());

        // pin + empty host string → fail closed
        let err = build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "s",
            did: "d",
            token: "t",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some(""),
            ep: None,
            relay: None,
            tlspin: Some(&wire),
        })
        .unwrap_err();
        assert_eq!(err, TlsPinError::HttpsRequired);

        // bad pin format at checked emit
        assert!(matches!(
            build_pair_qr_v2_checked(&PairQrV2Params {
                sid: "s",
                did: "d",
                token: "t",
                nonce: &nonce,
                fp: "fp",
                mesh: None,
                host: Some("https://h"),
                ep: None,
                relay: None,
                tlspin: Some("md5/AAAA"),
            })
            .unwrap_err(),
            TlsPinError::BadFormat(_)
        ));
        assert!(matches!(
            build_pair_qr_v2_checked(&PairQrV2Params {
                sid: "s",
                did: "d",
                token: "t",
                nonce: &nonce,
                fp: "fp",
                mesh: None,
                host: Some("https://h"),
                ep: None,
                relay: None,
                tlspin: Some("sha256/AAAA"),
            })
            .unwrap_err(),
            TlsPinError::BadDigest(_)
        ));

        // non-canonical input (Android standard base64) → QR emits canonical base64url no-pad
        let android = pin.to_android_wire();
        assert_ne!(android, wire);
        let qr_canon = build_pair_qr_v2_checked(&PairQrV2Params {
            sid: "s",
            did: "d",
            token: "t",
            nonce: &nonce,
            fp: "fp",
            mesh: None,
            host: Some("https://pair.example"),
            ep: None,
            relay: None,
            tlspin: Some(&android),
        })
        .unwrap();
        assert!(
            qr_canon.contains(&percent_encode(&wire)) || qr_canon.contains(&wire),
            "checked builder should re-emit canonical pin on QR"
        );
        // Android padded form should not appear raw on the wire
        assert!(!qr_canon.contains(&percent_encode(&android)));
    }

    #[test]
    fn nonce_roundtrip_wire() {
        let n = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let s = encode_pair_nonce(&n);
        assert!(!s.contains('='));
        assert_eq!(decode_pair_nonce(&s).unwrap(), n);
        assert!(decode_pair_nonce("AAAA").is_none()); // wrong length
    }

    #[tokio::test]
    async fn v2_status_public_echoes_session_nonce() {
        let paths = tmp_paths();
        let secret = [0x71u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, _token, nonce, mesh_id) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Confirm);

        let st = test_state(paths, secret, "host");
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/pair/v2/status?sid={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["protocol_version"], 2);
        assert_eq!(v["sid"], sid);
        assert_eq!(v["mesh_id"], mesh_id);
        assert_eq!(v["nonce"], encode_pair_nonce(&nonce));
        assert_eq!(v["phase"], "armed");
        assert_eq!(v["ep"], "confirm");
        assert_eq!(v["host_device_id_hex"], id.device_id().to_string());
    }

    #[tokio::test]
    async fn v2_pending_requires_bearer() {
        let paths = tmp_paths();
        let secret = [0x72u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (_sid, token, _nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Confirm);

        let joiner = DeviceId::from_bytes([0xc2u8; 32]);
        JoinStore::open(paths.join_dir())
            .unwrap()
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "peer".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = build_router(st);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/pair/v2/pending")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/pair/v2/pending")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["pending"][0]["device_id_hex"], joiner.to_string());
    }

    #[tokio::test]
    async fn v2_decide_not_bound_when_zero_pending() {
        let paths = tmp_paths();
        let secret = [0x73u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let joiner = DeviceId::from_bytes([0xd3u8; 32]);
        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);

        let body = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&nonce),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let v = json_body(resp).await;
        assert_eq!(v["code"], "not_bound");

        // Session remains armed (fail closed, no hang / no force-bind).
        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let s = store.load(&sid).unwrap().unwrap();
        assert_eq!(s.phase, mymesh_core::PairPhase::Armed);
        assert!(s.joiner_device_id.is_none());
    }

    #[tokio::test]
    async fn v2_dial_requires_bearer_and_rejects_self() {
        let paths = tmp_paths();
        let secret = [0x75u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (_sid, token, _nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let st = test_state(paths, secret, "joiner");
        let app = build_router(st);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/dial")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "resident_did": "ab".repeat(32) }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let self_did = id.device_id().to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/dial")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "resident_did": self_did }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let other = DeviceId::from_bytes([0xe5u8; 32]).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/dial")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "resident_did": other }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "dialing");
        assert_eq!(v["resident_did"], other);
    }

    #[tokio::test]
    async fn v2_decide_bind_single_pending_and_nonce_mismatch() {
        let paths = tmp_paths();
        let secret = [0x74u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let joiner = DeviceId::from_bytes([0xe4u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);

        // Wrong nonce → conflict
        let bad = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&[0xffu8; 16]),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bad.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(json_body(resp).await["code"], "conflict");

        // Correct nonce + single pending matching joiner → accept + bind
        let good = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&nonce),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(good.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "accepted");
        assert_eq!(v["phase"], "decided");

        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let s = store.load(&sid).unwrap().unwrap();
        assert_eq!(s.phase, mymesh_core::PairPhase::Decided);
        assert_eq!(s.joiner_device_id, Some(joiner));
        assert!(matches!(s.decision, Some(JoinDecision::Accept)));
        let d = joins.take_decision(&joiner).unwrap().unwrap();
        assert!(matches!(d, JoinDecision::Accept));
    }

    fn sign_decide_enroll(
        person: &Identity,
        person_id: &str,
        facet: PersonFacet,
        resident: &DeviceId,
        ts: &str,
        nonce: &[u8; 16],
    ) -> (String, String) {
        let ts_unix = mymesh_core::wire::parse_rfc3339_unix(ts).unwrap();
        let pk = person.verifying_key_bytes();
        let pre = mymesh_core::wire::carrier_enroll_v1_preimage(
            person_id,
            facet,
            resident.as_bytes(),
            ts_unix,
            nonce,
            &pk,
        )
        .unwrap();
        (hex::encode(pk), hex::encode(person.sign(&pre)))
    }

    #[tokio::test]
    async fn v2_decide_with_enroll_fields_writes_row() {
        let paths = tmp_paths();
        let secret = [0x76u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let joiner = DeviceId::from_bytes([0xe6u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let person = Identity::from_secret_bytes([0x42u8; 32]);
        let ts = rfc3339(Utc::now());
        let pid = "01HZXPERSON0000000000000";
        let (pk_hex, sig_hex) = sign_decide_enroll(
            &person,
            pid,
            PersonFacet::Personal,
            &id.device_id(),
            &ts,
            &nonce,
        );

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);
        let body = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": ts,
            "nonce": encode_pair_nonce(&nonce),
            "person_id": pid,
            "facet": "personal",
            "person_public_key_hex": pk_hex,
            "sig_hex": sig_hex,
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["state"], "accepted");
        assert_eq!(v["enroll_written"], true);

        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        let rec = store.get(pid).expect("enroll row");
        assert!(rec.can_drive);
        assert_eq!(rec.facet, PersonFacet::Personal);
        assert_eq!(rec.person_public_key_hex, pk_hex);
    }

    #[tokio::test]
    async fn v2_decide_without_enroll_fields_is_pair_only() {
        let paths = tmp_paths();
        let secret = [0x77u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let joiner = DeviceId::from_bytes([0xe7u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);
        let body = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&nonce),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["state"], "accepted");
        assert_eq!(v["enroll_written"], false);
        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        assert!(store.list().is_empty());
        assert!(!paths.enrollments_file().exists() || store.list().is_empty());
    }

    #[tokio::test]
    async fn v2_decide_bad_enroll_sig_does_not_block_pair() {
        let paths = tmp_paths();
        let secret = [0x78u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let joiner = DeviceId::from_bytes([0xe8u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let person = Identity::from_secret_bytes([0x42u8; 32]);
        let ts = rfc3339(Utc::now());
        let pid = "01HZXPERSONBADSIG00000000";
        let (pk_hex, mut sig_hex) = sign_decide_enroll(
            &person,
            pid,
            PersonFacet::Personal,
            &id.device_id(),
            &ts,
            &nonce,
        );
        let last = sig_hex.pop().unwrap();
        sig_hex.push(if last == '0' { '1' } else { '0' });

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);
        let body = serde_json::json!({
            "sid": sid,
            "decision": "accept",
            "joiner_device_id_hex": joiner.to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": ts,
            "nonce": encode_pair_nonce(&nonce),
            "person_id": pid,
            "facet": "personal",
            "person_public_key_hex": pk_hex,
            "sig_hex": sig_hex,
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["state"], "accepted");
        assert_eq!(v["enroll_written"], false);
        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        assert!(store.get(pid).is_none());
        let sess = PairSessionStore::open(paths.pair_sessions_dir())
            .unwrap()
            .load(&sid)
            .unwrap()
            .unwrap();
        assert_eq!(sess.phase, mymesh_core::PairPhase::Decided);
    }

    #[tokio::test]
    async fn confirm_on_machine_does_not_write_enroll() {
        let paths = tmp_paths();
        let secret = [0x79u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        ArmState::arm(paths.arm_file(), 600).unwrap();
        let (sid, _token, _nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Confirm);

        let joiner = DeviceId::from_bytes([0xe9u8; 32]);
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "joiner".into(),
                capabilities: Capability::all(),
                received_at: Utc::now(),
                fingerprint: NodeFingerprint::from_device_id(&joiner)
                    .as_str()
                    .to_string(),
            })
            .unwrap();

        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let sess = store.load(&sid).unwrap().unwrap();
        let token_raw = store.load_token_raw(&sid).unwrap().unwrap();
        let codes = mymesh_core::compute_confirm_codes(
            &token_raw,
            &sess.sid,
            &joiner.to_string(),
            &id.device_id().to_string(),
            &sess.nonce,
        );
        let applied = apply_pair_confirm(&store, &joins, &codes.accept, Some(&sid), None).unwrap();
        assert!(matches!(applied.decision, JoinDecision::Accept));
        let enroll = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        assert!(enroll.list().is_empty());
        assert!(!paths.enrollments_file().exists());
    }

    #[tokio::test]
    async fn v1_still_works_alongside_v2() {
        let paths = tmp_paths();
        let secret = [0x75u8; 32];
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let st = test_state(paths, secret, "host");
        let _ = mint_token(&st).await;
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/pair/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["protocol_version"], 1);
    }

    fn with_peer(mut req: Request<Body>, ip: [u8; 4]) -> Request<Body> {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 50_000))));
        req
    }

    /// S9: pair status unauth — 60 / min / peer IP → 429 + Retry-After.
    /// X-Forwarded-For is ignored without MYMESH_TRUST_PROXY.
    #[tokio::test]
    async fn pair_status_rate_limit_per_ip() {
        std::env::remove_var("MYMESH_TRUST_PROXY");
        let paths = tmp_paths();
        let secret = [0x81u8; 32];
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let metrics = paths.metrics_dir();
        let st = test_state(paths, secret, "host");
        let app = build_router(st);

        let peer = [203, 0, 113, 50];
        let limit = mymesh_core::PAIR_STATUS.max as usize;
        for i in 0..limit {
            let req = with_peer(
                Request::builder()
                    .uri("/pair/v2/status")
                    // Spoofed XFF must NOT bypass peer key when trust proxy is off.
                    .header("x-forwarded-for", "198.51.100.1")
                    .body(Body::empty())
                    .unwrap(),
                peer,
            );
            let resp = app.clone().oneshot(req).await.unwrap();
            assert!(
                resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::OK,
                "hit {i}: unexpected {}",
                resp.status()
            );
        }
        let resp = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .uri("/pair/v2/status")
                    .header("x-forwarded-for", "198.51.100.1")
                    .body(Body::empty())
                    .unwrap(),
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().get(header::RETRY_AFTER).is_some(),
            "429 must include Retry-After"
        );
        let body = json_body(resp).await;
        assert_eq!(body["code"], "rate_limited");

        // Different peer still allowed.
        let resp = app
            .oneshot(with_peer(
                Request::builder()
                    .uri("/pair/v2/status")
                    .body(Body::empty())
                    .unwrap(),
                [203, 0, 113, 51],
            ))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let counters = mymesh_core::EventCounters::load(&metrics).unwrap();
        assert!(counters.pair_status_total > limit as u64);
    }

    /// S9: pair decide — 10 / min / token → 429 + Retry-After; metrics.
    #[tokio::test]
    async fn pair_v2_decide_rate_limit_per_token() {
        let paths = tmp_paths();
        mymesh_core::rate_limit_clear_shared_for_tests(paths.metrics_dir());
        let secret = [0x82u8; 32];
        let id = Identity::from_secret_bytes(secret);
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);
        let metrics = paths.metrics_dir();

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);

        // Body fails early (not_bound) but still consumes decide budget.
        let body = serde_json::json!({
            "sid": sid,
            "decision": "deny",
            "joiner_device_id_hex": DeviceId::from_bytes([0x99u8; 32]).to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&nonce),
        });
        let limit = mymesh_core::PAIR_DECIDE.max as usize;
        for i in 0..limit {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/pair/v2/decide")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "hit {i} should not be limited yet"
            );
        }
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
        assert_eq!(json_body(resp).await["code"], "rate_limited");

        let counters = mymesh_core::EventCounters::load(&metrics).unwrap();
        assert_eq!(
            counters.pair_decide_total.get("rate_limited").copied(),
            Some(1)
        );
    }

    /// S9: HTTP decide hits and CLI confirm share one file-backed token budget.
    #[tokio::test]
    async fn decide_and_confirm_share_token_budget() {
        let paths = tmp_paths();
        mymesh_core::rate_limit_clear_shared_for_tests(paths.metrics_dir());
        let secret = [0x83u8; 32];
        let id = Identity::from_secret_bytes(secret);
        ArmState::arm(paths.arm_file(), 600).unwrap();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let (sid, token, nonce, _) =
            arm_v2_session(&paths, id.device_id(), PairEndpointClass::Direct);

        let st = test_state(paths.clone(), secret, "host");
        let app = build_router(st);
        let body = serde_json::json!({
            "sid": sid,
            "decision": "deny",
            "joiner_device_id_hex": DeviceId::from_bytes([0x77u8; 32]).to_string(),
            "resident_device_id_hex": id.device_id().to_string(),
            "ts": rfc3339(Utc::now()),
            "nonce": encode_pair_nonce(&nonce),
        });
        // Burn 9 of 10 via HTTP decide
        for _ in 0..9 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/pair/v2/decide")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        // 10th via confirm (same token_hash / metrics_dir file store)
        let store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let joins = JoinStore::open(paths.join_dir()).unwrap();
        // First confirm attempt consumes last slot (may fail not_bound / bad_code)
        let r1 = apply_pair_confirm(&store, &joins, "ZZZZ-ZZZZ", Some(&sid), None);
        assert!(
            !matches!(r1, Err(mymesh_core::PairConfirmError::RateLimited { .. })),
            "10th attempt should still be allowed: {r1:?}"
        );
        // 11th → RateLimited
        let r2 = apply_pair_confirm(&store, &joins, "ZZZZ-ZZZZ", Some(&sid), None);
        match r2 {
            Err(mymesh_core::PairConfirmError::RateLimited { retry_after_secs }) => {
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        // HTTP also blocked
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pair/v2/decide")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
    }

    async fn raw_http_get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// `mymesh serve` binds the same router — curl /pair/v2/status without `mymesh carrier`.
    #[tokio::test]
    async fn serve_pair_http_status_without_carrier_cli() {
        let paths = tmp_paths();
        let secret = [0x22u8; 32];
        let identity = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let handle = start_pair_http(
            paths.clone(),
            &identity,
            "host".into(),
            0,
            Some("127.0.0.1".into()),
        )
        .await
        .expect("start_pair_http");

        let raw = raw_http_get(handle.bind, "/pair/v2/status").await;
        assert!(
            raw.contains("404") || raw.contains("not_found"),
            "unarmed status should be 404 not_found: {raw}"
        );

        let armed = arm_pair_qr(&paths, &identity, 600, &handle.host_base).unwrap();
        assert!(armed.qr.starts_with("carrier://pair?v=2&"));
        assert!(armed.qr.contains(&format!("sid={}", armed.sid)));

        let raw = raw_http_get(handle.bind, &format!("/pair/v2/status?sid={}", armed.sid)).await;
        assert!(
            raw.contains("200") && raw.contains("\"protocol_version\":2"),
            "armed status via serve-owned HTTP: {raw}"
        );
        assert!(raw.contains(&armed.sid));
    }

    #[tokio::test]
    async fn pair_arm_admin_mma1_json() {
        let paths = tmp_paths();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let secret = [0x33u8; 32];
        let admin = PairArmAdmin {
            paths,
            secret,
            host_base: Arc::new(Mutex::new("http://127.0.0.1:17878".into())),
        };
        let ok = admin
            .handle(serde_json::json!({"cmd": "arm_pair_qr", "ttl_secs": 120}))
            .await;
        assert_eq!(ok["ok"], true);
        assert!(ok["qr"]
            .as_str()
            .unwrap()
            .starts_with("carrier://pair?v=2&"));
        assert!(ok["sid"].as_str().unwrap().len() > 4);
        assert_eq!(ok["host_base"], "http://127.0.0.1:17878");

        let bad = admin.handle(serde_json::json!({"cmd": "nope"})).await;
        assert_eq!(bad["ok"], false);
        assert_eq!(bad["code"], "bad_request");
    }

    /// Serve-shaped process: pair HTTP + MMA1 on the control socket, then MMD1.
    #[tokio::test]
    async fn serve_mma1_arm_then_connect_mesh_and_status() {
        use mymesh_net::{
            arm_pair_qr_via_agent, connect_mesh, serve_control_socket, LocalAdmin, LocalFabric,
            Transport,
        };
        use mymesh_protocol::ChannelId;
        use std::sync::Arc;
        use std::time::Duration;

        let paths = tmp_paths();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let secret = [0x44u8; 32];
        let identity = Identity::from_secret_bytes(secret);
        let http = start_pair_http(
            paths.clone(),
            &identity,
            "host".into(),
            0,
            Some("127.0.0.1".into()),
        )
        .await
        .unwrap();

        let fabric = LocalFabric::new();
        let id_b = Identity::generate();
        let ep_a = fabric.endpoint(identity.device_id());
        let ep_b = fabric.endpoint(id_b.device_id());
        let sock = std::env::temp_dir().join(format!(
            "mma1-serve-{}-{}.sock",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let admin: Arc<dyn LocalAdmin> = Arc::new(PairArmAdmin {
            paths: paths.clone(),
            secret,
            host_base: Arc::new(Mutex::new(http.host_base.clone())),
        });
        let t: Arc<dyn Transport> = Arc::new(ep_a);
        let sock2 = sock.clone();
        tokio::spawn(async move {
            let _ = serve_control_socket(sock2, t, Some(admin)).await;
        });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let armed = arm_pair_qr_via_agent(&sock, 600).await.expect("MMA1");
        assert!(armed.ok);
        let sid = armed.sid.expect("sid");
        let qr = armed.qr.expect("qr");
        assert!(qr.starts_with("carrier://pair?v=2&"));
        assert!(qr.contains(&format!("sid={sid}")));

        let raw = raw_http_get(http.bind, &format!("/pair/v2/status?sid={sid}")).await;
        assert!(
            raw.contains("\"protocol_version\":2"),
            "curl-style status without mymesh carrier: {raw}"
        );

        let accept = tokio::spawn(async move { ep_b.accept().await });
        let (conn, direct) = connect_mesh(&identity, id_b.device_id(), &sock)
            .await
            .expect("connect_mesh after MMA1");
        assert!(direct.is_none());
        conn.send_frame(mymesh_protocol::Frame {
            channel: ChannelId::control(),
            payload: bytes::Bytes::from_static(b"ok"),
        })
        .await
        .unwrap();
        let peer = accept.await.unwrap().unwrap();
        assert_eq!(&peer.recv_frame().await.unwrap().payload[..], b"ok");
        let _ = std::fs::remove_file(&sock);
    }
}
