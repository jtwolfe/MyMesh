//! Connect-by-carrier: local web page + pair/v1 + pair/v2 + mesh/v1 HTTP.
//!
//! Port 17878 (default). Serves deprecated HTML (`/`, `/api/*`) and machine API
//! under `/pair/v1` (status / pending / decide), `/pair/v2`, and `/mesh/v1`
//! (auth challenge + topology) using the same `Paths` as serve.
//! PairSessionStore is source of truth for v2 (PAIR-V2.md).
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use mymesh_core::{
    ArmState, Config, DeviceId, JoinDecision, JoinStore, MeshState, NodeFingerprint,
    PairEndpointClass, PairPhase, PairSessionFile, PairSessionStore, Paths, PendingJoin,
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

use crate::mesh_api::{self, MeshApiState, MeshAuthStore};

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

pub struct CarrierHandle {
    /// HTML page URL (deprecated fallback).
    pub url: String,
    pub bind: SocketAddr,
    /// Base `http://IP:port` for pair API (no trailing slash).
    pub host_base: String,
    /// Bootstrap token (base64url, no padding).
    pub bootstrap_token: String,
    /// Deep link: `carrier://pair?v=1&host=…&token=…&fp=…&mesh?…`
    pub pair_qr: String,
}

pub async fn start_carrier(
    paths: Paths,
    identity: Identity,
    label: String,
    port: u16,
    lan_ip: Option<String>,
) -> anyhow::Result<CarrierHandle> {
    paths.ensure()?;
    // Arm window gives bootstrap token its TTL (PAIR-HTTP.md).
    if !ArmState::load(paths.arm_file())?.is_effectively_armed() {
        let _ = ArmState::arm(paths.arm_file(), 900);
    }

    let bootstrap = Arc::new(Mutex::new(None));
    let st = CarrierState {
        paths: paths.clone(),
        secret: identity.to_secret_bytes(),
        label: label.clone(),
        pending_peer: Arc::new(Mutex::new(None)),
        status: Arc::new(Mutex::new("waiting for phone".into())),
        bootstrap: bootstrap.clone(),
        mesh_auth: Arc::new(Mutex::new(MeshAuthStore::default())),
    };

    // Mint arm-scoped token so QR is valid immediately.
    let token_b64 = {
        let mut guard = st.bootstrap.lock().await;
        ensure_bootstrap_locked(&st.paths, &mut guard)?
    };

    let app = build_router(st);

    let bind: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let actual = listener.local_addr()?;
    let host = lan_ip.unwrap_or_else(|| local_ipv4().unwrap_or_else(|| "127.0.0.1".into()));
    let url = format!("http://{host}:{}/", actual.port());
    let host_base = format!("http://{host}:{}", actual.port());
    let id = identity.device_id();
    let fp = NodeFingerprint::from_device_id(&id).as_str().to_string();
    let mesh_id = MeshState::load(paths.mesh_file())?.mesh_id;
    let pair_qr = build_pair_qr(&host_base, &token_b64, &fp, Some(&mesh_id));
    info!(%url, %host_base, "carrier + pair/v1 + mesh/v1 listening");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!(%e, "carrier server exit");
        }
    });

    Ok(CarrierHandle {
        url,
        bind: actual,
        host_base,
        bootstrap_token: token_b64,
        pair_qr,
    })
}

fn build_router(st: CarrierState) -> Router {
    let mesh_st = MeshApiState {
        paths: st.paths.clone(),
        secret: st.secret,
        label: st.label.clone(),
        auth: st.mesh_auth.clone(),
    };
    let pair_app = Router::new()
        // Deprecated HTML / phone-paste fallback
        .route("/", get(page))
        .route("/api/status", get(api_status))
        .route("/api/peer", post(api_peer))
        .route("/api/local", get(api_local))
        // pair/v1 machine API (compat through D5)
        .route("/pair/v1/status", get(pair_status))
        .route("/pair/v1/pending", get(pair_pending))
        .route("/pair/v1/decide", post(pair_decide))
        // pair/v2 control plane (PairSessionStore)
        .route("/pair/v2/status", get(pair_v2_status))
        .route("/pair/v2/pending", get(pair_v2_pending))
        .route("/pair/v2/decide", post(pair_v2_decide))
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
#[derive(Clone, Debug)]
pub struct PairQrV2Params<'a> {
    pub sid: &'a str,
    pub did: &'a str,
    pub token: &'a str,
    /// 16 raw session nonce bytes (encoded as base64url no pad on the wire).
    pub nonce: &'a [u8; 16],
    pub fp: &'a str,
    pub mesh: Option<&'a str>,
    /// Optional direct host base URL (`http://ip:port`). When set, `ep` defaults to direct.
    pub host: Option<&'a str>,
    pub ep: Option<PairEndpointClass>,
    pub relay: Option<&'a str>,
}

/// Build v2 pair QR. Fails only if nonce is not 16 bytes (compile-time via type) —
/// call sites must supply a real session nonce (KD27).
///
/// ```text
/// carrier://pair?v=2&sid=…&did=…&token=…&nonce=…&fp=…
///              &ep=direct|confirm|relay
///              &host=<optional>
///              &mesh=<optional>
///              &relay=<optional>
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
    q
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

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// --- pair/v1 handlers ---

async fn pair_status(State(st): State<CarrierState>) -> Response {
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
    if let Err(resp) = require_bootstrap(&st, &headers).await {
        return resp;
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
    reason: Option<String>,
}

#[derive(Serialize)]
struct DecideV2Response {
    ok: bool,
    state: &'static str,
    sid: String,
    phase: &'static str,
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

async fn pair_v2_status(State(st): State<CarrierState>, Query(q): Query<StatusQuery>) -> Response {
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
    let (store, mut sess, _raw) = match require_v2_session(&st.paths, &headers, Some(&body.sid)) {
        Ok(x) => x,
        Err(r) => return r,
    };

    // Optional person fields unused in Wave A (audit only).
    let _ = (body.person_id, body.sig_hex);

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
            return Json(DecideV2Response {
                ok: true,
                state: "already_decided",
                sid: sess.sid,
                phase: sess.phase.as_str(),
            })
            .into_response();
        }
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
    Json(DecideV2Response {
        ok: true,
        state,
        sid: sess.sid,
        phase: PairPhase::Decided.as_str(),
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
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use mymesh_core::{Capability, DeviceId, NodeFingerprint};
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
        });
        assert!(qr.starts_with("carrier://pair?v=2&"));
        assert!(qr.contains("sid=01HZXEXAMPLE00000000000000"));
        assert!(qr.contains(&format!("nonce={}", URL_SAFE_NO_PAD.encode(nonce))));
        assert!(qr.contains("ep=confirm"));
        assert!(!qr.contains("host="));
        assert!(qr.contains("mesh=mesh-1"));

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
        });
        assert!(qr_host.contains("ep=direct"));
        assert!(qr_host.contains("host=http%3A%2F%2F192.168.1.10%3A17878"));
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
}
