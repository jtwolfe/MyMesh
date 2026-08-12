//! Connect-by-carrier: local web page + pair/v1 HTTP for phone-assisted join.
//!
//! Port 17878 (default). Serves deprecated HTML (`/`, `/api/*`) and machine API
//! under `/pair/v1` (status / pending / decide) using the same `Paths` as serve.
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use mymesh_core::{
    ArmState, Config, DeviceId, JoinDecision, JoinStore, MeshState, NodeFingerprint, Paths,
    PendingJoin,
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

/// Pair HTTP listen port (matches `CARRIER_TCP` / PAIR-HTTP.md).
pub const PAIR_HTTP_PORT: u16 = 17878;
/// Path prefix for the machine pair API.
pub const PAIR_V1_PREFIX: &str = "/pair/v1";

#[derive(Clone)]
struct CarrierState {
    paths: Paths,
    secret: [u8; 32],
    label: String,
    pending_peer: Arc<Mutex<Option<String>>>,
    status: Arc<Mutex<String>>,
    /// Arm-scoped bootstrap secret (raw 32 bytes). None when disarmed/expired.
    bootstrap: Arc<Mutex<Option<BootstrapToken>>>,
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
    info!(%url, %host_base, "carrier + pair/v1 listening");

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
    Router::new()
        // Deprecated HTML / phone-paste fallback
        .route("/", get(page))
        .route("/api/status", get(api_status))
        .route("/api/peer", post(api_peer))
        .route("/api/local", get(api_local))
        // pair/v1 machine API
        .route("/pair/v1/status", get(pair_status))
        .route("/pair/v1/pending", get(pair_pending))
        .route("/pair/v1/decide", post(pair_decide))
        .layer(CorsLayer::permissive())
        .with_state(st)
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
}
