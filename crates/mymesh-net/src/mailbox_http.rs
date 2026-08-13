//! HTTP pairing mailbox + self-host admin last-mile (`mymesh mailbox`).
//!
//! Admin routes are **not** a public relay product. The mailbox cannot see
//! enrollments.json: it verifies device bind only and stores opaque bytes.
use crate::rendezvous::Rendezvous;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::header::HeaderMap;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mymesh_core::wire::{
    mailbox_bind_preimage, MailboxBind, ADMIN_BIND_SKEW_SECS, ADMIN_MAILBOX_MAX_BYTES,
    ADMIN_MAILBOX_POLL_MS, ADMIN_MAILBOX_TTL_SECS,
};
use mymesh_core::{client_ip_key, Error, LimitKind, RateLimited, Result};
use mymesh_crypto::IdentityPublic;
use mymesh_protocol::PairingMessage;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Opaque inbox/outbox budget (F6).
pub const ADMIN_MAILBOX_MAX_BYTES_NET: usize = ADMIN_MAILBOX_MAX_BYTES;
/// Default long-poll for admin GET.
pub const ADMIN_MAILBOX_POLL_MS_NET: u64 = ADMIN_MAILBOX_POLL_MS;

#[derive(Clone)]
pub struct HttpMailbox {
    base: String,
    client: reqwest::Client,
    ttl_ms: u64,
}

impl HttpMailbox {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            ttl_ms: 600_000,
        }
    }

    fn url(&self, code: &str, lane: &str) -> String {
        let safe: String = code
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{}/v1/box/{safe}/{lane}", self.base)
    }

    fn lane(as_host: bool, outbound: bool) -> &'static str {
        match (as_host, outbound) {
            (true, true) | (false, false) => "h2g",
            (true, false) | (false, true) => "g2h",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    msg: PairingMessage,
}

#[async_trait]
impl Rendezvous for HttpMailbox {
    async fn send(&self, code: &str, as_host: bool, msg: PairingMessage) -> Result<()> {
        let url = self.url(code, Self::lane(as_host, true));
        let res = self
            .client
            .post(&url)
            .json(&Envelope { msg })
            .send()
            .await
            .map_err(|e| Error::Session(format!("mailbox send: {e}")))?;
        if !res.status().is_success() {
            return Err(Error::Session(format!(
                "mailbox send status {}",
                res.status()
            )));
        }
        Ok(())
    }

    async fn recv(&self, code: &str, as_host: bool) -> Result<PairingMessage> {
        let url = self.url(code, Self::lane(as_host, false));
        let deadline = Instant::now() + Duration::from_millis(self.ttl_ms);
        loop {
            if Instant::now() > deadline {
                return Err(Error::Pairing("mailbox recv timeout".into()));
            }
            let res = self
                .client
                .get(&url)
                .query(&[("wait_ms", "5000")])
                .send()
                .await
                .map_err(|e| Error::Session(format!("mailbox recv: {e}")))?;
            if res.status().as_u16() == 204 {
                continue;
            }
            if !res.status().is_success() {
                return Err(Error::Session(format!(
                    "mailbox recv status {}",
                    res.status()
                )));
            }
            let env: Envelope = res
                .json()
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?;
            return Ok(env.msg);
        }
    }
}

// --- Server ---

struct Lane {
    queue: VecDeque<PairingMessage>,
    waiters: VecDeque<oneshot::Sender<PairingMessage>>,
    last: Instant,
}

impl Default for Lane {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            waiters: VecDeque::new(),
            last: Instant::now(),
        }
    }
}

impl Lane {
    fn push(&mut self, msg: PairingMessage) {
        self.last = Instant::now();
        if let Some(w) = self.waiters.pop_front() {
            let _ = w.send(msg);
        } else {
            self.queue.push_back(msg);
        }
    }
}

struct ByteLane {
    queue: VecDeque<(Vec<u8>, Instant)>,
    waiters: VecDeque<oneshot::Sender<Vec<u8>>>,
    last: Instant,
}

impl Default for ByteLane {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            waiters: VecDeque::new(),
            last: Instant::now(),
        }
    }
}

impl ByteLane {
    fn prune(&mut self, ttl: Duration) {
        let now = Instant::now();
        while let Some((_, t)) = self.queue.front() {
            if now.duration_since(*t) >= ttl {
                self.queue.pop_front();
            } else {
                break;
            }
        }
    }

    fn push(&mut self, msg: Vec<u8>, ttl: Duration) {
        self.prune(ttl);
        self.last = Instant::now();
        // Timed-out GETs drop `rx` but leave `tx` queued. Skip closed
        // waiters so the next PUT is not delivered into the void.
        let mut msg = Some(msg);
        while let Some(w) = self.waiters.pop_front() {
            if w.is_closed() {
                continue;
            }
            let payload = msg.take().expect("payload still pending");
            match w.send(payload) {
                Ok(()) => return,
                Err(payload) => msg = Some(payload),
            }
        }
        let msg = msg.expect("payload still pending");
        while self.queue.len() >= 8 {
            self.queue.pop_front();
        }
        self.queue.push_back((msg, Instant::now()));
    }

    fn pop(&mut self, ttl: Duration) -> Option<Vec<u8>> {
        self.prune(ttl);
        self.last = Instant::now();
        self.queue.pop_front().map(|(m, _)| m)
    }
}

struct AdminBox {
    inbox: ByteLane,
    outbox: ByteLane,
}

impl Default for AdminBox {
    fn default() -> Self {
        Self {
            inbox: ByteLane::default(),
            outbox: ByteLane::default(),
        }
    }
}

struct BoundDid {
    at: Instant,
    /// Node-only capability for GET inbox / POST outbox (not enrollment).
    token: String,
}

#[derive(Clone)]
struct MailboxState {
    boxes: Arc<Mutex<HashMap<String, Lane>>>,
    admin: Arc<Mutex<HashMap<String, AdminBox>>>,
    bound: Arc<Mutex<HashMap<String, BoundDid>>>,
    metrics_dir: Option<PathBuf>,
}

impl MailboxState {
    fn new(metrics_dir: Option<PathBuf>) -> Self {
        Self {
            boxes: Arc::new(Mutex::new(HashMap::new())),
            admin: Arc::new(Mutex::new(HashMap::new())),
            bound: Arc::new(Mutex::new(HashMap::new())),
            metrics_dir,
        }
    }
}

/// Router used by `mymesh mailbox` and tests.
pub fn mailbox_router(metrics_dir: Option<PathBuf>) -> Router {
    let state = MailboxState::new(metrics_dir);
    let gc_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let ttl = Duration::from_secs(ADMIN_MAILBOX_TTL_SECS);
            {
                let mut g = gc_state.boxes.lock();
                g.retain(|_, lane| lane.last.elapsed() < ttl);
            }
            {
                let mut g = gc_state.bound.lock();
                g.retain(|_, b| b.at.elapsed() < ttl);
            }
            {
                let mut g = gc_state.admin.lock();
                g.retain(|_, box_| {
                    box_.inbox.last.elapsed() < ttl || box_.outbox.last.elapsed() < ttl
                });
                for box_ in g.values_mut() {
                    box_.inbox.prune(ttl);
                    box_.outbox.prune(ttl);
                }
            }
        }
    });

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/box/{code}/{lane}", post(post_msg).get(get_msg))
        .route("/v1/admin/{device_id}/bind", post(admin_bind))
        .route(
            "/v1/admin/{device_id}/inbox",
            post(admin_put_inbox)
                .get(admin_get_inbox)
                .layer(DefaultBodyLimit::max(ADMIN_MAILBOX_MAX_BYTES)),
        )
        .route(
            "/v1/admin/{device_id}/outbox",
            post(admin_put_outbox)
                .get(admin_get_outbox)
                .layer(DefaultBodyLimit::max(ADMIN_MAILBOX_MAX_BYTES)),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run_mailbox_server(bind: SocketAddr) -> Result<()> {
    run_mailbox_server_with_metrics(bind, None).await
}

pub async fn run_mailbox_server_with_metrics(
    bind: SocketAddr,
    metrics_dir: Option<PathBuf>,
) -> Result<()> {
    let app = mailbox_router(metrics_dir);
    info!(%bind, "mymesh mailbox listening (SPAKE + /v1/admin; self-host, not a product)");
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(Error::Io)?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| Error::Session(format!("mailbox serve: {e}")))
}

async fn post_msg(
    State(state): State<MailboxState>,
    Path((code, lane)): Path<(String, String)>,
    Json(env): Json<Envelope>,
) -> std::result::Result<StatusCode, StatusCode> {
    if lane != "h2g" && lane != "g2h" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = format!("{code}/{lane}");
    let mut g = state.boxes.lock();
    g.entry(key).or_default().push(env.msg);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WaitQuery {
    wait_ms: Option<u64>,
}

async fn get_msg(
    State(state): State<MailboxState>,
    Path((code, lane)): Path<(String, String)>,
    Query(q): Query<WaitQuery>,
) -> std::result::Result<Json<Envelope>, StatusCode> {
    if lane != "h2g" && lane != "g2h" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = format!("{code}/{lane}");
    let wait_ms = q.wait_ms.unwrap_or(0).min(30_000);

    let rx = {
        let mut g = state.boxes.lock();
        let lane_ent = g.entry(key).or_default();
        if let Some(msg) = lane_ent.queue.pop_front() {
            lane_ent.last = Instant::now();
            return Ok(Json(Envelope { msg }));
        }
        if wait_ms == 0 {
            return Err(StatusCode::NO_CONTENT);
        }
        let (tx, rx) = oneshot::channel();
        lane_ent.waiters.push_back(tx);
        rx
    };

    match tokio::time::timeout(Duration::from_millis(wait_ms), rx).await {
        Ok(Ok(msg)) => Ok(Json(Envelope { msg })),
        _ => Err(StatusCode::NO_CONTENT),
    }
}

// ── Admin last-mile (opaque, bind-gated) ────────────────────────────────────

struct OptionalPeer(Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalPeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(OptionalPeer(peer))
    }
}

fn rate_limit_ip(peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let rip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    client_ip_key(peer, xff, rip)
}

fn limit_check(
    state: &MailboxState,
    kind: LimitKind,
    key: &str,
) -> std::result::Result<(), RateLimited> {
    if let Some(dir) = state.metrics_dir.as_ref() {
        mymesh_core::rate_limit_check_shared(dir, kind, key)
    } else {
        mymesh_core::rate_limit_check(kind, key)
    }
}

fn rate_limited(rl: RateLimited) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "code": "rate_limited",
            "error": format!("rate limit exceeded; retry after {}s", rl.retry_after_secs),
        })),
    )
        .into_response();
    if let Ok(hv) = axum::http::HeaderValue::from_str(&rl.retry_after_secs.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, hv);
    }
    resp
}

fn normalize_did_path(raw: &str) -> std::result::Result<String, StatusCode> {
    let t = raw.trim().to_ascii_lowercase();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(t)
}

fn parse_did32(hex_str: &str) -> std::result::Result<[u8; 32], StatusCode> {
    let t = normalize_did_path(hex_str)?;
    let bytes = hex::decode(t).map_err(|_| StatusCode::BAD_REQUEST)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| StatusCode::BAD_REQUEST)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_sig64(hex_str: &str) -> std::result::Result<[u8; 64], StatusCode> {
    let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(cleaned).map_err(|_| StatusCode::BAD_REQUEST)?;
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| StatusCode::BAD_REQUEST)
}

fn is_bound(state: &MailboxState, did: &str) -> bool {
    let ttl = Duration::from_secs(ADMIN_MAILBOX_TTL_SECS);
    let mut g = state.bound.lock();
    match g.get(did) {
        Some(b) if b.at.elapsed() < ttl => true,
        Some(_) => {
            g.remove(did);
            false
        }
        None => false,
    }
}

async fn admin_bind(
    State(state): State<MailboxState>,
    OptionalPeer(peer): OptionalPeer,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<MailboxBind>,
) -> Response {
    let ip = rate_limit_ip(peer, &headers);
    if let Err(rl) = limit_check(&state, LimitKind::MailboxBind, &ip) {
        return rate_limited(rl);
    }
    let path_did = match normalize_did_path(&device_id) {
        Ok(d) => d,
        Err(s) => return s.into_response(),
    };
    let body_did = match normalize_did_path(&body.did) {
        Ok(d) => d,
        Err(s) => return s.into_response(),
    };
    if path_did != body_did {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let skew = (now_unix() - body.ts).abs();
    if skew > ADMIN_BIND_SKEW_SECS {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let did = match parse_did32(&path_did) {
        Ok(d) => d,
        Err(s) => return s.into_response(),
    };
    let sig = match parse_sig64(&body.sig_hex) {
        Ok(s) => s,
        Err(s) => return s.into_response(),
    };
    let pre = mailbox_bind_preimage(&did, body.ts);
    let pk = IdentityPublic { verifying_key: did };
    if pk.verify(&pre, &sig).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = new_bind_token();
    state.bound.lock().insert(
        path_did,
        BoundDid {
            at: Instant::now(),
            token: token.clone(),
        },
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "token": token })),
    )
        .into_response()
}

fn new_bind_token() -> String {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let val = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    val.strip_prefix("Bearer ")
        .or_else(|| val.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn token_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// GET inbox / POST outbox: bind token. Phone POST inbox / GET outbox stay open.
fn require_node_token(
    state: &MailboxState,
    did: &str,
    headers: &HeaderMap,
) -> std::result::Result<(), StatusCode> {
    if !is_bound(state, did) {
        return Err(StatusCode::NOT_FOUND);
    }
    let want = state
        .bound
        .lock()
        .get(did)
        .map(|b| b.token.clone())
        .ok_or(StatusCode::NOT_FOUND)?;
    let got = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !token_eq(&want, &got) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

enum AdminLaneKind {
    Inbox,
    Outbox,
}

async fn admin_put_inbox(
    State(state): State<MailboxState>,
    Path(device_id): Path<String>,
    body: Bytes,
) -> Response {
    admin_put(state, device_id, body, AdminLaneKind::Inbox, None)
}

async fn admin_put_outbox(
    State(state): State<MailboxState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    body: Bytes,
) -> Response {
    admin_put(state, device_id, body, AdminLaneKind::Outbox, Some(headers))
}

fn admin_put(
    state: MailboxState,
    device_id: String,
    body: Bytes,
    lane: AdminLaneKind,
    headers: Option<HeaderMap>,
) -> Response {
    let did = match normalize_did_path(&device_id) {
        Ok(d) => d,
        Err(s) => return s.into_response(),
    };
    if body.len() > ADMIN_MAILBOX_MAX_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if matches!(lane, AdminLaneKind::Inbox) {
        if let Err(rl) = limit_check(&state, LimitKind::MailboxPut, &did) {
            return rate_limited(rl);
        }
    }
    if matches!(lane, AdminLaneKind::Outbox) {
        if let Some(h) = headers.as_ref() {
            if let Err(s) = require_node_token(&state, &did, h) {
                return s.into_response();
            }
        }
    }
    if !is_bound(&state, &did) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ttl = Duration::from_secs(ADMIN_MAILBOX_TTL_SECS);
    let mut g = state.admin.lock();
    let box_ = g.entry(did).or_default();
    match lane {
        AdminLaneKind::Inbox => box_.inbox.push(body.to_vec(), ttl),
        AdminLaneKind::Outbox => box_.outbox.push(body.to_vec(), ttl),
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn admin_get_inbox(
    State(state): State<MailboxState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Response {
    admin_get(state, device_id, q, AdminLaneKind::Inbox, Some(headers)).await
}

async fn admin_get_outbox(
    State(state): State<MailboxState>,
    Path(device_id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Response {
    admin_get(state, device_id, q, AdminLaneKind::Outbox, None).await
}

async fn admin_get(
    state: MailboxState,
    device_id: String,
    q: WaitQuery,
    lane: AdminLaneKind,
    headers: Option<HeaderMap>,
) -> Response {
    let did = match normalize_did_path(&device_id) {
        Ok(d) => d,
        Err(s) => return s.into_response(),
    };
    if matches!(lane, AdminLaneKind::Inbox) {
        if let Some(h) = headers.as_ref() {
            if let Err(s) = require_node_token(&state, &did, h) {
                return s.into_response();
            }
        }
    }
    if !is_bound(&state, &did) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let wait_ms = q
        .wait_ms
        .unwrap_or(ADMIN_MAILBOX_POLL_MS)
        .min(ADMIN_MAILBOX_POLL_MS);
    let ttl = Duration::from_secs(ADMIN_MAILBOX_TTL_SECS);
    let rx = {
        let mut g = state.admin.lock();
        let box_ = g.entry(did.clone()).or_default();
        let popped = match lane {
            AdminLaneKind::Inbox => box_.inbox.pop(ttl),
            AdminLaneKind::Outbox => box_.outbox.pop(ttl),
        };
        if let Some(msg) = popped {
            return opaque_ok(msg);
        }
        if wait_ms == 0 {
            return StatusCode::NO_CONTENT.into_response();
        }
        let (tx, rx) = oneshot::channel();
        match lane {
            AdminLaneKind::Inbox => box_.inbox.waiters.push_back(tx),
            AdminLaneKind::Outbox => box_.outbox.waiters.push_back(tx),
        }
        rx
    };
    match tokio::time::timeout(Duration::from_millis(wait_ms), rx).await {
        Ok(Ok(msg)) => opaque_ok(msg),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

fn opaque_ok(msg: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        msg,
    )
        .into_response()
}

// ── Client (serve poller / phone) ───────────────────────────────────────────

/// Errors from [`AdminMailboxClient`]. Messages never include bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminMailboxError {
    Unbound,
    Unauthorized,
    TooLarge,
    RateLimited { retry_after_secs: u64 },
    Http(String),
    Status(u16),
}

impl std::fmt::Display for AdminMailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unbound => write!(f, "mailbox did unbound"),
            Self::Unauthorized => write!(f, "mailbox bind token required"),
            Self::TooLarge => write!(f, "mailbox blob too large"),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "mailbox rate limited (retry {retry_after_secs}s)")
            }
            Self::Http(m) => write!(f, "mailbox http: {m}"),
            Self::Status(s) => write!(f, "mailbox status {s}"),
        }
    }
}

impl std::error::Error for AdminMailboxError {}

/// HTTP client for `/v1/admin/{did}/*`.
#[derive(Clone)]
pub struct AdminMailboxClient {
    base: String,
    client: reqwest::Client,
    /// Bind token for GET inbox / POST outbox (node poller).
    token: Arc<Mutex<Option<String>>>,
}

impl AdminMailboxClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(35))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
            token: Arc::new(Mutex::new(None)),
        }
    }

    fn admin_url(&self, did: &str, lane: &str) -> String {
        format!("{}/v1/admin/{did}/{lane}", self.base)
    }

    pub async fn bind(&self, body: &MailboxBind) -> std::result::Result<(), AdminMailboxError> {
        let url = self.admin_url(&body.did, "bind");
        let res = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| AdminMailboxError::Http(truncate_http(&e.to_string())))?;
        let status = res.status().as_u16();
        if status == 404 {
            return Err(AdminMailboxError::Unbound);
        }
        if !(200..300).contains(&status) {
            return Err(map_status_err(status));
        }
        let v: serde_json::Value = res
            .json()
            .await
            .map_err(|e| AdminMailboxError::Http(truncate_http(&e.to_string())))?;
        let token = v
            .get("token")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AdminMailboxError::Http("bind missing token".into()))?;
        *self.token.lock() = Some(token.to_string());
        Ok(())
    }

    fn node_auth_header(&self) -> Option<String> {
        self.token.lock().as_ref().map(|t| format!("Bearer {t}"))
    }

    pub async fn put_inbox(
        &self,
        did: &str,
        bytes: &[u8],
    ) -> std::result::Result<(), AdminMailboxError> {
        self.put_lane(did, "inbox", bytes).await
    }

    pub async fn put_outbox(
        &self,
        did: &str,
        bytes: &[u8],
    ) -> std::result::Result<(), AdminMailboxError> {
        self.put_lane(did, "outbox", bytes).await
    }

    async fn put_lane(
        &self,
        did: &str,
        lane: &str,
        bytes: &[u8],
    ) -> std::result::Result<(), AdminMailboxError> {
        if bytes.len() > ADMIN_MAILBOX_MAX_BYTES {
            return Err(AdminMailboxError::TooLarge);
        }
        let url = self.admin_url(did, lane);
        let mut req = self
            .client
            .post(&url)
            .header("content-type", "application/octet-stream");
        // Node writes outbox; phone writes inbox (no bind token).
        if lane == "outbox" {
            if let Some(h) = self.node_auth_header() {
                req = req.header("authorization", h);
            }
        }
        let res = req
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| AdminMailboxError::Http(truncate_http(&e.to_string())))?;
        map_empty_status(res.status().as_u16())
    }

    pub async fn get_inbox(
        &self,
        did: &str,
        wait_ms: u64,
    ) -> std::result::Result<Option<Vec<u8>>, AdminMailboxError> {
        self.get_lane(did, "inbox", wait_ms).await
    }

    pub async fn get_outbox(
        &self,
        did: &str,
        wait_ms: u64,
    ) -> std::result::Result<Option<Vec<u8>>, AdminMailboxError> {
        self.get_lane(did, "outbox", wait_ms).await
    }

    async fn get_lane(
        &self,
        did: &str,
        lane: &str,
        wait_ms: u64,
    ) -> std::result::Result<Option<Vec<u8>>, AdminMailboxError> {
        let url = self.admin_url(did, lane);
        let mut req = self
            .client
            .get(&url)
            .query(&[("wait_ms", wait_ms.min(ADMIN_MAILBOX_POLL_MS))]);
        // Node reads inbox; phone reads outbox (no bind token).
        if lane == "inbox" {
            if let Some(h) = self.node_auth_header() {
                req = req.header("authorization", h);
            }
        }
        let res = req
            .send()
            .await
            .map_err(|e| AdminMailboxError::Http(truncate_http(&e.to_string())))?;
        let status = res.status().as_u16();
        if status == 204 {
            return Ok(None);
        }
        if status == 404 {
            return Err(AdminMailboxError::Unbound);
        }
        if !(200..300).contains(&status) {
            return Err(map_status_err(status));
        }
        let bytes = res
            .bytes()
            .await
            .map_err(|e| AdminMailboxError::Http(truncate_http(&e.to_string())))?;
        if bytes.len() > ADMIN_MAILBOX_MAX_BYTES {
            return Err(AdminMailboxError::TooLarge);
        }
        Ok(Some(bytes.to_vec()))
    }
}

fn map_empty_status(status: u16) -> std::result::Result<(), AdminMailboxError> {
    match status {
        200 | 204 => Ok(()),
        404 => Err(AdminMailboxError::Unbound),
        401 => Err(AdminMailboxError::Unauthorized),
        413 => Err(AdminMailboxError::TooLarge),
        429 => Err(AdminMailboxError::RateLimited {
            retry_after_secs: 60,
        }),
        other => Err(map_status_err(other)),
    }
}

fn map_status_err(status: u16) -> AdminMailboxError {
    match status {
        404 => AdminMailboxError::Unbound,
        401 => AdminMailboxError::Unauthorized,
        413 => AdminMailboxError::TooLarge,
        429 => AdminMailboxError::RateLimited {
            retry_after_secs: 60,
        },
        other => AdminMailboxError::Status(other),
    }
}

fn truncate_http(s: &str) -> String {
    if s.contains("http://") || s.contains("https://") || s.contains("127.0.0.1") {
        return "transport failed".into();
    }
    s.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mymesh_core::wire::{mailbox_bind_preimage, MailboxBind};
    use mymesh_crypto::Identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_metrics() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mymesh-mbox-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    async fn start() -> (String, PathBuf) {
        let metrics = tmp_metrics();
        let app = mailbox_router(Some(metrics.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (format!("http://{addr}"), metrics)
    }

    fn signed_bind(id: &Identity) -> MailboxBind {
        let did = id.device_id().to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let pre = mailbox_bind_preimage(id.device_id().as_bytes(), ts);
        MailboxBind {
            did,
            ts,
            sig_hex: hex::encode(id.sign(&pre)),
        }
    }

    #[tokio::test]
    async fn unbound_inbox_is_404() {
        let (base, metrics) = start().await;
        let c = AdminMailboxClient::new(&base);
        let did = "aa".repeat(32);
        let err = c.put_inbox(&did, b"{}").await.unwrap_err();
        assert!(matches!(err, AdminMailboxError::Unbound), "{err:?}");
        let err = c.get_inbox(&did, 0).await.unwrap_err();
        assert!(matches!(err, AdminMailboxError::Unbound), "{err:?}");
        let _ = std::fs::remove_dir_all(metrics);
    }

    #[tokio::test]
    async fn bind_then_put_and_get_inbox() {
        let (base, metrics) = start().await;
        let c = AdminMailboxClient::new(&base);
        let id = Identity::from_secret_bytes([0x33u8; 32]);
        let bind = signed_bind(&id);
        c.bind(&bind).await.unwrap();
        let payload = br#"{"wrap":"dGVzdA","nonce":"MzMzMzMzMzMzMzMzMzMzMw","ciphertext":"Yw"}"#;
        c.put_inbox(&bind.did, payload).await.unwrap();
        let got = c.get_inbox(&bind.did, 0).await.unwrap();
        assert_eq!(got.as_deref(), Some(payload.as_slice()));
        let _ = std::fs::remove_dir_all(metrics);
    }

    #[tokio::test]
    async fn timed_out_get_does_not_drop_next_put() {
        let (base, metrics) = start().await;
        let c = AdminMailboxClient::new(&base);
        let id = Identity::from_secret_bytes([0x55u8; 32]);
        let bind = signed_bind(&id);
        c.bind(&bind).await.unwrap();
        assert!(c.get_inbox(&bind.did, 1).await.unwrap().is_none());
        let payload = b"sealed-after-timeout";
        c.put_inbox(&bind.did, payload).await.unwrap();
        let got = c.get_inbox(&bind.did, 0).await.unwrap();
        assert_eq!(got.as_deref(), Some(payload.as_slice()));
        let _ = std::fs::remove_dir_all(metrics);
    }

    #[tokio::test]
    async fn inbox_get_requires_bind_token() {
        let (base, metrics) = start().await;
        let c = AdminMailboxClient::new(&base);
        let id = Identity::from_secret_bytes([0x66u8; 32]);
        let bind = signed_bind(&id);
        c.bind(&bind).await.unwrap();
        c.put_inbox(&bind.did, b"x").await.unwrap();
        let bare = reqwest::Client::new();
        let res = bare
            .get(format!("{base}/v1/admin/{}/inbox?wait_ms=0", bind.did))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);
        let got = c.get_inbox(&bind.did, 0).await.unwrap();
        assert_eq!(got.as_deref(), Some(b"x".as_slice()));
        let _ = std::fs::remove_dir_all(metrics);
    }

    #[tokio::test]
    async fn put_rejects_oversize() {
        let (base, metrics) = start().await;
        let c = AdminMailboxClient::new(&base);
        let id = Identity::from_secret_bytes([0x44u8; 32]);
        let bind = signed_bind(&id);
        c.bind(&bind).await.unwrap();
        let big = vec![0u8; ADMIN_MAILBOX_MAX_BYTES + 1];
        let err = c.put_inbox(&bind.did, &big).await.unwrap_err();
        assert!(matches!(err, AdminMailboxError::TooLarge), "{err:?}");
        let _ = std::fs::remove_dir_all(metrics);
    }
}
