//! Mesh API v1 — auth challenge (Issue 4) + topology + owner claim (S4/B4) + grants (C2).
//!
//! Routes (served on the carrier HTTP process, same Paths as serve):
//!
//! ```text
//! GET  /mesh/v1/auth/challenge   # public: nonce + methods_allowed
//! POST /mesh/v1/auth/session     # prove challenge → short-lived session token
//! GET  /mesh/v1/topology         # Authorization: Bearer <mesh session>
//! POST /mesh/v1/owner/claim      # person sig; agent co-sign MRK or claim-window
//! GET  /mesh/v1/owner            # public meta (any mesh session or public)
//! PUT  /mesh/v1/owner/backup     # person_owner session
//! GET  /mesh/v1/owner/backup     # person_owner | mrk_proof
//! DELETE /mesh/v1/owner/claim    # mrk_proof only (or host-local via CLI)
//! POST /mesh/v1/grants           # create guest grant (authz matrix)
//! GET  /mesh/v1/grants           # list grants
//! POST /mesh/v1/grants/{id}/revoke
//! ```
//!
//! Auth methods (S0 freeze / CARRIER-NEXT Issue 4):
//! - `mrk_proof`      — MRK-derived admin Ed25519 (`mymesh/mrk/admin-sign`)
//! - `person_owner`   — person Ed25519 after claim (`mesh-owner.json`)
//! - `device_member`  — device Ed25519 of Trusted member (or serving host)
//! - `pair_read`      — bootstrap-bound pair session → **minimal** topology only
//!
//! Grants mutate authz (docs/GRANTS.md): person_owner | mrk_proof |
//! device_member with Admin. Guests and unauthenticated fail closed.
//! Host-local CLI mutates `grants.json` without HTTP (filesystem trust).
//!
//! Owner claim: phone sends **person signature only** — never MMK/MRK.
//! See docs/CARRIER-NEXT.md §S4/S6 and docs/MASTER-KEY.md.

// axum Response as Err is intentional for early-return handler helpers (same as carrier).
#![allow(clippy::result_large_err)]

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::{header, request::Parts, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mymesh_core::{
    client_ip_key, not_after_days, parse_capabilities, record_mesh_auth_challenge,
    Capability, DeviceId, DeviceRecord, DeviceStore, Error, Grant, GrantConstraints, GrantObject,
    GrantRole, GrantStore, IssuedBy, LimitKind, MeshState, NodeFingerprint, PairPhase,
    PairSessionStore, Paths, RateLimitState, TrustState,
};
use mymesh_crypto::{
    accept_owner_claim, check_claim_authorized, resolve_claim_fingerprint, ClaimAuthMethod,
    Identity, IdentityPublic, MeshMasterFile, MeshOwnerFile, MmkRuntime, Mrk, OwnerBackupSealed,
    OwnerClaimRequest, HKDF_ADMIN_SIGN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Path prefix for mesh API v1.
pub const MESH_V1_PREFIX: &str = "/mesh/v1";

/// Challenge lifetime.
const CHALLENGE_TTL_SECS: i64 = 120;
/// Full-session lifetime (device_member / person_owner / mrk_proof).
const SESSION_TTL_SECS: i64 = 15 * 60;
/// pair_read session lifetime (short TTL).
const PAIR_READ_TTL_SECS: i64 = 5 * 60;
/// Nonce size for challenges and session tokens.
const NONCE_LEN: usize = 32;

const AUTH_DOMAIN: &[u8] = b"mymesh-mesh-auth-v1";

// ── Shared state (held by carrier) ──────────────────────────────────────────

/// In-memory mesh auth challenges + minted sessions (process-local).
#[derive(Default)]
pub struct MeshAuthStore {
    challenges: HashMap<String, PendingChallenge>,
    sessions: HashMap<String, MeshSession>,
}

#[derive(Clone)]
struct PendingChallenge {
    challenge_id: String,
    nonce: [u8; NONCE_LEN],
    mesh_id: String,
    expires_at: DateTime<Utc>,
    /// Consumed after successful session mint (single-use).
    consumed: bool,
}

#[derive(Clone)]
struct MeshSession {
    /// Opaque session token (raw 32B) — key is SHA-256 hex of token for lookup.
    auth_mode: AuthMethod,
    expires_at: DateTime<Utc>,
    /// For pair_read: bound pair session sid.
    pair_sid: Option<String>,
    /// Device that authenticated (device_member) or host for mrk_proof.
    subject_device_id: Option<DeviceId>,
    /// Person that authenticated (person_owner).
    person_id: Option<String>,
}

/// Auth method wire enum (S0 freeze).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    MrkProof,
    PersonOwner,
    DeviceMember,
    PairRead,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MrkProof => "mrk_proof",
            Self::PersonOwner => "person_owner",
            Self::DeviceMember => "device_member",
            Self::PairRead => "pair_read",
        }
    }

    fn is_full_roster(self) -> bool {
        !matches!(self, Self::PairRead)
    }
}

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    /// base64url of 32B nonce.
    nonce: String,
    mesh_id: String,
    methods_allowed: Vec<&'static str>,
    expires_at: String,
    served_by_device_id_hex: String,
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    challenge_id: String,
    method: AuthMethod,
    /// Device Ed25519 signature (hex) over auth preimage — device_member / person_owner / mrk_proof.
    #[serde(default)]
    sig_hex: Option<String>,
    /// device_member: proving device id (hex). Defaults to host when omitted for host self-auth.
    #[serde(default)]
    device_id_hex: Option<String>,
    /// person_owner: must match mesh-owner.json person_id when present.
    #[serde(default)]
    person_id: Option<String>,
    /// pair_read: optional sid hint (token resolves session).
    #[serde(default)]
    sid: Option<String>,
    /// pair_read: raw bootstrap token base64url (alt to Authorization Bearer).
    #[serde(default)]
    token: Option<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    session_token: String,
    auth_mode: &'static str,
    expires_at: String,
    /// `full` | `minimal` (pair_read).
    scope: &'static str,
}

#[derive(Serialize)]
struct TopologyResponse {
    mesh_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mrk_fingerprint: Option<String>,
    owner: Option<TopologyOwner>,
    roster_generation: u64,
    members: Vec<TopologyMember>,
    /// Empty until Wave C grants API.
    grants_summary: Vec<serde_json::Value>,
    served_by_device_id_hex: String,
    snapshot_sig_hex: Option<String>,
    auth_mode: &'static str,
}

#[derive(Serialize)]
struct TopologyOwner {
    person_id: String,
    display_name: String,
}

#[derive(Serialize)]
struct TopologyMember {
    device_id_hex: String,
    label: String,
    fingerprint: String,
    short_id: String,
    mesh_role: &'static str,
    capabilities: Vec<Capability>,
    trust: TrustState,
    last_seen: Option<String>,
    aliases: Vec<String>,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct MeshErrorBody {
    error: String,
    code: &'static str,
}

// ── Router attachment ───────────────────────────────────────────────────────

/// State fragment mesh routes need from the carrier process.
#[derive(Clone)]
pub struct MeshApiState {
    pub paths: Paths,
    /// Process-local HTTP rate limits (S9).
    pub rate_limits: Arc<RateLimitState>,
    pub secret: [u8; 32],
    pub label: String,
    pub auth: Arc<Mutex<MeshAuthStore>>,
}

pub fn mesh_v1_routes(st: MeshApiState) -> Router {
    Router::new()
        .route("/mesh/v1/auth/challenge", get(auth_challenge))
        .route("/mesh/v1/auth/session", post(auth_session))
        .route("/mesh/v1/topology", get(topology))
        .route(
            "/mesh/v1/owner/claim",
            post(owner_claim).delete(owner_clear),
        )
        .route("/mesh/v1/owner", get(owner_get))
        .route(
            "/mesh/v1/owner/backup",
            put(owner_backup_put).get(owner_backup_get),
        )
        .route("/mesh/v1/grants", post(grants_create).get(grants_list))
        .route("/mesh/v1/grants/{id}/revoke", post(grants_revoke))
        .with_state(st)
}

// ── Challenge material ──────────────────────────────────────────────────────

/// Canonical preimage signed by device / person / MRK admin key.
///
/// ```text
/// "mymesh-mesh-auth-v1" || 0x00 || challenge_id || 0x00 || nonce_32
///   || 0x00 || mesh_id || 0x00 || method
/// ```
pub fn auth_challenge_preimage(
    challenge_id: &str,
    nonce: &[u8; NONCE_LEN],
    mesh_id: &str,
    method: AuthMethod,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        AUTH_DOMAIN.len()
            + 1
            + challenge_id.len()
            + 1
            + NONCE_LEN
            + 1
            + mesh_id.len()
            + 1
            + method.as_str().len(),
    );
    out.extend_from_slice(AUTH_DOMAIN);
    out.push(0);
    out.extend_from_slice(challenge_id.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce);
    out.push(0);
    out.extend_from_slice(mesh_id.as_bytes());
    out.push(0);
    out.extend_from_slice(method.as_str().as_bytes());
    out
}

fn new_challenge_id() -> String {
    // ULID-like: time millis hex + 10 random bytes hex (compact, sortable-ish).
    let ms = Utc::now().timestamp_millis() as u64;
    let mut r = [0u8; 10];
    OsRng.fill_bytes(&mut r);
    format!("{:016x}{}", ms, hex::encode(r))
}

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64_32(s: &str) -> Option<[u8; 32]> {
    let v = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn mesh_err(status: StatusCode, code: &'static str, error: impl Into<String>) -> Response {
    (
        status,
        Json(MeshErrorBody {
            error: error.into(),
            code,
        }),
    )
        .into_response()
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

fn session_token_key(raw: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw))
}

fn parse_sig_hex(s: &str) -> Option<[u8; 64]> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(cleaned).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&bytes);
    Some(a)
}

fn host_identity(secret: &[u8; 32]) -> Identity {
    Identity::from_secret_bytes(*secret)
}

/// Admin signing identity derived from MRK (HKDF admin-sign seed).
pub fn mrk_admin_identity(mrk: &Mrk) -> Identity {
    let seed = mrk.derive(HKDF_ADMIN_SIGN);
    Identity::from_secret_bytes(seed)
}

fn try_load_mrk(paths: &Paths) -> Option<Mrk> {
    MmkRuntime::load(paths.mmk_runtime_file())
        .ok()
        .flatten()
        .and_then(|rt| rt.to_mrk().ok())
}

fn methods_allowed(paths: &Paths) -> Vec<&'static str> {
    let mut m = vec![AuthMethod::DeviceMember.as_str()];
    if MeshMasterFile::exists(paths.mesh_master_file()) {
        m.push(AuthMethod::MrkProof.as_str());
    }
    if paths.mesh_owner_file().exists() {
        m.push(AuthMethod::PersonOwner.as_str());
    }
    // pair_read when any open (non-expired open-phase) session exists.
    if let Ok(store) = PairSessionStore::open(paths.pair_sessions_dir()) {
        if let Ok(list) = store.list() {
            let open = list.iter().any(|s| {
                !s.is_expired_now()
                    && matches!(
                        s.effective_phase(),
                        PairPhase::Armed
                            | PairPhase::Bound
                            | PairPhase::Decided
                            | PairPhase::Completing
                            | PairPhase::Completed
                    )
            });
            if open {
                m.push(AuthMethod::PairRead.as_str());
            }
        }
    }
    m
}

// ── Handlers ────────────────────────────────────────────────────────────────

fn mesh_rate_limited(retry_after_secs: u64) -> Response {
    let mut resp = mesh_err(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        format!("rate limit exceeded; retry after {retry_after_secs}s"),
    );
    let hv = header::HeaderValue::from_str(&retry_after_secs.to_string())
        .unwrap_or_else(|_| header::HeaderValue::from_static("60"));
    resp.headers_mut().insert(header::RETRY_AFTER, hv);
    resp
}

/// Optional TCP peer (see carrier::OptionalPeer).
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

/// IP rate-limit key: peer primary; XFF only if `MYMESH_TRUST_PROXY`.
fn rate_limit_ip(peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let rip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    client_ip_key(peer, xff, rip)
}

async fn auth_challenge(
    State(st): State<MeshApiState>,
    OptionalPeer(peer): OptionalPeer,
    headers: HeaderMap,
) -> Response {
    // S9: 30 / min / ip (TCP peer; XFF only with MYMESH_TRUST_PROXY)
    let ip = rate_limit_ip(peer, &headers);
    if let Err(rl) = st.rate_limits.check(LimitKind::MeshAuthChallenge, &ip) {
        record_mesh_auth_challenge(st.paths.metrics_dir());
        return mesh_rate_limited(rl.retry_after_secs);
    }
    record_mesh_auth_challenge(st.paths.metrics_dir());

    let mesh = match MeshState::load(st.paths.mesh_file()) {
        Ok(m) => m,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("mesh load: {e}"),
            );
        }
    };
    let host = host_identity(&st.secret);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let challenge_id = new_challenge_id();
    let expires_at = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS);
    let methods = methods_allowed(&st.paths);

    {
        let mut store = st.auth.lock().await;
        // Opportunistic GC of expired challenges.
        store
            .challenges
            .retain(|_, c| c.expires_at > Utc::now() && !c.consumed);
        store.challenges.insert(
            challenge_id.clone(),
            PendingChallenge {
                challenge_id: challenge_id.clone(),
                nonce,
                mesh_id: mesh.mesh_id.clone(),
                expires_at,
                consumed: false,
            },
        );
    }

    Json(ChallengeResponse {
        challenge_id,
        nonce: encode_b64(&nonce),
        mesh_id: mesh.mesh_id,
        methods_allowed: methods,
        expires_at: rfc3339(expires_at),
        served_by_device_id_hex: host.device_id().to_string(),
    })
    .into_response()
}

async fn auth_session(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> Response {
    // Take challenge (must exist, unexpired, unconsumed).
    let challenge = {
        let mut store = st.auth.lock().await;
        store.sessions.retain(|_, s| s.expires_at > Utc::now());
        match store.challenges.get_mut(&body.challenge_id) {
            Some(c) if c.consumed => {
                return mesh_err(
                    StatusCode::CONFLICT,
                    "challenge_consumed",
                    "challenge already used",
                );
            }
            Some(c) if c.expires_at <= Utc::now() => {
                return mesh_err(StatusCode::GONE, "challenge_expired", "challenge expired");
            }
            Some(c) => {
                c.consumed = true;
                c.clone()
            }
            None => {
                return mesh_err(
                    StatusCode::NOT_FOUND,
                    "challenge_not_found",
                    "unknown challenge_id",
                );
            }
        }
    };

    let preimage = auth_challenge_preimage(
        &challenge.challenge_id,
        &challenge.nonce,
        &challenge.mesh_id,
        body.method,
    );

    let result = match body.method {
        AuthMethod::DeviceMember => prove_device_member(&st, &body, &preimage),
        AuthMethod::MrkProof => prove_mrk(&st, &body, &preimage),
        AuthMethod::PersonOwner => prove_person(&st, &body, &preimage),
        AuthMethod::PairRead => prove_pair_read(&st, &headers, &body),
    };

    let (subject_device_id, person_id, pair_sid) = match result {
        Ok(x) => x,
        Err(r) => {
            // Allow retry: un-consume challenge on proof failure (except expiry).
            let mut store = st.auth.lock().await;
            if let Some(c) = store.challenges.get_mut(&body.challenge_id) {
                if c.expires_at > Utc::now() {
                    c.consumed = false;
                }
            }
            return r;
        }
    };

    let ttl = if body.method == AuthMethod::PairRead {
        PAIR_READ_TTL_SECS
    } else {
        SESSION_TTL_SECS
    };
    let expires_at = Utc::now() + Duration::seconds(ttl);
    let mut token_raw = [0u8; 32];
    OsRng.fill_bytes(&mut token_raw);
    let key = session_token_key(&token_raw);

    {
        let mut store = st.auth.lock().await;
        store.sessions.insert(
            key,
            MeshSession {
                auth_mode: body.method,
                expires_at,
                pair_sid,
                subject_device_id,
                person_id,
            },
        );
        // Challenge fully spent.
        store.challenges.remove(&body.challenge_id);
    }

    Json(SessionResponse {
        session_token: encode_b64(&token_raw),
        auth_mode: body.method.as_str(),
        expires_at: rfc3339(expires_at),
        scope: if body.method.is_full_roster() {
            "full"
        } else {
            "minimal"
        },
    })
    .into_response()
}

type ProveOk = (Option<DeviceId>, Option<String>, Option<String>);

fn prove_device_member(
    st: &MeshApiState,
    body: &SessionRequest,
    preimage: &[u8],
) -> Result<ProveOk, Response> {
    let host = host_identity(&st.secret);
    let host_id = host.device_id();

    let device_id = if let Some(hex) = body.device_id_hex.as_deref() {
        DeviceId::from_str_hex(hex).map_err(|e| {
            mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_device_id",
                format!("device_id_hex: {e}"),
            )
        })?
    } else {
        host_id
    };

    let sig = body
        .sig_hex
        .as_deref()
        .and_then(parse_sig_hex)
        .ok_or_else(|| {
            mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "sig_hex required (64-byte Ed25519 hex)",
            )
        })?;

    // Host self-auth: verify with host identity.
    if device_id == host_id {
        let pubk = IdentityPublic {
            verifying_key: host.verifying_key_bytes(),
        };
        pubk.verify(preimage, &sig).map_err(|_| {
            mesh_err(
                StatusCode::UNAUTHORIZED,
                "invalid_proof",
                "device signature verification failed",
            )
        })?;
        return Ok((Some(device_id), None, None));
    }

    // Peer: must be Trusted in DeviceStore. DeviceId == verifying key bytes.
    let store = DeviceStore::open(st.paths.devices_file()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("device store: {e}"),
        )
    })?;
    let rec = store.get(&device_id).ok_or_else(|| {
        mesh_err(
            StatusCode::FORBIDDEN,
            "not_member",
            "device not in mesh store",
        )
    })?;
    if rec.trust != TrustState::Trusted {
        return Err(mesh_err(
            StatusCode::FORBIDDEN,
            "not_member",
            "device is not Trusted",
        ));
    }

    let pubk = IdentityPublic {
        verifying_key: *device_id.as_bytes(),
    };
    pubk.verify(preimage, &sig).map_err(|_| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "device signature verification failed",
        )
    })?;
    Ok((Some(device_id), None, None))
}

fn prove_mrk(
    st: &MeshApiState,
    body: &SessionRequest,
    preimage: &[u8],
) -> Result<ProveOk, Response> {
    if !MeshMasterFile::exists(st.paths.mesh_master_file()) {
        return Err(mesh_err(
            StatusCode::FORBIDDEN,
            "mmk_not_initialized",
            "mesh master key not initialized — run mymesh mesh init",
        ));
    }
    let mrk = try_load_mrk(&st.paths).ok_or_else(|| {
        mesh_err(
            StatusCode::FORBIDDEN,
            "mmk_locked",
            "mesh master key locked — unlock on agent (mymesh mesh unlock)",
        )
    })?;
    let sig = body
        .sig_hex
        .as_deref()
        .and_then(parse_sig_hex)
        .ok_or_else(|| {
            mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "sig_hex required (64-byte Ed25519 hex)",
            )
        })?;
    let admin = mrk_admin_identity(&mrk);
    let pubk = IdentityPublic {
        verifying_key: admin.verifying_key_bytes(),
    };
    pubk.verify(preimage, &sig).map_err(|_| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "MRK admin signature verification failed",
        )
    })?;
    Ok((Some(host_identity(&st.secret).device_id()), None, None))
}

fn prove_person(
    st: &MeshApiState,
    body: &SessionRequest,
    preimage: &[u8],
) -> Result<ProveOk, Response> {
    let owner = MeshOwnerFile::try_load(st.paths.mesh_owner_file())
        .map_err(|e| {
            mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("owner load: {e}"),
            )
        })?
        .ok_or_else(|| {
            mesh_err(
                StatusCode::FORBIDDEN,
                "no_owner",
                "no person owner claim on this mesh",
            )
        })?;

    if let Some(pid) = body.person_id.as_deref() {
        if pid != owner.person_id {
            return Err(mesh_err(
                StatusCode::FORBIDDEN,
                "not_owner",
                "person_id does not match owner claim",
            ));
        }
    }

    let pk_bytes = hex::decode(owner.person_public_key_hex.trim()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("owner pubkey: {e}"),
        )
    })?;
    if pk_bytes.len() != 32 {
        return Err(mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "owner person_public_key_hex must be 32 bytes",
        ));
    }
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&pk_bytes);

    let sig = body
        .sig_hex
        .as_deref()
        .and_then(parse_sig_hex)
        .ok_or_else(|| {
            mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "sig_hex required (64-byte Ed25519 hex)",
            )
        })?;

    let pubk = IdentityPublic { verifying_key: vk };
    pubk.verify(preimage, &sig).map_err(|_| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "person signature verification failed",
        )
    })?;
    Ok((None, Some(owner.person_id), None))
}

fn prove_pair_read(
    st: &MeshApiState,
    headers: &HeaderMap,
    body: &SessionRequest,
) -> Result<ProveOk, Response> {
    let token_b64 = body
        .token
        .clone()
        .or_else(|| extract_bearer(headers))
        .ok_or_else(|| {
            mesh_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "pair_read requires Bearer token or body.token",
            )
        })?;
    let raw = decode_b64_32(&token_b64).ok_or_else(|| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid pair bootstrap token encoding",
        )
    })?;

    let store = PairSessionStore::open(st.paths.pair_sessions_dir()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("pair session store: {e}"),
        )
    })?;
    let sess = store
        .find_by_token_raw(&raw)
        .map_err(|e| {
            mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("session lookup: {e}"),
            )
        })?
        .ok_or_else(|| {
            mesh_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "unknown pair bootstrap token",
            )
        })?;

    if let Some(want) = body.sid.as_deref() {
        if sess.sid != want {
            return Err(mesh_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "token does not match sid",
            ));
        }
    }
    if sess.is_expired_now() {
        return Err(mesh_err(
            StatusCode::GONE,
            "session_gone",
            "pair session expired",
        ));
    }

    Ok((Some(sess.resident_device_id), None, Some(sess.sid.clone())))
}

async fn topology(State(st): State<MeshApiState>, headers: HeaderMap) -> Response {
    let token_b64 = match extract_bearer(&headers) {
        Some(t) => t,
        None => {
            return mesh_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing Authorization Bearer mesh session",
            );
        }
    };
    let raw = match decode_b64_32(&token_b64) {
        Some(r) => r,
        None => {
            return mesh_err(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid mesh session token",
            );
        }
    };
    let key = session_token_key(&raw);
    let session = {
        let mut store = st.auth.lock().await;
        store.sessions.retain(|_, s| s.expires_at > Utc::now());
        match store.sessions.get(&key) {
            Some(s) if s.expires_at > Utc::now() => s.clone(),
            Some(_) => {
                return mesh_err(
                    StatusCode::UNAUTHORIZED,
                    "session_expired",
                    "mesh session expired",
                );
            }
            None => {
                return mesh_err(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "unknown mesh session",
                );
            }
        }
    };

    let mesh = match MeshState::load(st.paths.mesh_file()) {
        Ok(m) => m,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("mesh load: {e}"),
            );
        }
    };
    let host = host_identity(&st.secret);
    let host_id = host.device_id();

    let mrk_fingerprint = MeshMasterFile::try_load(st.paths.mesh_master_file())
        .ok()
        .flatten()
        .map(|f| f.mrk_fingerprint)
        .or_else(|| try_load_mrk(&st.paths).map(|m| m.fingerprint()));

    let owner = MeshOwnerFile::try_load(st.paths.mesh_owner_file())
        .ok()
        .flatten()
        .map(|o| TopologyOwner {
            person_id: o.person_id,
            display_name: if o.display_name.is_empty() {
                "owner".into()
            } else {
                o.display_name
            },
        });

    let members = if session.auth_mode.is_full_roster() {
        match build_full_members(&st.paths, &host_id, &st.label) {
            Ok(m) => m,
            Err(e) => {
                return mesh_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("device store: {e}"),
                );
            }
        }
    } else {
        // pair_read: session-minimal — resident + joiner only.
        match build_pair_read_members(&st.paths, session.pair_sid.as_deref()) {
            Ok(m) => m,
            Err(r) => return r,
        }
    };

    Json(TopologyResponse {
        mesh_id: mesh.mesh_id,
        mrk_fingerprint,
        owner,
        roster_generation: mesh.roster_generation,
        members,
        grants_summary: vec![],
        served_by_device_id_hex: host_id.to_string(),
        snapshot_sig_hex: None,
        auth_mode: session.auth_mode.as_str(),
    })
    .into_response()
}

// ── Owner claim + sealed backup (S4 / B4) ───────────────────────────────────

#[derive(Debug, Deserialize)]
struct OwnerClaimBody {
    person_id: String,
    person_public_key_hex: String,
    /// Person Ed25519 sig hex over S0 claim preimage (phone only — no MMK).
    claim_sig_hex: String,
    /// Unix timestamp signed in preimage.
    ts_unix: i64,
    #[serde(default)]
    display_name: Option<String>,
    /// Force replace existing owner (requires live MRK unlock, not claim window alone).
    #[serde(default)]
    replace: bool,
}

#[derive(Serialize)]
struct OwnerClaimResponse {
    ok: bool,
    person_id: String,
    mrk_fingerprint: String,
    claimed_at: String,
    auth_method: &'static str,
}

#[derive(Serialize)]
struct OwnerPublicResponse {
    claimed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    person_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mrk_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mrk_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_at: Option<String>,
    backup_stored: bool,
}

async fn owner_claim(State(st): State<MeshApiState>, Json(body): Json<OwnerClaimBody>) -> Response {
    // Agent-local MMK auth (co-sign or claim window). Phone never holds MMK.
    let auth = match check_claim_authorized(
        st.paths.mmk_runtime_file(),
        st.paths.claim_window_file(),
    ) {
        Ok(a) => a,
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("expired") {
                "claim_window_expired"
            } else {
                "mmk_locked"
            };
            return mesh_err(
                StatusCode::FORBIDDEN,
                code,
                format!(
                    "{msg}; unlock on agent (mymesh mesh unlock) or open claim window (mymesh owner allow-claim)"
                ),
            );
        }
    };

    let mesh = match MeshState::load(st.paths.mesh_file()) {
        Ok(m) => m,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("mesh load: {e}"),
            );
        }
    };

    let mrk_fp = match resolve_claim_fingerprint(
        auth,
        st.paths.mmk_runtime_file(),
        st.paths.claim_window_file(),
        st.paths.mesh_master_file(),
    ) {
        Ok(fp) => fp,
        Err(e) => {
            return mesh_err(
                StatusCode::FORBIDDEN,
                "mmk_locked",
                format!("cannot resolve mrk_fingerprint: {e}"),
            );
        }
    };

    let existing = match MeshOwnerFile::try_load(st.paths.mesh_owner_file()) {
        Ok(o) => o,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("owner load: {e}"),
            );
        }
    };

    let host = host_identity(&st.secret);
    let req = OwnerClaimRequest {
        mesh_id: mesh.mesh_id.clone(),
        person_id: body.person_id.clone(),
        person_public_key_hex: body.person_public_key_hex.clone(),
        display_name: body.display_name.unwrap_or_default(),
        ts_unix: body.ts_unix,
        claim_sig_hex: body.claim_sig_hex.clone(),
        claimed_from_device_id: Some(host.device_id().to_string()),
        replace: body.replace,
    };

    let file = match accept_owner_claim(
        &req,
        &mrk_fp,
        auth,
        existing.as_ref(),
        st.paths.mesh_owner_file(),
    ) {
        Ok(f) => f,
        Err(e) => {
            let msg = e.to_string();
            let (status, code) = if msg.contains("already claimed") {
                (StatusCode::CONFLICT, "owner_exists")
            } else if msg.contains("signature") || msg.contains("claim_sig") {
                (StatusCode::UNAUTHORIZED, "invalid_proof")
            } else if msg.contains("replace") || msg.contains("Permission") {
                (StatusCode::FORBIDDEN, "forbidden")
            } else {
                (StatusCode::BAD_REQUEST, "invalid_claim")
            };
            return mesh_err(status, code, msg);
        }
    };

    // Consume claim window after successful first claim (one-shot capability).
    if auth == ClaimAuthMethod::ClaimWindow {
        let _ = mymesh_crypto::ClaimWindowFile::clear(st.paths.claim_window_file());
    }

    Json(OwnerClaimResponse {
        ok: true,
        person_id: file.person_id,
        mrk_fingerprint: file.mrk_fingerprint,
        claimed_at: rfc3339(file.claimed_at),
        auth_method: match auth {
            ClaimAuthMethod::MrkUnlocked => "agent_cosign",
            ClaimAuthMethod::ClaimWindow => "claim_window",
        },
    })
    .into_response()
}

async fn owner_get(State(st): State<MeshApiState>) -> Response {
    let owner = match MeshOwnerFile::try_load(st.paths.mesh_owner_file()) {
        Ok(o) => o,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("owner load: {e}"),
            );
        }
    };
    let backup_stored = st.paths.owner_backup_file().exists()
        || owner.as_ref().and_then(|o| o.backup_stored_at).is_some();
    match owner {
        Some(o) => Json(OwnerPublicResponse {
            claimed: true,
            person_id: Some(o.person_id),
            display_name: Some(if o.display_name.is_empty() {
                "owner".into()
            } else {
                o.display_name
            }),
            mrk_fingerprint: Some(o.mrk_fingerprint),
            mrk_epoch: Some(o.mrk_epoch),
            claimed_at: Some(rfc3339(o.claimed_at)),
            backup_stored,
        })
        .into_response(),
        None => Json(OwnerPublicResponse {
            claimed: false,
            person_id: None,
            display_name: None,
            mrk_fingerprint: None,
            mrk_epoch: None,
            claimed_at: None,
            backup_stored: false,
        })
        .into_response(),
    }
}

async fn owner_clear(State(st): State<MeshApiState>, headers: HeaderMap) -> Response {
    // DELETE requires mrk_proof session (mesh-destructive).
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if session.auth_mode != AuthMethod::MrkProof {
        return mesh_err(
            StatusCode::FORBIDDEN,
            "mrk_required",
            "clear owner requires mrk_proof session (MMK root of policy)",
        );
    }
    match MeshOwnerFile::clear(st.paths.mesh_owner_file()) {
        Ok(true) => {
            let _ = std::fs::remove_file(st.paths.owner_backup_file());
            Json(serde_json::json!({ "ok": true, "cleared": true })).into_response()
        }
        Ok(false) => Json(serde_json::json!({ "ok": true, "cleared": false })).into_response(),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("clear owner: {e}"),
        ),
    }
}

async fn owner_backup_put(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(body): Json<OwnerBackupSealed>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if session.auth_mode != AuthMethod::PersonOwner {
        return mesh_err(
            StatusCode::FORBIDDEN,
            "person_owner_required",
            "PUT owner/backup requires person_owner session",
        );
    }
    // Bind backup person_id to claimed owner when present.
    if let Ok(Some(owner)) = MeshOwnerFile::try_load(st.paths.mesh_owner_file()) {
        if body.person_id != owner.person_id {
            return mesh_err(
                StatusCode::FORBIDDEN,
                "not_owner",
                "backup person_id does not match owner claim",
            );
        }
    }
    if let Err(e) = OwnerBackupSealed::store_blob(st.paths.owner_backup_file(), &body) {
        return mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_backup",
            format!("store sealed backup: {e}"),
        );
    }
    // Update backup slot marker on claim file when present.
    if let Ok(Some(mut owner)) = MeshOwnerFile::try_load(st.paths.mesh_owner_file()) {
        owner.mark_backup_stored();
        let _ = owner.save(st.paths.mesh_owner_file());
    }
    Json(serde_json::json!({
        "ok": true,
        "stored": true,
        "person_id": body.person_id,
    }))
    .into_response()
}

async fn owner_backup_get(State(st): State<MeshApiState>, headers: HeaderMap) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match session.auth_mode {
        AuthMethod::PersonOwner | AuthMethod::MrkProof => {}
        _ => {
            return mesh_err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "GET owner/backup requires person_owner or mrk_proof session",
            );
        }
    }
    match OwnerBackupSealed::try_load(st.paths.owner_backup_file()) {
        Ok(Some(b)) => Json(b).into_response(),
        Ok(None) => mesh_err(
            StatusCode::NOT_FOUND,
            "no_backup",
            "no sealed owner backup stored",
        ),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("backup load: {e}"),
        ),
    }
}

async fn require_mesh_session(
    st: &MeshApiState,
    headers: &HeaderMap,
) -> Result<MeshSession, Response> {
    let token_b64 = extract_bearer(headers).ok_or_else(|| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization Bearer mesh session",
        )
    })?;
    let raw = decode_b64_32(&token_b64).ok_or_else(|| {
        mesh_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid mesh session token",
        )
    })?;
    let key = session_token_key(&raw);
    let mut store = st.auth.lock().await;
    store.sessions.retain(|_, s| s.expires_at > Utc::now());
    match store.sessions.get(&key) {
        Some(s) if s.expires_at > Utc::now() => Ok(s.clone()),
        Some(_) => Err(mesh_err(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "mesh session expired",
        )),
        None => Err(mesh_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "unknown mesh session",
        )),
    }
}

// ── Grants create / list / revoke (C2) ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateGrantBody {
    /// Subject (guest) device id — 64-hex. Need not be linked yet.
    subject_device_id_hex: String,
    /// Object host device id; defaults to serving host.
    #[serde(default)]
    object_device_id_hex: Option<String>,
    /// Capability names: `terminal`, `files`, `desktop`, `tcp` (not `admin`).
    capabilities: Vec<String>,
    /// Optional TTL in days → `constraints.not_after`.
    #[serde(default)]
    days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ListGrantsQuery {
    /// When true, include revoked/expired (default: active only).
    #[serde(default)]
    all: bool,
}

/// HTTP wire grant — DeviceIds as hex (mesh/v1 convention). Store serde stays bytes.
#[derive(Serialize)]
struct GrantHttp {
    grant_id: String,
    mesh_id: String,
    subject_device_id_hex: String,
    object: GrantObjectHttp,
    role: GrantRole,
    capabilities: Vec<Capability>,
    constraints: GrantConstraints,
    issued_by: IssuedBy,
    issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GrantObjectHttp {
    Device { device_id_hex: String },
}

impl From<&Grant> for GrantHttp {
    fn from(g: &Grant) -> Self {
        let object = match &g.object {
            GrantObject::Device { device_id } => GrantObjectHttp::Device {
                device_id_hex: device_id.to_string(),
            },
        };
        Self {
            grant_id: g.grant_id.clone(),
            mesh_id: g.mesh_id.clone(),
            subject_device_id_hex: g.subject_device_id.to_string(),
            object,
            role: g.role,
            capabilities: g.capabilities.clone(),
            constraints: g.constraints.clone(),
            issued_by: g.issued_by.clone(),
            issued_at: g.issued_at,
            revoked_at: g.revoked_at,
        }
    }
}

#[derive(Serialize)]
struct GrantsListResponse {
    grants: Vec<GrantHttp>,
}

/// Authz for grant create/list/revoke (docs/GRANTS.md + CARRIER-NEXT matrix).
///
/// Allow: `person_owner` | `mrk_proof` | `device_member` with Admin.
/// Deny: guest, pair_read, device_member without Admin, unauthenticated (caller).
fn require_grants_mutate_authz(
    st: &MeshApiState,
    session: &MeshSession,
) -> Result<(), Response> {
    match session.auth_mode {
        AuthMethod::PersonOwner | AuthMethod::MrkProof => Ok(()),
        AuthMethod::DeviceMember => {
            let device_id = session.subject_device_id.ok_or_else(|| {
                mesh_err(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "device_member session missing subject device",
                )
            })?;
            // Serving host = agent identity (data-dir owner); not host-local CLI but
            // same process trust as filesystem access for this node.
            let host_id = host_identity(&st.secret).device_id();
            if device_id == host_id {
                return Ok(());
            }
            let store = DeviceStore::open(st.paths.devices_file()).map_err(|e| {
                mesh_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("device store: {e}"),
                )
            })?;
            let Some(rec) = store.get(&device_id) else {
                return Err(mesh_err(
                    StatusCode::FORBIDDEN,
                    "not_member",
                    "device not in mesh store",
                ));
            };
            // Explicit guest reject (fail closed; guests never get Admin path).
            if rec.mesh_role.is_guest() {
                return Err(mesh_err(
                    StatusCode::FORBIDDEN,
                    "guest_forbidden",
                    "guests cannot create, list, or revoke grants",
                ));
            }
            if rec.trust != TrustState::Trusted {
                return Err(mesh_err(
                    StatusCode::FORBIDDEN,
                    "not_member",
                    "device is not Trusted",
                ));
            }
            if !store.has_admin(&device_id) {
                return Err(mesh_err(
                    StatusCode::FORBIDDEN,
                    "admin_required",
                    "device_member needs Admin capability to mutate grants",
                ));
            }
            Ok(())
        }
        AuthMethod::PairRead => Err(mesh_err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "pair_read cannot mutate grants",
        )),
    }
}

fn issued_by_for_session(st: &MeshApiState, session: &MeshSession) -> IssuedBy {
    match session.auth_mode {
        AuthMethod::PersonOwner => IssuedBy::PersonId(
            session
                .person_id
                .clone()
                .unwrap_or_else(|| "person_owner".into()),
        ),
        AuthMethod::MrkProof => {
            let fp = try_load_mrk(&st.paths)
                .map(|m| m.fingerprint())
                .or_else(|| {
                    MeshMasterFile::try_load(st.paths.mesh_master_file())
                        .ok()
                        .flatten()
                        .map(|f| f.mrk_fingerprint)
                })
                .unwrap_or_else(|| "mrk".into());
            IssuedBy::MasterKeyProof(fp)
        }
        AuthMethod::DeviceMember => match session.subject_device_id {
            Some(id) => IssuedBy::device(&id),
            None => IssuedBy::DeviceId("unknown".into()),
        },
        AuthMethod::PairRead => IssuedBy::DeviceId("pair_read".into()),
    }
}

fn parse_grant_capabilities(names: &[String]) -> Result<Vec<Capability>, Response> {
    if names.is_empty() {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_caps",
            "capabilities must not be empty",
        ));
    }
    parse_capabilities(&names.join(",")).map_err(|e| {
        mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_caps",
            e.to_string(),
        )
    })
}

async fn grants_create(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateGrantBody>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_grants_mutate_authz(&st, &session) {
        return r;
    }

    let subject = match DeviceId::from_str_hex(&body.subject_device_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_device_id",
                format!("subject_device_id_hex: {e}"),
            );
        }
    };
    let host_id = host_identity(&st.secret).device_id();
    let object = if let Some(hex) = body.object_device_id_hex.as_deref() {
        match DeviceId::from_str_hex(hex) {
            Ok(id) => id,
            Err(e) => {
                return mesh_err(
                    StatusCode::BAD_REQUEST,
                    "invalid_device_id",
                    format!("object_device_id_hex: {e}"),
                );
            }
        }
    } else {
        host_id
    };

    let capabilities = match parse_grant_capabilities(&body.capabilities) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Product policy: guest grants reject Admin (GrantStore also enforces).
    if capabilities.contains(&Capability::Admin) {
        return mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_caps",
            "Admin capability is not allowed on guest grants",
        );
    }

    let mesh = match MeshState::load(st.paths.mesh_file()) {
        Ok(m) => m,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("mesh load: {e}"),
            );
        }
    };

    let mut grants = match GrantStore::open(st.paths.grants_file()) {
        Ok(g) => g,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("grant store: {e}"),
            );
        }
    };

    match grants.create_guest(
        mesh.mesh_id,
        subject,
        object,
        capabilities,
        not_after_days(body.days),
        issued_by_for_session(&st, &session),
    ) {
        Ok(g) => (StatusCode::CREATED, Json(GrantHttp::from(&g))).into_response(),
        // Config = validation (empty caps / Admin on guest); other variants unexpected.
        Err(Error::Config(msg)) => mesh_err(StatusCode::BAD_REQUEST, "invalid_caps", msg),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("create grant: {e}"),
        ),
    }
}

async fn grants_list(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Query(q): Query<ListGrantsQuery>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_grants_mutate_authz(&st, &session) {
        return r;
    }

    let grants = match GrantStore::open(st.paths.grants_file()) {
        Ok(g) => g,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("grant store: {e}"),
            );
        }
    };
    let now = Utc::now();
    let list: Vec<GrantHttp> = grants
        .list()
        .into_iter()
        .filter(|g| q.all || g.is_active(now))
        .map(GrantHttp::from)
        .collect();
    Json(GrantsListResponse { grants: list }).into_response()
}

async fn grants_revoke(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_grants_mutate_authz(&st, &session) {
        return r;
    }

    let mut grants = match GrantStore::open(st.paths.grants_file()) {
        Ok(g) => g,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("grant store: {e}"),
            );
        }
    };
    match grants.revoke(&id) {
        Ok(g) => Json(GrantHttp::from(&g)).into_response(),
        Err(Error::NotFound(_)) => mesh_err(
            StatusCode::NOT_FOUND,
            "grant_not_found",
            format!("grant {id} not found"),
        ),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("revoke grant: {e}"),
        ),
    }
}

fn build_full_members(
    paths: &Paths,
    host_id: &DeviceId,
    host_label: &str,
) -> mymesh_core::Result<Vec<TopologyMember>> {
    let store = DeviceStore::open(paths.devices_file())?;
    let mut out: Vec<TopologyMember> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Serving host always appears as a member (even if not yet in devices.json).
    out.push(topology_member_from_host(host_id, host_label));
    seen.insert(*host_id);

    for rec in store.list() {
        // Full member roster: Trusted members only (guests excluded — GUEST.md / S5).
        if rec.trust != TrustState::Trusted {
            continue;
        }
        if rec.mesh_role.is_guest() {
            continue;
        }
        if !seen.insert(rec.id) {
            continue;
        }
        out.push(topology_member_from_record(rec));
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

fn build_pair_read_members(
    paths: &Paths,
    pair_sid: Option<&str>,
) -> Result<Vec<TopologyMember>, Response> {
    let sid = pair_sid.ok_or_else(|| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "pair_read session missing sid binding",
        )
    })?;
    let store = PairSessionStore::open(paths.pair_sessions_dir()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("pair store: {e}"),
        )
    })?;
    let sess = store
        .load(sid)
        .map_err(|e| {
            mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("pair load: {e}"),
            )
        })?
        .ok_or_else(|| {
            mesh_err(
                StatusCode::GONE,
                "session_gone",
                "pair session no longer available",
            )
        })?;

    let mut members = Vec::new();
    let resident = sess.resident_device_id;
    members.push(TopologyMember {
        device_id_hex: resident.to_string(),
        label: "resident".into(),
        fingerprint: NodeFingerprint::from_device_id(&resident)
            .as_str()
            .to_string(),
        short_id: resident.short(),
        mesh_role: "member",
        capabilities: Capability::all(),
        trust: TrustState::Trusted,
        last_seen: None,
        aliases: vec![],
        groups: vec![],
    });
    if let Some(joiner) = sess.joiner_device_id {
        let label = sess.joiner_label.clone().unwrap_or_else(|| "joiner".into());
        let fp = sess.joiner_fp.clone().unwrap_or_else(|| {
            NodeFingerprint::from_device_id(&joiner)
                .as_str()
                .to_string()
        });
        members.push(TopologyMember {
            device_id_hex: joiner.to_string(),
            label,
            fingerprint: fp,
            short_id: joiner.short(),
            mesh_role: "member",
            capabilities: Capability::all(),
            trust: TrustState::Trusted,
            last_seen: None,
            aliases: vec![],
            groups: vec![],
        });
    }
    Ok(members)
}

fn topology_member_from_host(id: &DeviceId, label: &str) -> TopologyMember {
    TopologyMember {
        device_id_hex: id.to_string(),
        label: label.to_string(),
        fingerprint: NodeFingerprint::from_device_id(id).as_str().to_string(),
        short_id: id.short(),
        mesh_role: "member",
        capabilities: Capability::all(),
        trust: TrustState::Trusted,
        last_seen: None,
        aliases: vec![],
        groups: vec![],
    }
}

fn topology_member_from_record(rec: &DeviceRecord) -> TopologyMember {
    TopologyMember {
        device_id_hex: rec.id.to_string(),
        label: rec.label.as_str().to_string(),
        fingerprint: rec.fingerprint.clone(),
        short_id: rec.id.short(),
        mesh_role: rec.mesh_role.as_str(),
        capabilities: rec.capabilities.clone(),
        trust: rec.trust.clone(),
        last_seen: rec.last_seen.map(rfc3339),
        aliases: rec.aliases.clone(),
        groups: rec.groups.clone(),
    }
}

// ── DeviceId helper ─────────────────────────────────────────────────────────

trait DeviceIdParse {
    fn from_str_hex(s: &str) -> Result<DeviceId, String>;
}

impl DeviceIdParse for DeviceId {
    fn from_str_hex(s: &str) -> Result<DeviceId, String> {
        s.parse::<DeviceId>().map_err(|e| e.to_string())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::extract::ConnectInfo;
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use mymesh_core::{DeviceLabel, PairEndpointClass, PairSessionStore};
    use mymesh_crypto::{mesh_init, MmkRuntime};
    use tower::ServiceExt;

    fn tmp_paths() -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-meshapi-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        let paths = Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        };
        paths.ensure().unwrap();
        paths
    }

    fn test_state(paths: Paths, secret: [u8; 32], label: &str) -> MeshApiState {
        MeshApiState {
            paths,
            rate_limits: Arc::new(RateLimitState::new()),
            secret,
            label: label.into(),
            auth: Arc::new(Mutex::new(MeshAuthStore::default())),
        }
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn get_challenge(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        (status, json_body(resp).await)
    }

    #[tokio::test]
    async fn challenge_public_lists_device_member() {
        let paths = tmp_paths();
        let secret = [0xA1u8; 32];
        let id = Identity::from_secret_bytes(secret);
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let st = test_state(paths, secret, "host-a");
        let app = mesh_v1_routes(st);
        let (status, v) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["challenge_id"].as_str().unwrap().len() > 8);
        assert!(!v["nonce"].as_str().unwrap().is_empty());
        assert!(v["methods_allowed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "device_member"));
        assert_eq!(v["served_by_device_id_hex"], id.device_id().to_string());
        assert!(!v["methods_allowed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "mrk_proof")); // no mesh-master yet
    }

    #[tokio::test]
    async fn device_member_host_session_and_full_topology() {
        let paths = tmp_paths();
        let secret = [0xB2u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Peer Trusted device in store.
        let peer_secret = [0xC3u8; 32];
        let peer = Identity::from_secret_bytes(peer_secret);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("laptop"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
                    .as_str()
                    .to_string(),
                capabilities: Capability::all(),
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec!["nb".into()],
                groups: vec!["home".into()],
                mesh_role: mymesh_core::MeshRole::Member,
            })
            .unwrap();
        // Pending peer must not appear.
        let pending = Identity::from_secret_bytes([0xD4u8; 32]);
        store
            .upsert(DeviceRecord {
                id: pending.device_id(),
                label: DeviceLabel::new("pending-phone"),
                fingerprint: NodeFingerprint::from_device_id(&pending.device_id())
                    .as_str()
                    .to_string(),
                capabilities: Capability::all(),
                trust: TrustState::Pending,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: mymesh_core::MeshRole::Member,
            })
            .unwrap();

        let st = test_state(paths.clone(), secret, "host-a");
        let app = mesh_v1_routes(st);

        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce_b64 = ch["nonce"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(&nonce_b64).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::DeviceMember);
        let sig = host.sign(&pre);

        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "device_member",
            "device_id_hex": host.device_id().to_string(),
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sess = json_body(resp).await;
        assert_eq!(sess["auth_mode"], "device_member");
        assert_eq!(sess["scope"], "full");
        let token = sess["session_token"].as_str().unwrap().to_string();

        // Topology without auth → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let topo = json_body(resp).await;
        assert_eq!(topo["mesh_id"], mesh.mesh_id);
        assert_eq!(topo["auth_mode"], "device_member");
        assert_eq!(
            topo["served_by_device_id_hex"],
            host.device_id().to_string()
        );
        let members = topo["members"].as_array().unwrap();
        // host + trusted peer only (not pending)
        assert_eq!(members.len(), 2);
        let ids: Vec<&str> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&host.device_id().to_string().as_str()));
        assert!(ids.contains(&peer.device_id().to_string().as_str()));
        assert!(!ids.contains(&pending.device_id().to_string().as_str()));
        let peer_m = members
            .iter()
            .find(|m| m["device_id_hex"] == peer.device_id().to_string())
            .unwrap();
        assert_eq!(peer_m["label"], "laptop");
        assert_eq!(peer_m["mesh_role"], "member");
        assert_eq!(peer_m["aliases"][0], "nb");
        assert_eq!(peer_m["groups"][0], "home");
        assert!(topo["grants_summary"].as_array().unwrap().is_empty());
        assert!(topo["snapshot_sig_hex"].is_null());
    }

    #[tokio::test]
    async fn peer_device_member_must_be_trusted() {
        let paths = tmp_paths();
        let secret = [0xE5u8; 32];
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let peer = Identity::from_secret_bytes([0xF6u8; 32]);
        // not in store at all

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let mesh_id = ch["mesh_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh_id, AuthMethod::DeviceMember);
        let sig = peer.sign(&pre);

        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "device_member",
            "device_id_hex": peer.device_id().to_string(),
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "not_member");
    }

    #[tokio::test]
    async fn mrk_proof_requires_unlock_then_full_topology() {
        let paths = tmp_paths();
        let secret = [0x17u8; 32];
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();

        let password = b"test-mmk-password-ok";
        let init = mesh_init(
            password,
            Some(mymesh_crypto::KdfParams {
                m: 64_000,
                t: 2,
                p: 1,
            }),
        )
        .unwrap();
        init.file.save(paths.mesh_master_file()).unwrap();
        // locked — no runtime

        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st.clone());
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        assert!(ch["methods_allowed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "mrk_proof"));

        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let mesh_id = ch["mesh_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh_id, AuthMethod::MrkProof);
        // Sign with real admin key even while locked — server must still refuse.
        let admin = mrk_admin_identity(&init.mrk);
        let sig = admin.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "mrk_proof",
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "mmk_locked");

        // Unlock via runtime cache.
        MmkRuntime::from_mrk(&init.mrk)
            .save(paths.mmk_runtime_file())
            .unwrap();

        let (_, ch2) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid2 = ch2["challenge_id"].as_str().unwrap().to_string();
        let nonce2 = decode_b64_32(ch2["nonce"].as_str().unwrap()).unwrap();
        let pre2 = auth_challenge_preimage(&cid2, &nonce2, &mesh_id, AuthMethod::MrkProof);
        let sig2 = admin.sign(&pre2);
        let body2 = serde_json::json!({
            "challenge_id": cid2,
            "method": "mrk_proof",
            "sig_hex": hex::encode(sig2),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body2.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sess = json_body(resp).await;
        assert_eq!(sess["auth_mode"], "mrk_proof");
        let token = sess["session_token"].as_str().unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let topo = json_body(resp).await;
        assert_eq!(topo["auth_mode"], "mrk_proof");
        assert_eq!(topo["mrk_fingerprint"], init.mrk.fingerprint());
    }

    #[tokio::test]
    async fn person_owner_session_when_claim_exists() {
        let paths = tmp_paths();
        let secret = [0x28u8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let ts = Utc::now().timestamp();
        let owner = MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: "01PERSONTEST00000000000000".into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Ada".into(),
            claimed_at: Utc::now(),
            claim_ts_unix: ts,
            claimed_from_device_id: None,
            mrk_fingerprint: "deadbeef".into(),
            mrk_epoch: 0,
            claim_sig_hex: "00".repeat(64),
            backup_stored_at: None,
        };
        owner.save(paths.mesh_owner_file()).unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        assert!(ch["methods_allowed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "person_owner"));

        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::PersonOwner);
        let sig = person.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "person_owner",
            "person_id": owner.person_id,
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token = json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let topo = json_body(resp).await;
        assert_eq!(topo["auth_mode"], "person_owner");
        assert_eq!(topo["owner"]["person_id"], owner.person_id);
        assert_eq!(topo["owner"]["display_name"], "Ada");
    }

    #[tokio::test]
    async fn owner_claim_agent_cosign_and_reject_without_mmk() {
        use mymesh_crypto::{
            owner_claim_preimage, seal_owner_backup, sign_owner_claim, unseal_owner_backup,
            OwnerBackupSealed,
        };

        let paths = tmp_paths();
        let secret = [0x6Au8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let password = b"test-mmk-owner-claim";
        let init = mesh_init(
            password,
            Some(mymesh_crypto::KdfParams {
                m: 64_000,
                t: 2,
                p: 1,
            }),
        )
        .unwrap();
        init.file.save(paths.mesh_master_file()).unwrap();
        let fp = init.mrk.fingerprint();

        let person = Identity::generate();
        let pk = person.verifying_key_bytes();
        let ts = Utc::now().timestamp();
        let pre = owner_claim_preimage(&mesh.mesh_id, "01CLAIM", &pk, &fp, ts).unwrap();
        let sig = sign_owner_claim(&person, &pre);

        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);

        // Locked → 403 mmk_locked
        let body = serde_json::json!({
            "person_id": "01CLAIM",
            "person_public_key_hex": hex::encode(pk),
            "claim_sig_hex": hex::encode(sig),
            "ts_unix": ts,
            "display_name": "Claimer",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/owner/claim")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "mmk_locked");

        // Unlock → agent co-sign succeeds
        MmkRuntime::from_mrk(&init.mrk)
            .save(paths.mmk_runtime_file())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/owner/claim")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["person_id"], "01CLAIM");
        assert_eq!(v["mrk_fingerprint"], fp);
        assert_eq!(v["auth_method"], "agent_cosign");
        assert!(paths.mesh_owner_file().exists());

        // GET /owner public meta
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let meta = json_body(resp).await;
        assert_eq!(meta["claimed"], true);
        assert_eq!(meta["person_id"], "01CLAIM");
        assert_eq!(meta["backup_stored"], false);

        // Second different claim without replace → conflict
        let person2 = Identity::generate();
        let pk2 = person2.verifying_key_bytes();
        let pre2 = owner_claim_preimage(&mesh.mesh_id, "01OTHER", &pk2, &fp, ts).unwrap();
        let sig2 = sign_owner_claim(&person2, &pre2);
        let body2 = serde_json::json!({
            "person_id": "01OTHER",
            "person_public_key_hex": hex::encode(pk2),
            "claim_sig_hex": hex::encode(sig2),
            "ts_unix": ts,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/owner/claim")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body2.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // person_owner session + PUT backup roundtrip store
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let auth_pre =
            auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::PersonOwner);
        let auth_sig = person.sign(&auth_pre);
        let sess_body = serde_json::json!({
            "challenge_id": cid,
            "method": "person_owner",
            "person_id": "01CLAIM",
            "sig_hex": hex::encode(auth_sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(sess_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let token = json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sealed = seal_owner_backup(
            b"backup-pass",
            "01CLAIM",
            &seed,
            "{}",
            None,
            Some(mymesh_crypto::KdfParams {
                m: 64_000,
                t: 2,
                p: 1,
            }),
        )
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mesh/v1/owner/backup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(serde_json::to_string(&sealed).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(paths.owner_backup_file().exists());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/owner/backup")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got: OwnerBackupSealed = serde_json::from_value(json_body(resp).await).unwrap();
        let (out_seed, _) = unseal_owner_backup(b"backup-pass", &got).unwrap();
        assert_eq!(out_seed, seed);
    }

    #[tokio::test]
    async fn owner_claim_via_allow_claim_window() {
        use mymesh_crypto::{owner_claim_preimage, sign_owner_claim, ClaimWindowFile};

        let paths = tmp_paths();
        let secret = [0x7Bu8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let init = mesh_init(
            b"mmk-window-test",
            Some(mymesh_crypto::KdfParams {
                m: 64_000,
                t: 2,
                p: 1,
            }),
        )
        .unwrap();
        init.file.save(paths.mesh_master_file()).unwrap();
        let fp = init.mrk.fingerprint();
        // Window only — no runtime unlock.
        ClaimWindowFile::mint(&fp, 300)
            .save(paths.claim_window_file())
            .unwrap();

        let person = Identity::generate();
        let pk = person.verifying_key_bytes();
        let ts = Utc::now().timestamp();
        let pre = owner_claim_preimage(&mesh.mesh_id, "01WIN", &pk, &fp, ts).unwrap();
        let sig = sign_owner_claim(&person, &pre);

        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);
        let body = serde_json::json!({
            "person_id": "01WIN",
            "person_public_key_hex": hex::encode(pk),
            "claim_sig_hex": hex::encode(sig),
            "ts_unix": ts,
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/owner/claim")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["auth_method"], "claim_window");
        assert!(paths.mesh_owner_file().exists());
        // Window consumed.
        assert!(!paths.claim_window_file().exists());
    }

    #[tokio::test]
    async fn pair_read_minimal_topology_not_full_roster() {
        let paths = tmp_paths();
        let secret = [0x39u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Extra trusted devices that must NOT appear in pair_read.
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        for i in 0..3u8 {
            let id = Identity::from_secret_bytes([0x40 + i; 32]);
            store
                .upsert(DeviceRecord {
                    id: id.device_id(),
                    label: DeviceLabel::new(format!("extra-{i}")),
                    fingerprint: NodeFingerprint::from_device_id(&id.device_id())
                        .as_str()
                        .to_string(),
                    capabilities: Capability::all(),
                    trust: TrustState::Trusted,
                    linked_at: Utc::now(),
                    last_seen: None,
                    endpoint_hint: None,
                    mesh_id: Some(mesh.mesh_id.clone()),
                    aliases: vec![],
                    groups: vec![],
                    mesh_role: mymesh_core::MeshRole::Member,
                })
                .unwrap();
        }

        let pair_store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let armed = pair_store
            .arm_new(
                &mesh.mesh_id,
                host.device_id(),
                900,
                PairEndpointClass::Confirm,
            )
            .unwrap();
        let joiner = DeviceId::from_bytes([0xAAu8; 32]);
        let mut sess = armed.session;
        sess.joiner_device_id = Some(joiner);
        sess.joiner_label = Some("phone-joiner".into());
        sess.joiner_fp = Some(
            NodeFingerprint::from_device_id(&joiner)
                .as_str()
                .to_string(),
        );
        sess.phase = PairPhase::Bound;
        pair_store.save(&sess).unwrap();
        let token = URL_SAFE_NO_PAD.encode(armed.token_raw);

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        assert!(ch["methods_allowed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "pair_read"));

        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "pair_read",
            "sid": sess.sid,
            "token": token,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sess_resp = json_body(resp).await;
        assert_eq!(sess_resp["auth_mode"], "pair_read");
        assert_eq!(sess_resp["scope"], "minimal");
        let mesh_tok = sess_resp["session_token"].as_str().unwrap().to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/topology")
                    .header(header::AUTHORIZATION, format!("Bearer {mesh_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let topo = json_body(resp).await;
        assert_eq!(topo["auth_mode"], "pair_read");
        let members = topo["members"].as_array().unwrap();
        // Only resident + joiner — not the 3 extras.
        assert_eq!(members.len(), 2);
        let ids: Vec<String> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&host.device_id().to_string()));
        assert!(ids.contains(&joiner.to_string()));
        // No extra-* devices
        for m in members {
            assert!(!m["label"].as_str().unwrap().starts_with("extra-"));
        }
    }

    #[tokio::test]
    async fn bad_signature_fails_closed() {
        let paths = tmp_paths();
        let secret = [0x51u8; 32];
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let body = serde_json::json!({
            "challenge_id": ch["challenge_id"],
            "method": "device_member",
            "sig_hex": hex::encode([0u8; 64]),
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(resp).await["code"], "invalid_proof");
    }

    #[test]
    fn preimage_domain_separated_by_method() {
        let nonce = [7u8; 32];
        let a = auth_challenge_preimage("cid", &nonce, "mesh", AuthMethod::DeviceMember);
        let b = auth_challenge_preimage("cid", &nonce, "mesh", AuthMethod::MrkProof);
        assert_ne!(a, b);
        assert!(a.starts_with(AUTH_DOMAIN));
    }

    /// Mint a device_member session for `signer` (must be host or Trusted member).
    async fn mint_device_member_token(
        app: &axum::Router,
        mesh_id: &str,
        signer: &Identity,
        device_id: &DeviceId,
    ) -> String {
        let (_, ch) = get_challenge(app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, mesh_id, AuthMethod::DeviceMember);
        let sig = signer.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "device_member",
            "device_id_hex": device_id.to_string(),
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "mint device_member session");
        json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn mint_person_owner_token(
        app: &axum::Router,
        mesh_id: &str,
        person: &Identity,
        person_id: &str,
    ) -> String {
        let (_, ch) = get_challenge(app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, mesh_id, AuthMethod::PersonOwner);
        let sig = person.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "person_owner",
            "person_id": person_id,
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "mint person_owner session");
        json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn grants_create_list_revoke_via_person_owner() {
        let paths = tmp_paths();
        let secret = [0x71u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let person_id = "01GRANTPERSON0000000000000";
        MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Granter".into(),
            claimed_at: Utc::now(),
            claim_ts_unix: Utc::now().timestamp(),
            claimed_from_device_id: None,
            mrk_fingerprint: "fp".into(),
            mrk_epoch: 0,
            claim_sig_hex: "00".repeat(64),
            backup_stored_at: None,
        }
        .save(paths.mesh_owner_file())
        .unwrap();

        let guest = Identity::from_secret_bytes([0x72u8; 32]);
        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        // Unauthenticated create → 401
        let body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["terminal", "files"],
            "days": 7,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Create
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = json_body(resp).await;
        assert_eq!(created["role"], "guest");
        assert_eq!(created["mesh_id"], mesh.mesh_id);
        // HTTP DTO: DeviceIds as hex (mesh/v1 convention; store still raw bytes).
        assert_eq!(
            created["subject_device_id_hex"],
            guest.device_id().to_string()
        );
        assert_eq!(
            created["object"]["device_id_hex"],
            host.device_id().to_string()
        );
        assert_eq!(created["object"]["kind"], "device");
        assert_eq!(created["issued_by"]["kind"], "person_id");
        assert!(created["revoked_at"].is_null());
        let grant_id = created["grant_id"].as_str().unwrap().to_string();

        // List active
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let listed = json_body(resp).await;
        assert_eq!(listed["grants"].as_array().unwrap().len(), 1);
        assert_eq!(listed["grants"][0]["grant_id"], grant_id);

        // Revoke
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mesh/v1/grants/{grant_id}/revoke"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let revoked = json_body(resp).await;
        assert!(!revoked["revoked_at"].is_null());

        // Active list empty; ?all=true still shows
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(json_body(resp).await["grants"]
            .as_array()
            .unwrap()
            .is_empty());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/grants?all=true")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(resp).await["grants"].as_array().unwrap().len(), 1);

        // Persist on disk
        let store = GrantStore::open(paths.grants_file()).unwrap();
        assert!(store.get(&grant_id).unwrap().revoked_at.is_some());
    }

    #[tokio::test]
    async fn grants_device_member_without_admin_denied() {
        let paths = tmp_paths();
        let secret = [0x73u8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let peer = Identity::from_secret_bytes([0x74u8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("member-no-admin"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
                    .as_str()
                    .to_string(),
                capabilities: Capability::all(), // no Admin
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: mymesh_core::MeshRole::Member,
            })
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token =
            mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;

        let guest = Identity::from_secret_bytes([0x75u8; 32]);
        let body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["terminal"],
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "admin_required");
    }

    #[tokio::test]
    async fn grants_device_member_with_admin_ok() {
        let paths = tmp_paths();
        let secret = [0x76u8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let peer = Identity::from_secret_bytes([0x77u8; 32]);
        let mut caps = Capability::all();
        caps.push(Capability::Admin);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("admin-laptop"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
                    .as_str()
                    .to_string(),
                capabilities: caps,
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: mymesh_core::MeshRole::Member,
            })
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token =
            mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;

        let guest = Identity::from_secret_bytes([0x78u8; 32]);
        let body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["files"],
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let g = json_body(resp).await;
        assert_eq!(g["issued_by"]["kind"], "device_id");
        assert_eq!(g["issued_by"]["value"], peer.device_id().to_string());
    }

    #[tokio::test]
    async fn grants_guest_device_member_forbidden() {
        let paths = tmp_paths();
        let secret = [0x79u8; 32];
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let guest = Identity::from_secret_bytes([0x7Au8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: guest.device_id(),
                label: DeviceLabel::new("guest-phone"),
                fingerprint: NodeFingerprint::from_device_id(&guest.device_id())
                    .as_str()
                    .to_string(),
                // Even if caps list Admin, guest path must deny mutate.
                capabilities: vec![Capability::Terminal, Capability::Admin],
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: None,
                endpoint_hint: None,
                mesh_id: Some(mesh.mesh_id.clone()),
                aliases: vec![],
                groups: vec![],
                mesh_role: mymesh_core::MeshRole::Guest,
            })
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token =
            mint_device_member_token(&app, &mesh.mesh_id, &guest, &guest.device_id()).await;

        let body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["terminal"],
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "guest_forbidden");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "guest_forbidden");

        // Guest cannot revoke either.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants/01FAKEGRANTID000000000000/revoke")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "guest_forbidden");
    }

    #[tokio::test]
    async fn grants_pair_read_forbidden() {
        let paths = tmp_paths();
        let secret = [0x7Du8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let pair_store = PairSessionStore::open(paths.pair_sessions_dir()).unwrap();
        let armed = pair_store
            .arm_new(
                &mesh.mesh_id,
                host.device_id(),
                900,
                PairEndpointClass::Confirm,
            )
            .unwrap();
        let mut sess = armed.session;
        sess.joiner_device_id = Some(DeviceId::from_bytes([0xABu8; 32]));
        sess.phase = PairPhase::Bound;
        pair_store.save(&sess).unwrap();
        let pair_token = URL_SAFE_NO_PAD.encode(armed.token_raw);

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let body = serde_json::json!({
            "challenge_id": ch["challenge_id"],
            "method": "pair_read",
            "sid": sess.sid,
            "token": pair_token,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mesh_tok = json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string();

        let guest = Identity::from_secret_bytes([0x7Eu8; 32]);
        let create_body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["terminal"],
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {mesh_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "forbidden");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {mesh_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(resp).await["code"], "forbidden");
    }

    #[tokio::test]
    async fn grants_create_via_mrk_proof() {
        let paths = tmp_paths();
        let secret = [0x7Fu8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let password = b"test-mmk-grants-mrk";
        let init = mesh_init(
            password,
            Some(mymesh_crypto::KdfParams {
                m: 64_000,
                t: 2,
                p: 1,
            }),
        )
        .unwrap();
        init.file.save(paths.mesh_master_file()).unwrap();
        MmkRuntime::from_mrk(&init.mrk)
            .save(paths.mmk_runtime_file())
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::MrkProof);
        let admin = mrk_admin_identity(&init.mrk);
        let sig = admin.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "mrk_proof",
            "sig_hex": hex::encode(sig),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/auth/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token = json_body(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string();

        let guest = Identity::from_secret_bytes([0x80u8; 32]);
        let create = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["desktop"],
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let g = json_body(resp).await;
        assert_eq!(g["issued_by"]["kind"], "master_key_proof");
        assert_eq!(g["issued_by"]["value"], init.mrk.fingerprint());
        assert_eq!(
            g["object"]["device_id_hex"],
            host.device_id().to_string()
        );
    }

    #[tokio::test]
    async fn grants_reject_admin_capability_on_create() {
        let paths = tmp_paths();
        let secret = [0x7Bu8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token =
            mint_device_member_token(&app, &mesh.mesh_id, &host, &host.device_id()).await;

        let guest = Identity::from_secret_bytes([0x7Cu8; 32]);
        let body = serde_json::json!({
            "subject_device_id_hex": guest.device_id().to_string(),
            "capabilities": ["terminal", "admin"],
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/grants")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["code"], "invalid_caps");
    }

    /// S9: mesh auth challenge — 30 / min / peer IP → 429 + Retry-After.
    #[tokio::test]
    async fn auth_challenge_rate_limit_per_ip() {
        std::env::remove_var("MYMESH_TRUST_PROXY");
        let paths = tmp_paths();
        let secret = [0xD1u8; 32];
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let metrics = paths.metrics_dir();
        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);

        let peer = std::net::SocketAddr::from(([198, 51, 100, 7], 40_000));
        let limit = mymesh_core::MESH_AUTH_CHALLENGE.max as usize;
        for i in 0..limit {
            let mut req = Request::builder()
                .uri("/mesh/v1/auth/challenge")
                .header("x-forwarded-for", "203.0.113.1") // ignored without trust proxy
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "hit {i}");
        }
        let mut req = Request::builder()
            .uri("/mesh/v1/auth/challenge")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
        assert_eq!(json_body(resp).await["code"], "rate_limited");

        // Other peer ok
        let mut req = Request::builder()
            .uri("/mesh/v1/auth/challenge")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [198, 51, 100, 8],
                40_001,
            ))));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let counters = mymesh_core::EventCounters::load(&metrics).unwrap();
        assert!(counters.mesh_auth_challenge_total > limit as u64);
    }
}
