//! Mesh API v1 — auth challenge (Issue 4) + topology + owner claim (S4/B4) + grants (C2/C4)
//! + continuity materialize/wipe/status (S8/E4).
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
//! POST /mesh/v1/continuity/materialize  # unwrap pack sealed to host pubkey
//! POST /mesh/v1/continuity/wipe         # wipe_token or owner/mrk
//! GET  /mesh/v1/continuity/status       # present | wiped | absent
//! GET  /mesh/v1/memberships             # this-node catalog (F8)
//! POST /mesh/v1/memberships             # guest overlap; role=member → 501
//! DELETE /mesh/v1/memberships/{mesh_id} # leave guest row
//! ```
//!
//! Auth methods (S0 freeze / CARRIER-NEXT Issue 4):
//! - `mrk_proof`      — MRK-derived admin Ed25519 (`mymesh/mrk/admin-sign`)
//! - `person_owner`   — person Ed25519 after claim (`mesh-owner.json`)
//! - `device_member`  — device Ed25519 of Trusted member (or serving host)
//! - `pair_read`      — bootstrap-bound pair session → **minimal** topology only
//!
//! Topology authz (S6 / C4 — docs/GUEST.md, CARRIER-NEXT §S6):
//! - `person_owner` / `mrk_proof` → full **member** roster + active `grants_summary`
//! - `device_member` (member) → full **member** roster (guests excluded);
//!   `grants_summary` when Admin/host (all active) or own subject/object grants
//! - `device_member` (guest) → **self + object host(s) only**; empty grants_summary;
//!   `minimal_roster` **pinned at session mint** (missing guest row cannot fail open)
//! - `pair_read` → session-minimal (resident+joiner); empty grants_summary
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
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mymesh_core::wire::{CatalogRole, CreateMembershipBody, CreateMembershipResponse};
use mymesh_core::{
    client_ip_key, load_state as load_continuity_state, materialize_pack, not_after_days,
    parse_capabilities, record_mesh_auth_challenge, status_pack as continuity_status_pack,
    wipe_pack as continuity_wipe_pack, Capability, ContinuityHostManifest, ContinuityHostStatus,
    DeviceId, DeviceRecord, DeviceStore, Error, Grant, GrantConstraints, GrantObject, GrantRole,
    GrantStore, IssuedBy, LimitKind, MaterializeInput, MembershipStore, MeshState, NodeFingerprint,
    PairPhase, PairSessionStore, Paths, RateLimitState, TrustState,
};
use mymesh_crypto::{
    accept_owner_claim, check_claim_authorized, open_continuity_pack_for_device,
    resolve_claim_fingerprint, verify_wipe_token, ClaimAuthMethod, ContinuityPack,
    ContinuityStatus, Identity, IdentityPublic, MeshMasterFile, MeshOwnerFile, MmkRuntime, Mrk,
    OwnerBackupSealed, OwnerClaimRequest, CONTINUITY_MAX_CIPHERTEXT_BYTES, CONTINUITY_PACK_VERSION,
    HKDF_ADMIN_SIGN,
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
    /// Pinned at mint: topology must not upgrade to full roster for this session.
    /// True for `pair_read` and guest `device_member` (GUEST.md / KD19 fail-closed).
    /// Re-deriving guest from live DeviceStore would fail *open* if the guest row
    /// disappears mid-session.
    minimal_roster: bool,
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

    /// Whether this auth mode can ever receive the full member roster.
    /// Guest `device_member` sessions are still `DeviceMember` but filtered at
    /// topology time (self + object host only).
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
    /// `full` | `minimal` (pair_read or guest device_member).
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
    /// Active grants visible to this session (S6/C4). Empty for pair_read / guest.
    grants_summary: Vec<GrantHttp>,
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
        .route(
            "/mesh/v1/memberships",
            get(memberships_list).post(memberships_create),
        )
        .route("/mesh/v1/memberships/{mesh_id}", delete(memberships_delete))
        .route(
            "/mesh/v1/continuity/materialize",
            post(continuity_materialize),
        )
        .route("/mesh/v1/continuity/wipe", post(continuity_wipe))
        .route("/mesh/v1/continuity/status", get(continuity_status))
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
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
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

    // Pin minimal roster at mint (pair_read or guest device_member). Topology
    // honors this flag so a later missing guest DeviceStore row cannot fail open
    // to the full household roster (GUEST.md / KD19).
    let guest_subject = body.method == AuthMethod::DeviceMember
        && subject_device_id
            .as_ref()
            .map(|id| device_is_guest(&st.paths, id))
            .unwrap_or(false);
    let minimal_roster = body.method == AuthMethod::PairRead || guest_subject;

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
                minimal_roster,
            },
        );
        // Challenge fully spent.
        store.challenges.remove(&body.challenge_id);
    }

    let scope = if minimal_roster { "minimal" } else { "full" };

    Json(SessionResponse {
        session_token: encode_b64(&token_raw),
        auth_mode: body.method.as_str(),
        expires_at: rfc3339(expires_at),
        scope,
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
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
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

    // Honor mint-time pin first (never upgrade minimal → full mid-session).
    // Live guest re-check only *narrows* further if role became guest after mint
    // (fail-closed); it must not expand a pinned-minimal session.
    let live_guest = session.auth_mode == AuthMethod::DeviceMember
        && session
            .subject_device_id
            .as_ref()
            .map(|id| device_is_guest(&st.paths, id))
            .unwrap_or(false);
    let minimal_session = session.minimal_roster || live_guest;

    let members = if session.auth_mode == AuthMethod::PairRead {
        // pair_read: session-minimal — resident + joiner only.
        match build_pair_read_members(&st.paths, session.pair_sid.as_deref()) {
            Ok(m) => m,
            Err(r) => return r,
        }
    } else if minimal_session {
        // Guest (pinned or live) cannot full-read household roster (GUEST.md / S6).
        let Some(guest_id) = session.subject_device_id else {
            return mesh_err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "minimal topology session missing subject device",
            );
        };
        match build_guest_members(&st.paths, &guest_id, &host_id, &st.label) {
            Ok(m) => m,
            Err(e) => {
                return mesh_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("guest topology: {e}"),
                );
            }
        }
    } else {
        // person_owner / mrk_proof / device_member (member): Trusted members only.
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
    };

    let grants_summary = match build_grants_summary(&st, &session, minimal_session) {
        Ok(g) => g,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("grants summary: {e}"),
            );
        }
    };

    Json(TopologyResponse {
        mesh_id: mesh.mesh_id,
        mrk_fingerprint,
        owner,
        roster_generation: mesh.roster_generation,
        members,
        grants_summary,
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
fn require_grants_mutate_authz(st: &MeshApiState, session: &MeshSession) -> Result<(), Response> {
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
    parse_capabilities(&names.join(","))
        .map_err(|e| mesh_err(StatusCode::BAD_REQUEST, "invalid_caps", e.to_string()))
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

// ── Memberships catalog + guest overlap (F8) ────────────────────────────────

fn require_x_mesh_id(headers: &HeaderMap, primary: &str) -> Result<(), Response> {
    match headers
        .get("x-mesh-id")
        .or_else(|| headers.get("X-Mesh-Id"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => Ok(()),
        Some(id) if id == primary => Ok(()),
        Some(_) => Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "X-Mesh-Id does not match this node's primary mesh",
        )),
    }
}

fn require_memberships_read_authz(session: &MeshSession) -> Result<(), Response> {
    match session.auth_mode {
        AuthMethod::PersonOwner | AuthMethod::MrkProof | AuthMethod::DeviceMember => Ok(()),
        AuthMethod::PairRead => Err(mesh_err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "pair_read cannot read memberships (this-node catalog is not topology)",
        )),
    }
}

fn load_mesh_and_catalog(paths: &Paths) -> Result<(MeshState, MembershipStore), Response> {
    let mesh = MeshState::load(paths.mesh_file()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("mesh load: {e}"),
        )
    })?;
    let cat = MembershipStore::open_or_migrate(paths.mesh_memberships_file(), &mesh.mesh_id)
        .map_err(|e| {
            mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("memberships: {e}"),
            )
        })?;
    Ok((mesh, cat))
}

fn catalog_http_err(e: Error) -> Response {
    match e {
        Error::NotImplemented(msg) => mesh_err(StatusCode::NOT_IMPLEMENTED, "not_implemented", msg),
        Error::Conflict(msg) => mesh_err(StatusCode::CONFLICT, "conflict", msg),
        Error::NotFound(msg) => mesh_err(StatusCode::NOT_FOUND, "not_found", msg),
        Error::Config(msg) => mesh_err(StatusCode::BAD_REQUEST, "bad_request", msg),
        other => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("memberships: {other}"),
        ),
    }
}

async fn memberships_list(State(st): State<MeshApiState>, headers: HeaderMap) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_memberships_read_authz(&session) {
        return r;
    }
    let (mesh, cat) = match load_mesh_and_catalog(&st.paths) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_x_mesh_id(&headers, &mesh.mesh_id) {
        return r;
    }
    Json(cat.file().clone()).into_response()
}

async fn memberships_create(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateMembershipBody>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let (mesh, mut cat) = match load_mesh_and_catalog(&st.paths) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_x_mesh_id(&headers, &mesh.mesh_id) {
        return r;
    }

    if body.role == CatalogRole::Member {
        if body.mesh_id == mesh.mesh_id {
            return mesh_err(
                StatusCode::CONFLICT,
                "conflict",
                "primary member row already exists",
            );
        }
        return mesh_err(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "member overlap is F8b (DeviceRecord.memberships)",
        );
    }
    if body.role != CatalogRole::Guest {
        return mesh_err(StatusCode::BAD_REQUEST, "bad_request", "role must be guest");
    }

    let subject = match DeviceId::from_str_hex(&body.device_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return mesh_err(
                StatusCode::BAD_REQUEST,
                "invalid_device_id",
                format!("device_id_hex: {e}"),
            );
        }
    };
    let dest = body.mesh_id.trim();
    if dest.is_empty() {
        return mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "mesh_id is required",
        );
    }
    let host_id = host_identity(&st.secret).device_id();
    let is_subject = subject == host_id;

    if !is_subject {
        // Dest policy node: create guest grant only. Catalog lives on the subject.
        if dest != mesh.mesh_id {
            return mesh_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "dest grant mesh_id must be this node's primary",
            );
        }
        if body.grant.is_none() {
            return mesh_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "grant payload required to create dest guest grant",
            );
        }
        if let Err(r) = require_grants_mutate_authz(&st, &session) {
            return r;
        }
        let grant = match create_overlap_grant(&st, &session, dest, subject, body.grant.as_ref()) {
            Ok(g) => g,
            Err(r) => return r,
        };
        return (
            StatusCode::CREATED,
            Json(CreateMembershipResponse {
                membership: None,
                via_grant_id: Some(grant.grant_id),
            }),
        )
            .into_response();
    }

    // Subject node: accept guest catalog row (+ optional local grant).
    if dest == mesh.mesh_id {
        return mesh_err(
            StatusCode::CONFLICT,
            "conflict",
            "cannot add extra membership on the primary mesh",
        );
    }
    if let Err(r) = require_grants_mutate_authz(&st, &session) {
        // Host-local subject accept reuses dest-grant authz on this box (person_owner /
        // mrk / Admin device). person_enrolled is F4.
        return r;
    }

    let via = if body.grant.is_some() {
        match create_overlap_grant(&st, &session, dest, subject, body.grant.as_ref()) {
            Ok(g) => Some(g.grant_id),
            Err(r) => return r,
        }
    } else if let Some(gid) = body
        .via_grant_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Err(r) = validate_overlap_grant(&st.paths, gid, dest, &subject) {
            return r;
        }
        Some(gid.to_string())
    } else {
        find_overlap_grant(&st.paths, dest, &subject)
    };

    match cat.add_guest(dest, via.clone()) {
        Ok(row) => (
            StatusCode::CREATED,
            Json(CreateMembershipResponse {
                membership: Some(row),
                via_grant_id: via,
            }),
        )
            .into_response(),
        Err(e) => catalog_http_err(e),
    }
}

async fn memberships_delete(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Path(mesh_id): Path<String>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_grants_mutate_authz(&st, &session) {
        return r;
    }
    let (mesh, mut cat) = match load_mesh_and_catalog(&st.paths) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_x_mesh_id(&headers, &mesh.mesh_id) {
        return r;
    }
    match cat.leave(&mesh_id) {
        Ok(row) => Json(row).into_response(),
        Err(e) => catalog_http_err(e),
    }
}

fn create_overlap_grant(
    st: &MeshApiState,
    session: &MeshSession,
    dest_mesh_id: &str,
    subject: DeviceId,
    grant: Option<&mymesh_core::wire::CreateMembershipGrant>,
) -> Result<Grant, Response> {
    let spec = grant.ok_or_else(|| {
        mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "grant payload required",
        )
    })?;
    let object = DeviceId::from_str_hex(&spec.object_device_id_hex).map_err(|e| {
        mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_device_id",
            format!("object_device_id_hex: {e}"),
        )
    })?;
    let capabilities = parse_grant_capabilities(&spec.capabilities)?;
    if capabilities.contains(&Capability::Admin) {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "invalid_caps",
            "Admin capability is not allowed on guest grants",
        ));
    }
    let mut grants = GrantStore::open(st.paths.grants_file()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("grant store: {e}"),
        )
    })?;
    grants
        .create_guest(
            dest_mesh_id,
            subject,
            object,
            capabilities,
            not_after_days(spec.not_after_days),
            issued_by_for_session(st, session),
        )
        .map_err(|e| match e {
            Error::Config(msg) => mesh_err(StatusCode::BAD_REQUEST, "invalid_caps", msg),
            other => mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("create grant: {other}"),
            ),
        })
}

fn validate_overlap_grant(
    paths: &Paths,
    grant_id: &str,
    dest_mesh_id: &str,
    subject: &DeviceId,
) -> Result<(), Response> {
    let grants = GrantStore::open(paths.grants_file()).map_err(|e| {
        mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("grant store: {e}"),
        )
    })?;
    let g = grants.get(grant_id).ok_or_else(|| {
        mesh_err(
            StatusCode::NOT_FOUND,
            "grant_not_found",
            format!("grant {grant_id} not found"),
        )
    })?;
    if g.mesh_id != dest_mesh_id {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "via_grant_id mesh_id does not match dest",
        ));
    }
    if g.role != GrantRole::Guest {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "via_grant_id is not a guest grant",
        ));
    }
    if &g.subject_device_id != subject {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "via_grant_id subject is not the membership device",
        ));
    }
    if g.object.as_device_id().is_none() {
        return Err(mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "via_grant_id object must be GrantObject::Device",
        ));
    }
    Ok(())
}

fn find_overlap_grant(paths: &Paths, dest_mesh_id: &str, subject: &DeviceId) -> Option<String> {
    let grants = GrantStore::open(paths.grants_file()).ok()?;
    let now = Utc::now();
    grants
        .list()
        .into_iter()
        .find(|g| {
            g.mesh_id == dest_mesh_id
                && g.subject_device_id == *subject
                && g.role == GrantRole::Guest
                && g.object.as_device_id().is_some()
                && g.is_active(now)
        })
        .map(|g| g.grant_id.clone())
}

// ── Continuity materialize / wipe / status (S8 / E4) ────────────────────────

/// Authz for continuity materialize + status (and wipe when not using wipe_token).
///
/// Allow: `person_owner` | `mrk_proof` | `device_member` when subject is **this host**
/// (object host only). Deny: pair_read, remote non-host members, guests, unauthenticated.
fn require_continuity_host_authz(st: &MeshApiState, session: &MeshSession) -> Result<(), Response> {
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
            let host_id = host_identity(&st.secret).device_id();
            if device_id == host_id {
                return Ok(());
            }
            Err(mesh_err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "continuity materialize/status requires object host device_member",
            ))
        }
        AuthMethod::PairRead => Err(mesh_err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "pair_read cannot access continuity",
        )),
    }
}

#[derive(Serialize)]
struct ContinuityMaterializeResponse {
    pack_id: String,
    status: ContinuityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContinuityWipeBody {
    pack_id: String,
    /// Hex wipe token (32B). Optional when caller has person_owner | mrk_proof.
    #[serde(default)]
    wipe_token: Option<String>,
}

#[derive(Serialize)]
struct ContinuityWipeResponse {
    pack_id: String,
    status: ContinuityStatus,
}

#[derive(Debug, Deserialize)]
struct ContinuityStatusQuery {
    pack_id: String,
}

#[derive(Serialize)]
struct ContinuityStatusResponse {
    pack_id: String,
    status: ContinuityStatus,
}

fn host_status_to_wire(s: ContinuityHostStatus) -> ContinuityStatus {
    match s {
        ContinuityHostStatus::Present => ContinuityStatus::Present,
        ContinuityHostStatus::Wiped => ContinuityStatus::Wiped,
        ContinuityHostStatus::Absent => ContinuityStatus::Absent,
    }
}

async fn continuity_materialize(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(pack): Json<ContinuityPack>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_continuity_host_authz(&st, &session) {
        return r;
    }

    if pack.version != CONTINUITY_PACK_VERSION {
        return mesh_err(
            StatusCode::BAD_REQUEST,
            "bad_pack",
            format!("unsupported continuity pack version {}", pack.version),
        );
    }
    if let Err(e) = mymesh_crypto::validate_pack_id(&pack.pack_id) {
        return mesh_err(StatusCode::BAD_REQUEST, "bad_pack", e.to_string());
    }

    // Size budget fail-closed before crypto work.
    let ct_len = base64::engine::general_purpose::STANDARD
        .decode(pack.ciphertext.trim())
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if ct_len > CONTINUITY_MAX_CIPHERTEXT_BYTES {
        return mesh_err(
            StatusCode::BAD_REQUEST,
            "too_large",
            format!("ciphertext {ct_len} exceeds max {CONTINUITY_MAX_CIPHERTEXT_BYTES}"),
        );
    }

    let host = host_identity(&st.secret);
    let host_id = host.device_id().to_string();
    let seed = host.to_secret_bytes();
    let fields = match open_continuity_pack_for_device(&seed, &host_id, &pack) {
        Ok(f) => f,
        Err(e) => {
            return mesh_err(
                StatusCode::BAD_REQUEST,
                "unwrap_failed",
                // No pack_key in message — ContinuityError is already redacted.
                e.to_string(),
            );
        }
    };

    let envelope = match serde_json::to_vec(&pack) {
        Ok(b) => b,
        Err(e) => {
            return mesh_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("pack serialize: {e}"),
            );
        }
    };

    let manifest = ContinuityHostManifest {
        label: pack.manifest.label.clone(),
        created_at: pack.manifest.created_at.clone(),
        person_id: pack.manifest.person_id.clone(),
        facet_id: pack.manifest.facet_id.clone(),
        fields_summary: pack.manifest.fields_summary.clone(),
        byte_length: pack.manifest.byte_length,
    };

    match materialize_pack(
        &st.paths,
        MaterializeInput {
            pack_id: &pack.pack_id,
            version: pack.version,
            wipe_token_hash: &pack.wipe_token_hash,
            host_device_id_hex: &pack.host_device_id_hex,
            manifest,
            fields_json: &fields,
            pack_envelope_json: &envelope,
        },
    ) {
        Ok(r) => Json(ContinuityMaterializeResponse {
            pack_id: r.pack_id,
            status: ContinuityStatus::Present,
            path_hint: Some(r.path_hint),
        })
        .into_response(),
        Err(Error::Config(msg)) if msg.contains("already present") => {
            mesh_err(StatusCode::CONFLICT, "conflict", msg)
        }
        Err(Error::Config(msg)) => mesh_err(StatusCode::BAD_REQUEST, "bad_pack", msg),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("materialize: {e}"),
        ),
    }
}

async fn continuity_wipe(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Json(body): Json<ContinuityWipeBody>,
) -> Response {
    if let Err(e) = mymesh_crypto::validate_pack_id(&body.pack_id) {
        return mesh_err(StatusCode::BAD_REQUEST, "bad_pack", e.to_string());
    }

    // Auth: wipe_token match **or** person_owner / mrk_proof session.
    // (device_member object host alone is not enough without wipe_token.)
    let mut authorized = false;

    if let Some(token) = body.wipe_token.as_deref().filter(|t| !t.trim().is_empty()) {
        match load_continuity_state(&st.paths, &body.pack_id) {
            Ok(Some(state)) if !state.wipe_token_hash.is_empty() => {
                if verify_wipe_token(&state.wipe_token_hash, token).is_ok() {
                    authorized = true;
                }
            }
            Ok(None) | Ok(Some(_)) => {
                // Absent / no hash: token alone cannot authorize; fall through.
            }
            Err(e) => {
                return mesh_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("continuity state: {e}"),
                );
            }
        }
    }

    if !authorized {
        match require_mesh_session(&st, &headers).await {
            Ok(session) => match session.auth_mode {
                AuthMethod::PersonOwner | AuthMethod::MrkProof => {
                    authorized = true;
                }
                AuthMethod::DeviceMember => {
                    // Object host may wipe only with valid wipe_token (already checked).
                    return mesh_err(
                        StatusCode::FORBIDDEN,
                        "forbidden",
                        "device_member wipe requires valid wipe_token",
                    );
                }
                AuthMethod::PairRead => {
                    return mesh_err(
                        StatusCode::FORBIDDEN,
                        "forbidden",
                        "pair_read cannot wipe continuity",
                    );
                }
            },
            Err(r) => {
                // No session and no valid wipe_token.
                if body
                    .wipe_token
                    .as_deref()
                    .filter(|t| !t.trim().is_empty())
                    .is_some()
                {
                    return mesh_err(
                        StatusCode::FORBIDDEN,
                        "wipe_token_invalid",
                        "wipe token mismatch or pack absent",
                    );
                }
                return r;
            }
        }
    }

    if !authorized {
        return mesh_err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "wipe requires wipe_token or owner/mrk session",
        );
    }

    match continuity_wipe_pack(&st.paths, &body.pack_id) {
        Ok(st_status) => Json(ContinuityWipeResponse {
            pack_id: body.pack_id,
            status: host_status_to_wire(st_status),
        })
        .into_response(),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("wipe: {e}"),
        ),
    }
}

async fn continuity_status(
    State(st): State<MeshApiState>,
    headers: HeaderMap,
    Query(q): Query<ContinuityStatusQuery>,
) -> Response {
    let session = match require_mesh_session(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_continuity_host_authz(&st, &session) {
        return r;
    }
    if let Err(e) = mymesh_crypto::validate_pack_id(&q.pack_id) {
        return mesh_err(StatusCode::BAD_REQUEST, "bad_pack", e.to_string());
    }

    match continuity_status_pack(&st.paths, &q.pack_id) {
        Ok(s) => Json(ContinuityStatusResponse {
            pack_id: q.pack_id,
            status: host_status_to_wire(s),
        })
        .into_response(),
        Err(e) => mesh_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("status: {e}"),
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

/// True when `device_id` is recorded as guest on this agent.
///
/// Missing store/row → `false` (used only to *detect* guest at mint or to
/// narrow further mid-session). Topology roster isolation must use the
/// session's pinned `minimal_roster` so a deleted guest row cannot fail open.
fn device_is_guest(paths: &Paths, device_id: &DeviceId) -> bool {
    DeviceStore::open(paths.devices_file())
        .ok()
        .and_then(|s| s.get(device_id).cloned())
        .map(|r| r.mesh_role.is_guest())
        .unwrap_or(false)
}

/// Guest topology: self + object host(s) from active grants (+ serving host).
/// Never the full household roster (GUEST.md).
fn build_guest_members(
    paths: &Paths,
    guest_id: &DeviceId,
    host_id: &DeviceId,
    host_label: &str,
) -> mymesh_core::Result<Vec<TopologyMember>> {
    let store = DeviceStore::open(paths.devices_file())?;
    let grants = GrantStore::open(paths.grants_file())?;
    let now = Utc::now();

    let mut out: Vec<TopologyMember> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Guest self.
    if let Some(rec) = store.get(guest_id) {
        out.push(topology_member_from_record(rec));
    } else {
        out.push(TopologyMember {
            device_id_hex: guest_id.to_string(),
            label: "guest".into(),
            fingerprint: NodeFingerprint::from_device_id(guest_id)
                .as_str()
                .to_string(),
            short_id: guest_id.short(),
            mesh_role: "guest",
            capabilities: vec![],
            trust: TrustState::Trusted,
            last_seen: None,
            aliases: vec![],
            groups: vec![],
        });
    }
    seen.insert(*guest_id);

    // Object hosts covered by active grants for this guest.
    let mut objects = std::collections::HashSet::new();
    for g in grants.list() {
        if g.subject_device_id == *guest_id && g.is_active(now) {
            if let Some(oid) = g.object.as_device_id() {
                objects.insert(*oid);
            }
        }
    }
    // Guest is talking to this agent's mesh API — serving host is visible.
    objects.insert(*host_id);

    for oid in objects {
        if !seen.insert(oid) {
            continue;
        }
        if oid == *host_id {
            out.push(topology_member_from_host(host_id, host_label));
        } else if let Some(rec) = store.get(&oid) {
            // Do not expand object host into full member peer list; only the object.
            out.push(topology_member_from_record(rec));
        } else {
            out.push(TopologyMember {
                device_id_hex: oid.to_string(),
                label: "object-host".into(),
                fingerprint: NodeFingerprint::from_device_id(&oid).as_str().to_string(),
                short_id: oid.short(),
                mesh_role: "member",
                capabilities: Capability::default_grant(),
                trust: TrustState::Trusted,
                last_seen: None,
                aliases: vec![],
                groups: vec![],
            });
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

/// Active grants visible on topology for this session (S6/C4).
///
/// - `pair_read` / minimal (guest) → empty
/// - `person_owner` / `mrk_proof` → all active
/// - `device_member` Admin or serving host → all active
/// - `device_member` otherwise → grants where subject or object is self ("own")
fn build_grants_summary(
    st: &MeshApiState,
    session: &MeshSession,
    minimal_session: bool,
) -> mymesh_core::Result<Vec<GrantHttp>> {
    if session.auth_mode == AuthMethod::PairRead || minimal_session {
        return Ok(vec![]);
    }

    let grants = GrantStore::open(st.paths.grants_file())?;
    let now = Utc::now();
    let active: Vec<&Grant> = grants
        .list()
        .into_iter()
        .filter(|g| g.is_active(now))
        .collect();

    let include_all = match session.auth_mode {
        AuthMethod::PersonOwner | AuthMethod::MrkProof => true,
        AuthMethod::DeviceMember => device_member_sees_all_grants(st, session),
        AuthMethod::PairRead => false,
    };

    let filtered: Vec<GrantHttp> = if include_all {
        active.into_iter().map(GrantHttp::from).collect()
    } else if let Some(self_id) = session.subject_device_id {
        active
            .into_iter()
            .filter(|g| {
                g.subject_device_id == self_id
                    || g.object.as_device_id().is_some_and(|o| *o == self_id)
            })
            .map(GrantHttp::from)
            .collect()
    } else {
        vec![]
    };
    Ok(filtered)
}

/// Host identity or Trusted member with Admin may see full grants_summary.
fn device_member_sees_all_grants(st: &MeshApiState, session: &MeshSession) -> bool {
    let Some(device_id) = session.subject_device_id else {
        return false;
    };
    let host_id = host_identity(&st.secret).device_id();
    if device_id == host_id {
        return true;
    }
    let Ok(store) = DeviceStore::open(st.paths.devices_file()) else {
        return false;
    };
    let Some(rec) = store.get(&device_id) else {
        return false;
    };
    if rec.mesh_role.is_guest() || rec.trust != TrustState::Trusted {
        return false;
    }
    store.has_admin(&device_id)
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
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
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
        let token = mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;

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
        let token = mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;

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
        let token = mint_device_member_token(&app, &mesh.mesh_id, &guest, &guest.device_id()).await;

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
        assert_eq!(g["object"]["device_id_hex"], host.device_id().to_string());
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
        let token = mint_device_member_token(&app, &mesh.mesh_id, &host, &host.device_id()).await;

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

    // ── C4: topology grants_summary + guest cannot full-read ────────────────

    #[tokio::test]
    async fn topology_person_owner_includes_grants_summary() {
        let paths = tmp_paths();
        let secret = [0x81u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let person_id = "01TOPOPERSON00000000000000";
        MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Owner".into(),
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

        // Extra member + guest device in store (guest must not appear in members).
        let peer = Identity::from_secret_bytes([0x82u8; 32]);
        let guest = Identity::from_secret_bytes([0x83u8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("peer-laptop"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
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
        store
            .upsert(DeviceRecord {
                id: guest.device_id(),
                label: DeviceLabel::new("guest-pad"),
                fingerprint: NodeFingerprint::from_device_id(&guest.device_id())
                    .as_str()
                    .to_string(),
                capabilities: vec![Capability::Terminal],
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

        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        let active = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Terminal, Capability::Files],
                not_after_days(Some(7)),
                IssuedBy::PersonId(person_id.into()),
            )
            .unwrap();
        let revoked = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Desktop],
                None,
                IssuedBy::PersonId(person_id.into()),
            )
            .unwrap();
        grants.revoke(&revoked.grant_id).unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

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
        assert_eq!(topo["auth_mode"], "person_owner");

        let members = topo["members"].as_array().unwrap();
        let ids: Vec<&str> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&host.device_id().to_string().as_str()));
        assert!(ids.contains(&peer.device_id().to_string().as_str()));
        // Guests are not listed as members (grants_summary carries guest access).
        assert!(!ids.contains(&guest.device_id().to_string().as_str()));
        for m in members {
            assert_ne!(m["mesh_role"], "guest");
        }

        let summary = topo["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 1, "only active grants");
        assert_eq!(summary[0]["grant_id"], active.grant_id);
        assert_eq!(
            summary[0]["subject_device_id_hex"],
            guest.device_id().to_string()
        );
        assert_eq!(
            summary[0]["object"]["device_id_hex"],
            host.device_id().to_string()
        );
        assert!(summary[0]["revoked_at"].is_null());
    }

    #[tokio::test]
    async fn topology_guest_device_member_minimal_not_full_roster() {
        let paths = tmp_paths();
        let secret = [0x84u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Household members that guest must NOT see.
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        let extras: Vec<Identity> = (0..3u8)
            .map(|i| Identity::from_secret_bytes([0x90 + i; 32]))
            .collect();
        for (i, id) in extras.iter().enumerate() {
            store
                .upsert(DeviceRecord {
                    id: id.device_id(),
                    label: DeviceLabel::new(format!("household-{i}")),
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

        let guest = Identity::from_secret_bytes([0x85u8; 32]);
        store
            .upsert(DeviceRecord {
                id: guest.device_id(),
                label: DeviceLabel::new("guest-phone"),
                fingerprint: NodeFingerprint::from_device_id(&guest.device_id())
                    .as_str()
                    .to_string(),
                capabilities: vec![Capability::Terminal],
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

        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Terminal],
                not_after_days(Some(3)),
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

        let st = test_state(paths, secret, "host-a");
        let app = mesh_v1_routes(st);

        // Session scope is minimal for guests.
        let (_, ch) = get_challenge(&app, "/mesh/v1/auth/challenge").await;
        let cid = ch["challenge_id"].as_str().unwrap().to_string();
        let nonce = decode_b64_32(ch["nonce"].as_str().unwrap()).unwrap();
        let pre = auth_challenge_preimage(&cid, &nonce, &mesh.mesh_id, AuthMethod::DeviceMember);
        let sig = guest.sign(&pre);
        let body = serde_json::json!({
            "challenge_id": cid,
            "method": "device_member",
            "device_id_hex": guest.device_id().to_string(),
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
        assert_eq!(sess["scope"], "minimal");
        let token = sess["session_token"].as_str().unwrap().to_string();

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
        assert_eq!(topo["auth_mode"], "device_member");

        let members = topo["members"].as_array().unwrap();
        // Self + object host only — not the 3 household members.
        assert_eq!(members.len(), 2);
        let ids: Vec<String> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&guest.device_id().to_string()));
        assert!(ids.contains(&host.device_id().to_string()));
        for extra in &extras {
            assert!(
                !ids.contains(&extra.device_id().to_string()),
                "guest must not see household member"
            );
        }
        for m in members {
            assert!(!m["label"].as_str().unwrap().starts_with("household-"));
        }
        // Guest does not receive grants_summary (minimal only).
        assert!(topo["grants_summary"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn topology_pair_read_empty_grants_summary() {
        let paths = tmp_paths();
        let secret = [0x86u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Seed an active grant that pair_read must not see.
        let guest = Identity::from_secret_bytes([0x87u8; 32]);
        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Files],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

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
        sess.joiner_device_id = Some(DeviceId::from_bytes([0xACu8; 32]));
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
        assert!(topo["grants_summary"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn topology_device_member_host_sees_grants_summary() {
        let paths = tmp_paths();
        let secret = [0x88u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let guest = Identity::from_secret_bytes([0x89u8; 32]);
        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        let g = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_device_member_token(&app, &mesh.mesh_id, &host, &host.device_id()).await;

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
        let summary = topo["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0]["grant_id"], g.grant_id);
    }

    #[tokio::test]
    async fn topology_device_member_without_admin_sees_own_grants_only() {
        let paths = tmp_paths();
        let secret = [0x8Au8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Non-admin trusted peer.
        let peer = Identity::from_secret_bytes([0x8Bu8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("peer-no-admin"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
                    .as_str()
                    .to_string(),
                capabilities: Capability::default_grant(), // no Admin
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

        let guest_a = Identity::from_secret_bytes([0x8Cu8; 32]);
        let guest_b = Identity::from_secret_bytes([0x8Du8; 32]);
        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        // Grant on host object — peer is neither subject nor object.
        let foreign = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_a.device_id(),
                host.device_id(),
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();
        // Grant where peer is object host ("own").
        let own = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_b.device_id(),
                peer.device_id(),
                vec![Capability::Files],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;

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
        let summary = topo["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0]["grant_id"], own.grant_id);
        assert_ne!(summary[0]["grant_id"], foreign.grant_id);
    }

    /// Mint-time `minimal_roster` pin: deleting the guest DeviceStore row mid-session
    /// must not upgrade topology to the full household roster.
    #[tokio::test]
    async fn topology_guest_pin_survives_deleted_device_row() {
        let paths = tmp_paths();
        let secret = [0x8Eu8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        let extra = Identity::from_secret_bytes([0x8Fu8; 32]);
        store
            .upsert(DeviceRecord {
                id: extra.device_id(),
                label: DeviceLabel::new("secret-household"),
                fingerprint: NodeFingerprint::from_device_id(&extra.device_id())
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

        let guest = Identity::from_secret_bytes([0x91u8; 32]);
        store
            .upsert(DeviceRecord {
                id: guest.device_id(),
                label: DeviceLabel::new("guest-ephemeral"),
                fingerprint: NodeFingerprint::from_device_id(&guest.device_id())
                    .as_str()
                    .to_string(),
                capabilities: vec![Capability::Terminal],
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

        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

        let st = test_state(paths.clone(), secret, "host-a");
        let app = mesh_v1_routes(st);
        let token = mint_device_member_token(&app, &mesh.mesh_id, &guest, &guest.device_id()).await;

        // Simulate mid-session store wipe of guest row (would fail open without pin).
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store.remove(&guest.device_id()).unwrap();
        assert!(store.get(&guest.device_id()).is_none());
        assert!(!device_is_guest(&paths, &guest.device_id()));

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
        let members = topo["members"].as_array().unwrap();
        let ids: Vec<String> = members
            .iter()
            .map(|m| m["device_id_hex"].as_str().unwrap().to_string())
            .collect();
        assert!(
            ids.contains(&guest.device_id().to_string()),
            "guest self still listed (synthetic if row gone)"
        );
        assert!(ids.contains(&host.device_id().to_string()));
        assert!(
            !ids.contains(&extra.device_id().to_string()),
            "pinned minimal must not leak household after guest row delete"
        );
        assert!(topo["grants_summary"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn topology_mrk_proof_includes_grants_summary() {
        let paths = tmp_paths();
        let secret = [0x92u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let password = b"test-mmk-topo-grants";
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

        let guest = Identity::from_secret_bytes([0x93u8; 32]);
        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        let g = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest.device_id(),
                host.device_id(),
                vec![Capability::Files],
                None,
                IssuedBy::MasterKeyProof(init.mrk.fingerprint()),
            )
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
        let summary = topo["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0]["grant_id"], g.grant_id);
    }

    #[tokio::test]
    async fn topology_device_member_admin_non_host_sees_all_grants() {
        let paths = tmp_paths();
        let secret = [0x94u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Trusted peer with Admin (not serving host).
        let admin_peer = Identity::from_secret_bytes([0x95u8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: admin_peer.device_id(),
                label: DeviceLabel::new("admin-laptop"),
                fingerprint: NodeFingerprint::from_device_id(&admin_peer.device_id())
                    .as_str()
                    .to_string(),
                capabilities: Capability::with_admin(),
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

        let guest_a = Identity::from_secret_bytes([0x96u8; 32]);
        let guest_b = Identity::from_secret_bytes([0x97u8; 32]);
        let mut grants = GrantStore::open(paths.grants_file()).unwrap();
        // Foreign grant: admin_peer is neither subject nor object — still visible with Admin.
        let on_host = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_a.device_id(),
                host.device_id(),
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();
        let on_peer = grants
            .create_guest(
                mesh.mesh_id.clone(),
                guest_b.device_id(),
                admin_peer.device_id(),
                vec![Capability::Files],
                None,
                IssuedBy::device(&host.device_id()),
            )
            .unwrap();

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token =
            mint_device_member_token(&app, &mesh.mesh_id, &admin_peer, &admin_peer.device_id())
                .await;

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
        let summary = topo["grants_summary"].as_array().unwrap();
        assert_eq!(summary.len(), 2, "Admin non-host sees all active grants");
        let ids: Vec<&str> = summary
            .iter()
            .map(|g| g["grant_id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&on_host.grant_id.as_str()));
        assert!(ids.contains(&on_peer.grant_id.as_str()));
    }

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

    // ── F8 memberships catalog + guest overlap ─────────────────────────────

    fn write_owner_file(paths: &Paths, mesh_id: &str, person: &Identity, person_id: &str) {
        MeshOwnerFile {
            mesh_id: mesh_id.into(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Owner".into(),
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
    }

    #[tokio::test]
    async fn memberships_get_post_delete_guest_grant_path() {
        let paths = tmp_paths();
        let secret = [0x81u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mut mesh = MeshState::new_mesh();
        mesh.mesh_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
        mesh.save(paths.mesh_file()).unwrap();
        let person = Identity::generate();
        let person_id = "01MEMBERPERSON00000000000";
        write_owner_file(&paths, &mesh.mesh_id, &person, person_id);

        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/memberships")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/memberships")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let listed = json_body(resp).await;
        assert_eq!(listed["primary_mesh_id"], mesh.mesh_id);
        assert_eq!(listed["memberships"].as_array().unwrap().len(), 1);
        assert_eq!(listed["memberships"][0]["role"], "member");
        assert_eq!(listed["memberships"][0]["primary"], true);

        let dest = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let body = serde_json::json!({
            "device_id_hex": host.device_id().to_string(),
            "mesh_id": dest,
            "role": "guest",
            "grant": {
                "object_device_id_hex": host.device_id().to_string(),
                "capabilities": ["terminal", "files"],
                "not_after_days": 7
            }
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/memberships")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "{}",
            json_body(resp).await
        );
        // Re-fetch body — previous json_body consumes. Recreate request result via store.
        let grants = GrantStore::open(paths.grants_file()).unwrap();
        assert_eq!(grants.list().len(), 1);
        let g = grants.list()[0];
        assert_eq!(g.mesh_id, dest);
        assert_eq!(g.role, GrantRole::Guest);
        assert_eq!(g.subject_device_id, host.device_id());
        assert!(g.object.as_device_id().is_some());

        let cat = MembershipStore::open(paths.mesh_memberships_file()).unwrap();
        assert!(cat.has_extra_rows());
        assert_eq!(
            cat.get(dest).unwrap().via_grant_id.as_deref(),
            Some(g.grant_id.as_str())
        );

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/mesh/v1/memberships/{dest}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cat = MembershipStore::open(paths.mesh_memberships_file()).unwrap();
        assert!(!cat.has_extra_rows());
    }

    #[tokio::test]
    async fn memberships_role_member_extra_501() {
        let paths = tmp_paths();
        let secret = [0x82u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mut mesh = MeshState::new_mesh();
        mesh.mesh_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
        mesh.save(paths.mesh_file()).unwrap();
        let person = Identity::generate();
        let person_id = "01MEMBERPERSON50100000000";
        write_owner_file(&paths, &mesh.mesh_id, &person, person_id);
        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        let body = serde_json::json!({
            "device_id_hex": host.device_id().to_string(),
            "mesh_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "role": "member"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/memberships")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let j = json_body(resp).await;
        assert_eq!(j["code"], "not_implemented");
    }

    #[tokio::test]
    async fn memberships_x_mesh_id_foreign_400() {
        let paths = tmp_paths();
        let secret = [0x83u8; 32];
        let mut mesh = MeshState::new_mesh();
        mesh.mesh_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
        mesh.save(paths.mesh_file()).unwrap();
        let person = Identity::generate();
        let person_id = "01MEMBERPERSONXMESH00000";
        write_owner_file(&paths, &mesh.mesh_id, &person, person_id);
        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/mesh/v1/memberships")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header("X-Mesh-Id", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(resp).await["code"], "bad_request");
    }

    // ── Continuity materialize / wipe / status (S8 / E4) ───────────────────

    fn seal_for_host(host: &Identity, fields: &str) -> mymesh_crypto::SealedContinuity {
        let pk_hex = hex::encode(host.verifying_key_bytes());
        let did = host.device_id().to_string();
        mymesh_crypto::seal_continuity_pack(mymesh_crypto::SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &did,
            person_id: "01CONTINUITYPERSON00000000",
            facet_id: Some("personal"),
            label: "hotel bag",
            fields_json: fields,
            fields_summary: vec!["profile".into()],
            pack_id: Some("01CONTTESTPACK0000000000000"),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn continuity_materialize_wipe_status_roundtrip() {
        let paths = tmp_paths();
        let secret = [0xA1u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let person_id = "01CONTPERSON000000000000000";
        MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Cont Owner".into(),
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

        let fields = r#"{"profile":{"name":"Ada"}}"#;
        let sealed = seal_for_host(&host, fields);

        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        // Unauthenticated materialize → 401
        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Status absent before materialize
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/mesh/v1/continuity/status?pack_id={}",
                        sealed.pack.pack_id
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "absent");

        // Materialize
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mat = json_body(resp).await;
        assert_eq!(mat["status"], "present");
        assert_eq!(mat["pack_id"], sealed.pack.pack_id);
        assert!(mat["path_hint"].as_str().unwrap().contains("continuity/"));

        // Fields written on disk
        let fields_path = paths
            .continuity_pack_dir(&sealed.pack.pack_id)
            .join("fields.json");
        assert!(fields_path.exists());
        assert_eq!(std::fs::read(&fields_path).unwrap(), fields.as_bytes());

        // Status present
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/mesh/v1/continuity/status?pack_id={}",
                        sealed.pack.pack_id
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(resp).await["status"], "present");

        // Wrong wipe_token without owner would fail — use wrong token + no owner path via
        // wipe with bad token and no auth.
        let bad = serde_json::json!({
            "pack_id": sealed.pack.pack_id,
            "wipe_token": "00".repeat(32),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bad.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(fields_path.exists(), "bad wipe must not remove secrets");

        // Good wipe_token (no session required)
        let wipe_body = serde_json::json!({
            "pack_id": sealed.pack.pack_id,
            "wipe_token": sealed.wipe_token_hex(),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(wipe_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "wiped");
        assert!(!fields_path.exists(), "wipe removes fields.json");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/mesh/v1/continuity/status?pack_id={}",
                        sealed.pack.pack_id
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(resp).await["status"], "wiped");
    }

    #[tokio::test]
    async fn continuity_wrong_host_key_fails_closed() {
        let paths = tmp_paths();
        let secret = [0xA2u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let other = Identity::from_secret_bytes([0xA3u8; 32]);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        // Pack sealed to *other* device, not host.
        let sealed = seal_for_host(&other, r#"{"x":1}"#);

        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_device_member_token(&app, &mesh.mesh_id, &host, &host.device_id()).await;

        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = json_body(resp).await;
        assert_eq!(err["code"], "unwrap_failed");
        let err_s = err["error"].as_str().unwrap();
        assert!(!err_s.contains("pack_key"));
    }

    #[tokio::test]
    async fn continuity_pair_read_and_remote_member_denied() {
        let paths = tmp_paths();
        let secret = [0xA4u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let peer = Identity::from_secret_bytes([0xA5u8; 32]);
        let mut store = DeviceStore::open(paths.devices_file()).unwrap();
        store
            .upsert(DeviceRecord {
                id: peer.device_id(),
                label: DeviceLabel::new("peer"),
                fingerprint: NodeFingerprint::from_device_id(&peer.device_id())
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

        let sealed = seal_for_host(&host, r#"{"y":2}"#);
        let st = test_state(paths, secret, "host");
        let app = mesh_v1_routes(st);

        let peer_tok =
            mint_device_member_token(&app, &mesh.mesh_id, &peer, &peer.device_id()).await;
        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {peer_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Host device_member may materialize (object host).
        let host_tok =
            mint_device_member_token(&app, &mesh.mesh_id, &host, &host.device_id()).await;
        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {host_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn continuity_owner_wipe_without_token() {
        let paths = tmp_paths();
        let secret = [0xA6u8; 32];
        let host = Identity::from_secret_bytes(secret);
        let mesh = MeshState::new_mesh();
        mesh.save(paths.mesh_file()).unwrap();

        let person = Identity::generate();
        let person_id = "01CONTOWNERWIPE00000000000";
        MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: person_id.into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Wiper".into(),
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

        let sealed = seal_for_host(&host, r#"{"z":3}"#);
        let st = test_state(paths.clone(), secret, "host");
        let app = mesh_v1_routes(st);
        let token = mint_person_owner_token(&app, &mesh.mesh_id, &person, person_id).await;

        let body = serde_json::to_string(&sealed.pack).unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/materialize")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Owner wipe with empty wipe_token
        let wipe_body = serde_json::json!({
            "pack_id": sealed.pack.pack_id,
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mesh/v1/continuity/wipe")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(wipe_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "wiped");
        assert!(!paths
            .continuity_pack_dir(&sealed.pack.pack_id)
            .join("fields.json")
            .exists());
    }
}
