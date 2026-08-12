//! Mesh API v1 — auth challenge (Issue 4) + topology read from DeviceStore.
//!
//! Routes (served on the carrier HTTP process, same Paths as serve):
//!
//! ```text
//! GET  /mesh/v1/auth/challenge   # public: nonce + methods_allowed
//! POST /mesh/v1/auth/session     # prove challenge → short-lived session token
//! GET  /mesh/v1/topology         # Authorization: Bearer <mesh session>
//! ```
//!
//! Auth methods (S0 freeze / CARRIER-NEXT Issue 4):
//! - `mrk_proof`      — MRK-derived admin Ed25519 (`mymesh/mrk/admin-sign`)
//! - `person_owner`   — person Ed25519 after claim (`mesh-owner.json`)
//! - `device_member`  — device Ed25519 of Trusted member (or serving host)
//! - `pair_read`      — bootstrap-bound pair session → **minimal** topology only
//!
//! See docs/CARRIER-NEXT.md §S6 and docs/MASTER-KEY.md.

// axum Response as Err is intentional for early-return handler helpers (same as carrier).
#![allow(clippy::result_large_err)]

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mymesh_core::{
    Capability, DeviceId, DeviceRecord, DeviceStore, MeshState, NodeFingerprint, PairPhase,
    PairSessionStore, Paths, TrustState,
};
use mymesh_crypto::{
    Identity, IdentityPublic, MeshMasterFile, MmkRuntime, Mrk, HKDF_ADMIN_SIGN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Device that authenticated (device_member) or host for others.
    /// Retained for future grants / audit (C2+).
    #[allow(dead_code)]
    subject_device_id: Option<DeviceId>,
    /// Person that authenticated (person_owner).
    #[allow(dead_code)]
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

/// Minimal owner claim file reader (S4 shape; claim write is B4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshOwnerFile {
    pub mesh_id: String,
    pub person_id: String,
    pub person_public_key_hex: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub claimed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub claimed_from_device_id: Option<String>,
    #[serde(default)]
    pub mrk_fingerprint: Option<String>,
    #[serde(default)]
    pub mrk_epoch: u64,
    #[serde(default)]
    pub claim_sig_hex: Option<String>,
}

impl MeshOwnerFile {
    pub fn try_load(path: impl AsRef<std::path::Path>) -> mymesh_core::Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }
}

// ── Router attachment ───────────────────────────────────────────────────────

/// State fragment mesh routes need from the carrier process.
#[derive(Clone)]
pub struct MeshApiState {
    pub paths: Paths,
    pub secret: [u8; 32],
    pub label: String,
    pub auth: Arc<Mutex<MeshAuthStore>>,
}

pub fn mesh_v1_routes(st: MeshApiState) -> Router {
    Router::new()
        .route("/mesh/v1/auth/challenge", get(auth_challenge))
        .route("/mesh/v1/auth/session", post(auth_session))
        .route("/mesh/v1/topology", get(topology))
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

async fn auth_challenge(State(st): State<MeshApiState>) -> Response {
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
        store.challenges.retain(|_, c| c.expires_at > Utc::now() && !c.consumed);
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
                return mesh_err(
                    StatusCode::GONE,
                    "challenge_expired",
                    "challenge expired",
                );
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
    let sess = store.find_by_token_raw(&raw).map_err(|e| {
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

    Ok((
        Some(sess.resident_device_id),
        None,
        Some(sess.sid.clone()),
    ))
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
        let label = sess
            .joiner_label
            .clone()
            .unwrap_or_else(|| "joiner".into());
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
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
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
        assert_eq!(topo["served_by_device_id_hex"], host.device_id().to_string());
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
        let init = mesh_init(password, Some(mymesh_crypto::KdfParams {
            m: 64_000,
            t: 2,
            p: 1,
        }))
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
        let owner = MeshOwnerFile {
            mesh_id: mesh.mesh_id.clone(),
            person_id: "01PERSONTEST00000000000000".into(),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            display_name: "Ada".into(),
            claimed_at: Some(Utc::now()),
            claimed_from_device_id: None,
            mrk_fingerprint: None,
            mrk_epoch: 0,
            claim_sig_hex: None,
        };
        std::fs::write(
            paths.mesh_owner_file(),
            serde_json::to_string_pretty(&owner).unwrap(),
        )
        .unwrap();

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
}
