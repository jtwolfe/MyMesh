//! Pair v2 session store under agent Paths (`pair-sessions/<sid>.json`).
//!
//! See docs/PAIR-V2.md — sid, token_hash, 16B nonce, phase machine, arm TTL,
//! optional joiner bind. Source of truth lives on disk; carrier HTTP is a facade.
//!
//! Raw bootstrap token is stored only as a sidecar (`<sid>.token`, mode 0600)
//! for local confirm HMAC; the session JSON keeps **hash only**.
use crate::pair_confirm::{compute_confirm_codes, confirm_codes_equal};
use crate::{DeviceId, JoinDecision, JoinStore, PendingJoin, Result};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Crockford base32 alphabet (ULID).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Handoff phase for a pair session (PAIR-V2.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairPhase {
    Armed,
    Bound,
    Decided,
    Completing,
    Completed,
    FailedPartial,
    Expired,
}

impl PairPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Bound => "bound",
            Self::Decided => "decided",
            Self::Completing => "completing",
            Self::Completed => "completed",
            Self::FailedPartial => "failed_partial",
            Self::Expired => "expired",
        }
    }

    /// True if the session may still accept bind / decide.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Armed | Self::Bound)
    }

    /// Terminal or post-decide phases for idempotent decide checks.
    pub fn is_post_decide(self) -> bool {
        matches!(self, Self::Decided | Self::Completing | Self::Completed)
    }
}

/// Endpoint class advertised in QR / status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PairEndpointClass {
    Direct,
    #[default]
    Confirm,
    Relay,
}

impl PairEndpointClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Confirm => "confirm",
            Self::Relay => "relay",
        }
    }
}

/// On-disk pair session (paths.data_dir/pair-sessions/<sid>.json, mode 0600).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairSessionFile {
    pub sid: String,
    pub mesh_id: String,
    /// Host / resident device id (did from QR).
    pub resident_device_id: DeviceId,
    /// SHA-256 of raw 32B bootstrap token, hex-encoded (store hash only).
    pub token_hash: String,
    /// Session nonce: 16 raw bytes (same bytes as QR_A, status, SessionDecision).
    #[serde(with = "nonce_hex")]
    pub nonce: [u8; 16],
    pub until: DateTime<Utc>,
    pub joiner_device_id: Option<DeviceId>,
    pub joiner_label: Option<String>,
    pub joiner_fp: Option<String>,
    pub phase: PairPhase,
    pub decision: Option<JoinDecision>,
    #[serde(default)]
    pub confirm_consumed: bool,
    /// Advertised endpoint class (direct when host QR hint present).
    #[serde(default)]
    pub ep: PairEndpointClass,
    /// Optional TLS SPKI pin advertised in QR (`tlspin=sha256/…`). Wire form when set.
    /// Requires HTTPS host on the client (see `tls_pin` module / PAIR-V2.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

mod nonce_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(nonce: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(nonce))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
        if raw.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "nonce must be 16 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Material returned when arming a new session (raw secrets for QR only).
#[derive(Clone, Debug)]
pub struct ArmedPairSession {
    pub session: PairSessionFile,
    /// Raw 32-byte token (never written to disk).
    pub token_raw: [u8; 32],
}

/// SHA-256 of raw token bytes → 64 hex chars.
pub fn hash_pair_token(raw: &[u8]) -> String {
    let dig = Sha256::digest(raw);
    hex::encode(dig)
}

/// Constant-time compare of equal-length slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

/// Generate a 26-char Crockford ULID (time-sortable session id).
pub fn new_pair_sid() -> String {
    let ms = Utc::now().timestamp_millis().max(0) as u64;
    let mut entropy = [0u8; 10];
    OsRng.fill_bytes(&mut entropy);
    let mut bytes = [0u8; 16];
    bytes[0] = ((ms >> 40) & 0xff) as u8;
    bytes[1] = ((ms >> 32) & 0xff) as u8;
    bytes[2] = ((ms >> 24) & 0xff) as u8;
    bytes[3] = ((ms >> 16) & 0xff) as u8;
    bytes[4] = ((ms >> 8) & 0xff) as u8;
    bytes[5] = (ms & 0xff) as u8;
    bytes[6..].copy_from_slice(&entropy);
    encode_crockford_128(&bytes)
}

fn encode_crockford_128(bytes: &[u8; 16]) -> String {
    // 128 bits → 26 base32 chars (with 2 pad bits of zero at MSB side of last group).
    let mut chars = String::with_capacity(26);
    let mut acc: u128 = 0;
    for b in bytes {
        acc = (acc << 8) | u128::from(*b);
    }
    // We have 128 bits; take 26 × 5 = 130 bits with 2 leading zero bits.
    acc <<= 2;
    for i in (0..26).rev() {
        let shift = i * 5;
        let idx = ((acc >> shift) & 0x1f) as usize;
        chars.push(CROCKFORD[idx] as char);
    }
    chars
}

impl PairSessionFile {
    /// True when `until` is in the past (regardless of phase).
    pub fn is_expired_now(&self) -> bool {
        Utc::now() >= self.until
    }

    /// Effective phase after applying wall-clock expiry.
    pub fn effective_phase(&self) -> PairPhase {
        if self.is_expired_now()
            && matches!(
                self.phase,
                PairPhase::Armed | PairPhase::Bound | PairPhase::Decided | PairPhase::Completing
            )
        {
            PairPhase::Expired
        } else {
            self.phase
        }
    }

    /// Verify raw token against stored hash.
    pub fn token_matches(&self, raw: &[u8]) -> bool {
        let expect = hex::decode(&self.token_hash).unwrap_or_default();
        let got = Sha256::digest(raw);
        ct_eq(&expect, got.as_slice())
    }
}

/// Disk-backed pair session store.
pub struct PairSessionStore {
    root: PathBuf,
}

impl PairSessionStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn safe_sid(sid: &str) -> String {
        // sid is ULID / alphanumeric — still sanitize path separators
        sid.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    pub fn path_for(&self, sid: &str) -> PathBuf {
        self.root.join(format!("{}.json", Self::safe_sid(sid)))
    }

    /// Sidecar path for raw 32B bootstrap token (hex, mode 0600).
    pub fn token_path_for(&self, sid: &str) -> PathBuf {
        self.root.join(format!("{}.token", Self::safe_sid(sid)))
    }

    /// Persist raw token for local confirm (never logged; mode 0600).
    pub fn save_token_raw(&self, sid: &str, raw: &[u8; 32]) -> Result<()> {
        let path = self.token_path_for(sid);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&path, hex::encode(raw))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load raw bootstrap token for confirm HMAC, if present.
    pub fn load_token_raw(&self, sid: &str) -> Result<Option<[u8; 32]>> {
        let path = self.token_path_for(sid);
        if !path.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(path)?;
        let raw = hex::decode(s.trim())
            .map_err(|e| crate::Error::Session(format!("pair token decode: {e}")))?;
        if raw.len() != 32 {
            return Err(crate::Error::Session(format!(
                "pair token must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Some(out))
    }

    /// Remove sidecar token (e.g. after consume / expire).
    pub fn clear_token_raw(&self, sid: &str) -> Result<()> {
        let path = self.token_path_for(sid);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    pub fn save(&self, session: &PairSessionFile) -> Result<()> {
        let path = self.path_for(&session.sid);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let body = serde_json::to_string_pretty(session)?;
        std::fs::write(&path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load(&self, sid: &str) -> Result<Option<PairSessionFile>> {
        let path = self.path_for(sid);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn list(&self) -> Result<Vec<PairSessionFile>> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return Ok(out);
        }
        for ent in std::fs::read_dir(&self.root)? {
            let ent = ent?;
            if ent.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(ent.path())?;
            match serde_json::from_str::<PairSessionFile>(&raw) {
                Ok(s) => out.push(s),
                Err(_) => continue,
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        Ok(out)
    }

    /// Find session whose token_hash matches SHA-256(raw_token).
    pub fn find_by_token_raw(&self, raw: &[u8]) -> Result<Option<PairSessionFile>> {
        let want = hash_pair_token(raw);
        for s in self.list()? {
            if s.token_hash == want {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    /// Most recently created non-expired session still open or mid-handoff.
    pub fn active_session(&self) -> Result<Option<PairSessionFile>> {
        let now = Utc::now();
        Ok(self.list()?.into_iter().find(|s| {
            s.until > now
                && matches!(
                    s.phase,
                    PairPhase::Armed
                        | PairPhase::Bound
                        | PairPhase::Decided
                        | PairPhase::Completing
                )
        }))
    }

    /// Arm a new pair session: mint token + 16B nonce, persist hash only.
    pub fn arm_new(
        &self,
        mesh_id: impl Into<String>,
        resident_device_id: DeviceId,
        ttl_secs: u64,
        ep: PairEndpointClass,
    ) -> Result<ArmedPairSession> {
        let now = Utc::now();
        let mut token_raw = [0u8; 32];
        OsRng.fill_bytes(&mut token_raw);
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let sid = new_pair_sid();
        let session = PairSessionFile {
            sid,
            mesh_id: mesh_id.into(),
            resident_device_id,
            token_hash: hash_pair_token(&token_raw),
            nonce,
            until: now + chrono::Duration::seconds(ttl_secs as i64),
            joiner_device_id: None,
            joiner_label: None,
            joiner_fp: None,
            phase: PairPhase::Armed,
            decision: None,
            confirm_consumed: false,
            ep,
            tls_pin: None,
            created_at: now,
            updated_at: now,
        };
        self.save(&session)?;
        self.save_token_raw(&session.sid, &token_raw)?;
        Ok(ArmedPairSession { session, token_raw })
    }

    /// Bind joiner to an armed session (phase → bound).
    ///
    /// If already bound to the same joiner, returns Ok (idempotent).
    /// If bound to a different joiner, returns Err.
    pub fn bind_joiner(
        &self,
        sid: &str,
        joiner: DeviceId,
        label: Option<String>,
        fp: Option<String>,
    ) -> Result<PairSessionFile> {
        let mut s = self
            .load(sid)?
            .ok_or_else(|| crate::Error::NotFound(format!("pair session {sid}")))?;
        if s.is_expired_now() {
            s.phase = PairPhase::Expired;
            s.updated_at = Utc::now();
            self.save(&s)?;
            return Err(crate::Error::Session("pair session expired".into()));
        }
        match s.phase {
            PairPhase::Armed => {
                s.joiner_device_id = Some(joiner);
                s.joiner_label = label;
                s.joiner_fp = fp;
                s.phase = PairPhase::Bound;
                s.updated_at = Utc::now();
                self.save(&s)?;
                Ok(s)
            }
            PairPhase::Bound => {
                if s.joiner_device_id == Some(joiner) {
                    // refresh label/fp if provided
                    if label.is_some() {
                        s.joiner_label = label;
                    }
                    if fp.is_some() {
                        s.joiner_fp = fp;
                    }
                    s.updated_at = Utc::now();
                    self.save(&s)?;
                    Ok(s)
                } else {
                    Err(crate::Error::Session(
                        "session already bound to a different joiner".into(),
                    ))
                }
            }
            other => Err(crate::Error::Session(format!(
                "cannot bind in phase {}",
                other.as_str()
            ))),
        }
    }

    /// Record accept/deny on a bound (or just-bound) session.
    pub fn write_decision(
        &self,
        sid: &str,
        decision: JoinDecision,
        confirm_consumed: bool,
    ) -> Result<PairSessionFile> {
        let mut s = self
            .load(sid)?
            .ok_or_else(|| crate::Error::NotFound(format!("pair session {sid}")))?;
        s.decision = Some(decision);
        s.phase = PairPhase::Decided;
        s.confirm_consumed = confirm_consumed;
        s.updated_at = Utc::now();
        self.save(&s)?;
        Ok(s)
    }

    /// Mark phase expired when wall clock passes until.
    pub fn expire_if_needed(&self, sid: &str) -> Result<Option<PairSessionFile>> {
        let Some(mut s) = self.load(sid)? else {
            return Ok(None);
        };
        if s.is_expired_now()
            && s.phase != PairPhase::Expired
            && matches!(s.phase, PairPhase::Armed | PairPhase::Bound)
        {
            s.phase = PairPhase::Expired;
            s.updated_at = Utc::now();
            self.save(&s)?;
        }
        Ok(Some(s))
    }

    /// Resolve active open session: exact sid, or unique active non-expired session.
    pub fn resolve_session(
        &self,
        sid: Option<&str>,
    ) -> std::result::Result<PairSessionFile, PairConfirmError> {
        if let Some(sid) = sid {
            let s = self
                .load(sid)
                .map_err(|e| PairConfirmError::Other(e.to_string()))?
                .ok_or(PairConfirmError::SessionGone)?;
            return Ok(s);
        }
        let now = Utc::now();
        let open: Vec<_> = self
            .list()
            .map_err(|e| PairConfirmError::Other(e.to_string()))?
            .into_iter()
            .filter(|s| {
                s.until > now
                    && matches!(
                        s.phase,
                        PairPhase::Armed
                            | PairPhase::Bound
                            | PairPhase::Decided
                            | PairPhase::Completing
                    )
            })
            .collect();
        match open.as_slice() {
            [] => Err(PairConfirmError::SessionGone),
            [one] => Ok(one.clone()),
            _ => Err(PairConfirmError::AmbiguousSession),
        }
    }
}

/// Operator/CLI confirm error codes (PAIR-V2.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairConfirmError {
    NotBound,
    AmbiguousSession,
    AlreadyDecided,
    SessionGone,
    AmbiguousPending,
    BadCode,
    Other(String),
}

impl PairConfirmError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotBound => "not_bound",
            Self::AmbiguousSession => "ambiguous_session",
            Self::AlreadyDecided => "already_decided",
            Self::SessionGone => "session_gone",
            Self::AmbiguousPending => "ambiguous_pending",
            Self::BadCode => "bad_code",
            Self::Other(_) => "error",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::NotBound => {
                "Joiner has not dialed yet — wait for JoinRequest / finish dual-scan order, then re-run confirm.".into()
            }
            Self::AmbiguousSession => {
                "multiple active pair sessions — pass --sid <sid>".into()
            }
            Self::AlreadyDecided => "pair session already decided / confirm consumed".into(),
            Self::SessionGone => "no active pair session (expired or missing)".into(),
            Self::AmbiguousPending => {
                "multiple pending joiners — pass --joiner <did>".into()
            }
            Self::BadCode => "confirm code does not match accept or deny for bound joiner".into(),
            Self::Other(s) => s.clone(),
        }
    }
}

impl std::fmt::Display for PairConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for PairConfirmError {}

/// Result of a successful `apply_pair_confirm`.
#[derive(Clone, Debug)]
pub struct ConfirmApplyResult {
    pub session: PairSessionFile,
    pub decision: JoinDecision,
    pub joiner: DeviceId,
}

/// Fail-closed confirm-on-machine (PAIR-V2.md §Confirm CLI).
///
/// 1. Resolve session (`sid` or unique active).
/// 2. Binding gate: bound joiner, or arm+single pending → bind, or zero → `not_bound`.
/// 3. HMAC verify accept/deny; write JoinStore + session phase `decided`.
pub fn apply_pair_confirm(
    store: &PairSessionStore,
    joins: &JoinStore,
    code: &str,
    sid: Option<&str>,
    joiner_hint: Option<DeviceId>,
) -> std::result::Result<ConfirmApplyResult, PairConfirmError> {
    let mut sess = store.resolve_session(sid)?;

    if sess.is_expired_now() {
        let _ = store.expire_if_needed(&sess.sid);
        return Err(PairConfirmError::SessionGone);
    }

    // Terminal / already consumed
    if sess.confirm_consumed
        || matches!(
            sess.phase,
            PairPhase::Decided
                | PairPhase::Completing
                | PairPhase::Completed
                | PairPhase::Expired
                | PairPhase::FailedPartial
        )
    {
        return Err(PairConfirmError::AlreadyDecided);
    }

    let pepper = store
        .load_token_raw(&sess.sid)
        .map_err(|e| PairConfirmError::Other(e.to_string()))?
        .ok_or_else(|| {
            PairConfirmError::Other("bootstrap token missing for session (re-run pair dual)".into())
        })?;

    // --- Binding gate ---
    let joiner = resolve_bind_joiner(store, joins, &mut sess, joiner_hint, &pepper, code)?;

    let resident_hex = sess.resident_device_id.to_string();
    let joiner_hex = joiner.to_string();
    let codes = compute_confirm_codes(&pepper, &sess.sid, &joiner_hex, &resident_hex, &sess.nonce);

    let is_accept = confirm_codes_equal(code, &codes.accept);
    let is_deny = confirm_codes_equal(code, &codes.deny);
    if !is_accept && !is_deny {
        return Err(PairConfirmError::BadCode);
    }

    let decision = if is_accept {
        JoinDecision::Accept
    } else {
        JoinDecision::Deny {
            reason: "denied via pair confirm".into(),
        }
    };

    joins
        .write_decision(&joiner, decision.clone())
        .map_err(|e| PairConfirmError::Other(e.to_string()))?;

    let sess = store
        .write_decision(&sess.sid, decision.clone(), true)
        .map_err(|e| PairConfirmError::Other(e.to_string()))?;

    // On accept, disarm rules are applied by the join host loop (alpha.1).
    Ok(ConfirmApplyResult {
        session: sess,
        decision,
        joiner,
    })
}

/// Resolve which joiner to verify against; may bind armed session to a pending peer.
fn resolve_bind_joiner(
    store: &PairSessionStore,
    joins: &JoinStore,
    sess: &mut PairSessionFile,
    joiner_hint: Option<DeviceId>,
    pepper: &[u8; 32],
    code: &str,
) -> std::result::Result<DeviceId, PairConfirmError> {
    // Already bound
    if sess.phase == PairPhase::Bound {
        if let Some(j) = sess.joiner_device_id {
            if let Some(hint) = joiner_hint {
                if hint != j {
                    return Err(PairConfirmError::Other(
                        "session bound to a different joiner than --joiner".into(),
                    ));
                }
            }
            return Ok(j);
        }
    }

    if sess.phase != PairPhase::Armed {
        return Err(PairConfirmError::Other(format!(
            "cannot confirm in phase {}",
            sess.phase.as_str()
        )));
    }

    let pending = joins
        .list_pending()
        .map_err(|e| PairConfirmError::Other(e.to_string()))?;

    match pending.as_slice() {
        [] => Err(PairConfirmError::NotBound),
        [one] => {
            if let Some(hint) = joiner_hint {
                if hint != one.device_id {
                    return Err(PairConfirmError::Other(
                        "pending joiner does not match --joiner".into(),
                    ));
                }
            }
            bind_pending(store, sess, one)
        }
        many => {
            // Multiple pending: require --joiner whose recomputed code matches input.
            let hint = joiner_hint.ok_or(PairConfirmError::AmbiguousPending)?;
            let p = many
                .iter()
                .find(|p| p.device_id == hint)
                .ok_or_else(|| PairConfirmError::Other("no pending join for --joiner".into()))?;
            let resident_hex = sess.resident_device_id.to_string();
            let joiner_hex = p.device_id.to_string();
            let codes =
                compute_confirm_codes(pepper, &sess.sid, &joiner_hex, &resident_hex, &sess.nonce);
            if !confirm_codes_equal(code, &codes.accept) && !confirm_codes_equal(code, &codes.deny)
            {
                return Err(PairConfirmError::BadCode);
            }
            bind_pending(store, sess, p)
        }
    }
}

fn bind_pending(
    store: &PairSessionStore,
    sess: &mut PairSessionFile,
    p: &PendingJoin,
) -> std::result::Result<DeviceId, PairConfirmError> {
    let bound = store
        .bind_joiner(
            &sess.sid,
            p.device_id,
            Some(p.label.clone()),
            Some(p.fingerprint.clone()),
        )
        .map_err(|e| PairConfirmError::Other(e.to_string()))?;
    *sess = bound;
    Ok(p.device_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceId;

    fn tmp_store() -> (PairSessionStore, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "mymesh-pair-sess-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = PairSessionStore::open(&root).unwrap();
        (store, root)
    }

    #[test]
    fn arm_persists_hash_not_raw_token_and_nonce_16b() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0xabu8; 32]);
        let armed = store
            .arm_new("mesh-1", resident, 900, PairEndpointClass::Confirm)
            .unwrap();
        assert_eq!(armed.session.phase, PairPhase::Armed);
        assert_eq!(armed.session.nonce.len(), 16);
        assert_eq!(armed.token_raw.len(), 32);
        assert_eq!(armed.session.token_hash, hash_pair_token(&armed.token_raw));
        // disk has hash, not raw token bytes as base64
        let raw = std::fs::read_to_string(store.path_for(&armed.session.sid)).unwrap();
        assert!(!raw.contains(&hex::encode(armed.token_raw)));
        assert!(raw.contains(&armed.session.token_hash));
        // reload
        let loaded = store.load(&armed.session.sid).unwrap().unwrap();
        assert_eq!(loaded.nonce, armed.session.nonce);
        assert_eq!(loaded.resident_device_id, resident);
        assert!(loaded.token_matches(&armed.token_raw));
        assert!(!loaded.token_matches(&[0u8; 32]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn phase_bind_and_decision() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0x11u8; 32]);
        let joiner = DeviceId::from_bytes([0x22u8; 32]);
        let armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Direct)
            .unwrap();
        let sid = armed.session.sid.clone();

        let bound = store
            .bind_joiner(&sid, joiner, Some("laptop".into()), Some("fp".into()))
            .unwrap();
        assert_eq!(bound.phase, PairPhase::Bound);
        assert_eq!(bound.joiner_device_id, Some(joiner));

        // idempotent same joiner
        let bound2 = store.bind_joiner(&sid, joiner, None, None).unwrap();
        assert_eq!(bound2.phase, PairPhase::Bound);

        // different joiner fails
        let other = DeviceId::from_bytes([0x33u8; 32]);
        assert!(store.bind_joiner(&sid, other, None, None).is_err());

        let decided = store
            .write_decision(&sid, JoinDecision::Accept, false)
            .unwrap();
        assert_eq!(decided.phase, PairPhase::Decided);
        assert!(matches!(decided.decision, Some(JoinDecision::Accept)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn find_by_token_and_active() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0x44u8; 32]);
        let a = store
            .arm_new("m", resident, 600, PairEndpointClass::Confirm)
            .unwrap();
        let found = store.find_by_token_raw(&a.token_raw).unwrap().unwrap();
        assert_eq!(found.sid, a.session.sid);
        assert!(store.find_by_token_raw(&[9u8; 32]).unwrap().is_none());
        let active = store.active_session().unwrap().unwrap();
        assert_eq!(active.sid, a.session.sid);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sid_is_ulid_shaped() {
        let s = new_pair_sid();
        assert_eq!(s.len(), 26);
        assert!(s.chars().all(|c| CROCKFORD.contains(&(c as u8))
            || CROCKFORD.contains(&(c.to_ascii_uppercase() as u8))));
    }

    #[test]
    fn cannot_bind_when_expired() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0x55u8; 32]);
        let mut armed = store
            .arm_new("m", resident, 1, PairEndpointClass::Confirm)
            .unwrap();
        // force until into the past
        armed.session.until = Utc::now() - chrono::Duration::seconds(10);
        store.save(&armed.session).unwrap();
        let joiner = DeviceId::from_bytes([0x66u8; 32]);
        let err = store.bind_joiner(&armed.session.sid, joiner, None, None);
        assert!(err.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn arm_saves_token_sidecar() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0x77u8; 32]);
        let armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Confirm)
            .unwrap();
        let loaded = store.load_token_raw(&armed.session.sid).unwrap().unwrap();
        assert_eq!(loaded, armed.token_raw);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn confirm_not_bound_fail_closed() {
        let (store, root) = tmp_store();
        let join_root = root.join("join");
        let joins = JoinStore::open(&join_root).unwrap();
        let resident = DeviceId::from_bytes([0xa1u8; 32]);
        let armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Confirm)
            .unwrap();
        let err = apply_pair_confirm(&store, &joins, "ZCRE-1R14", Some(&armed.session.sid), None)
            .unwrap_err();
        assert_eq!(err, PairConfirmError::NotBound);
        // stay armed
        let s = store.load(&armed.session.sid).unwrap().unwrap();
        assert_eq!(s.phase, PairPhase::Armed);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn confirm_bind_single_pending_and_accept() {
        use crate::pair_confirm::compute_confirm_codes;
        use crate::PendingJoin;

        let (store, root) = tmp_store();
        let join_root = root.join("join");
        let joins = JoinStore::open(&join_root).unwrap();
        let resident = DeviceId::from_bytes([0xa1u8; 32]);
        let joiner = DeviceId::from_bytes([0xb2u8; 32]);
        let armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Confirm)
            .unwrap();
        joins
            .write_pending(&PendingJoin {
                device_id: joiner,
                label: "laptop".into(),
                capabilities: vec![],
                received_at: Utc::now(),
                fingerprint: "fp".into(),
            })
            .unwrap();

        let codes = compute_confirm_codes(
            &armed.token_raw,
            &armed.session.sid,
            &joiner.to_string(),
            &resident.to_string(),
            &armed.session.nonce,
        );
        let res = apply_pair_confirm(
            &store,
            &joins,
            &codes.accept,
            Some(&armed.session.sid),
            None,
        )
        .unwrap();
        assert!(matches!(res.decision, JoinDecision::Accept));
        assert_eq!(res.joiner, joiner);
        assert_eq!(res.session.phase, PairPhase::Decided);
        assert!(res.session.confirm_consumed);

        // single-use
        let err = apply_pair_confirm(
            &store,
            &joins,
            &codes.accept,
            Some(&armed.session.sid),
            None,
        )
        .unwrap_err();
        assert_eq!(err, PairConfirmError::AlreadyDecided);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn confirm_deny_code_writes_deny() {
        use crate::pair_confirm::compute_confirm_codes;

        let (store, root) = tmp_store();
        let joins = JoinStore::open(root.join("join")).unwrap();
        let resident = DeviceId::from_bytes([0xa1u8; 32]);
        let joiner = DeviceId::from_bytes([0xb2u8; 32]);
        let armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Confirm)
            .unwrap();
        store
            .bind_joiner(&armed.session.sid, joiner, Some("x".into()), None)
            .unwrap();
        let codes = compute_confirm_codes(
            &armed.token_raw,
            &armed.session.sid,
            &joiner.to_string(),
            &resident.to_string(),
            &armed.session.nonce,
        );
        let res = apply_pair_confirm(&store, &joins, &codes.deny, Some(&armed.session.sid), None)
            .unwrap();
        assert!(matches!(res.decision, JoinDecision::Deny { .. }));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn optional_tls_pin_persists_on_session() {
        let (store, root) = tmp_store();
        let resident = DeviceId::from_bytes([0xc3u8; 32]);
        let mut armed = store
            .arm_new("m", resident, 600, PairEndpointClass::Direct)
            .unwrap();
        assert!(armed.session.tls_pin.is_none());
        let pin = crate::TlsPin::from_spki_der(&[0x30, 0x02, 0xaa, 0xbb]).to_wire();
        armed.session.tls_pin = Some(pin.clone());
        store.save(&armed.session).unwrap();
        let loaded = store.load(&armed.session.sid).unwrap().unwrap();
        assert_eq!(loaded.tls_pin.as_deref(), Some(pin.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }
}
