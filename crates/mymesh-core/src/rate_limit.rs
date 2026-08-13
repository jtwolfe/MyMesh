//! Rate limits (S9 / CARRIER-NEXT defaults).
//!
//! ## Multi-process design
//!
//! | Kind | Scope | Storage |
//! |------|-------|---------|
//! | `PairDecide` | 10 / min / token | **File-backed** under `metrics_dir/rate-limits.json` so carrier HTTP decide and CLI `pair confirm` share one budget on the same host |
//! | `OwnerBackupUnwrap` | 5 / 15 min / person_id | **File-backed** (CLI unwrap attempts across processes) |
//! | `GrantMutate` | 30 / min / session | **File-backed** |
//! | `AdminEnvelope` | 30 / min / person_id | **File-backed** (F4p: serve is the consumer) |
//! | `EnrollWrite` | 10 / min / person_id | **File-backed** (CLI add; HTTP F4) |
//! | `MailboxBind` | 10 / min / ip | **File-backed** (F4p type; mailbox poller F6) |
//! | `MailboxPut` | 30 / min / did | **File-backed** (F4p type; mailbox poller F6) |
//! | `PairStatus` | 60 / min / ip | **In-process** (`RateLimitState` on carrier) — same process as status HTTP |
//! | `MeshAuthChallenge` | 30 / min / ip | **In-process** (carrier mesh routes) |
//!
//! File windows use wall-clock unix seconds (not `Instant`) so they survive
//! process boundaries. A simple exclusive lock file serializes updates.
//!
//! ## IP keys
//!
//! Prefer TCP peer address (`ConnectInfo`). Client-supplied `X-Forwarded-For` /
//! `X-Real-IP` are **ignored** unless `MYMESH_TRUST_PROXY=1|true|yes` (explicit
//! reverse-proxy deployment). Without a peer address (e.g. unit tests that do
//! not inject `ConnectInfo`), the key is `"unknown"`.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// S9 default policies.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub max: u32,
    pub window: Duration,
}

/// pair decide / confirm — 10 / min / token.
pub const PAIR_DECIDE: Policy = Policy {
    max: 10,
    window: Duration::from_secs(60),
};
/// pair status unauth — 60 / min / ip.
pub const PAIR_STATUS: Policy = Policy {
    max: 60,
    window: Duration::from_secs(60),
};
/// mesh auth challenge — 30 / min / ip.
pub const MESH_AUTH_CHALLENGE: Policy = Policy {
    max: 30,
    window: Duration::from_secs(60),
};
/// backup unwrap attempts — 5 / 15 min / person_id.
pub const OWNER_BACKUP_UNWRAP: Policy = Policy {
    max: 5,
    window: Duration::from_secs(15 * 60),
};
/// grant mutate — 30 / min / session.
pub const GRANT_MUTATE: Policy = Policy {
    max: 30,
    window: Duration::from_secs(60),
};
/// AdminEnvelope RPC — 30 / min / person_id (F1; F4p file-backed on serve).
pub const ADMIN_ENVELOPE: Policy = Policy {
    max: 30,
    window: Duration::from_secs(60),
};
/// Enroll write — 10 / min / person_id (CLI add; HTTP F4).
pub const ENROLL_WRITE: Policy = Policy {
    max: 10,
    window: Duration::from_secs(60),
};
/// Mailbox device bind — 10 / min / ip (F1 type; unused this PR).
pub const MAILBOX_BIND: Policy = Policy {
    max: 10,
    window: Duration::from_secs(60),
};
/// Mailbox inbox put — 30 / min / did (F1 type; unused this PR).
pub const MAILBOX_PUT: Policy = Policy {
    max: 30,
    window: Duration::from_secs(60),
};

/// Which limiter bucket to consult.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    PairDecide,
    PairStatus,
    MeshAuthChallenge,
    OwnerBackupUnwrap,
    GrantMutate,
    AdminEnvelope,
    EnrollWrite,
    MailboxBind,
    MailboxPut,
}

impl LimitKind {
    pub fn policy(self) -> Policy {
        match self {
            Self::PairDecide => PAIR_DECIDE,
            Self::PairStatus => PAIR_STATUS,
            Self::MeshAuthChallenge => MESH_AUTH_CHALLENGE,
            Self::OwnerBackupUnwrap => OWNER_BACKUP_UNWRAP,
            Self::GrantMutate => GRANT_MUTATE,
            Self::AdminEnvelope => ADMIN_ENVELOPE,
            Self::EnrollWrite => ENROLL_WRITE,
            Self::MailboxBind => MAILBOX_BIND,
            Self::MailboxPut => MAILBOX_PUT,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PairDecide => "pair_decide",
            Self::PairStatus => "pair_status",
            Self::MeshAuthChallenge => "mesh_auth_challenge",
            Self::OwnerBackupUnwrap => "owner_backup_unwrap",
            Self::GrantMutate => "grant_mutate",
            Self::AdminEnvelope => "admin_envelope",
            Self::EnrollWrite => "enroll_write",
            Self::MailboxBind => "mailbox_bind",
            Self::MailboxPut => "mailbox_put",
        }
    }

    /// Kinds that persist under `metrics_dir/rate-limits.json` (serve-owned after F4p).
    pub fn is_file_backed(self) -> bool {
        matches!(
            self,
            Self::PairDecide
                | Self::OwnerBackupUnwrap
                | Self::GrantMutate
                | Self::AdminEnvelope
                | Self::EnrollWrite
                | Self::MailboxBind
                | Self::MailboxPut
        )
    }
}

/// Error when a key has exceeded its policy window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimited {
    pub kind: LimitKind,
    pub key: String,
    pub retry_after_secs: u64,
}

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rate limited ({}, retry after {}s)",
            self.kind.as_str(),
            self.retry_after_secs
        )
    }
}

impl std::error::Error for RateLimited {}

// ── Wall-clock window (file + memory) ───────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sliding window of unix-second hit timestamps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct UnixWindow {
    #[serde(default)]
    hits: VecDeque<u64>,
}

impl UnixWindow {
    fn prune(&mut self, window_secs: u64, now: u64) {
        while let Some(&front) = self.hits.front() {
            if now.saturating_sub(front) >= window_secs {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    fn try_hit(&mut self, policy: Policy, now: u64) -> Result<(), u64> {
        let window_secs = policy.window.as_secs().max(1);
        self.prune(window_secs, now);
        if self.hits.len() as u32 >= policy.max {
            let oldest = self.hits.front().copied().unwrap_or(now);
            let elapsed = now.saturating_sub(oldest);
            let retry = window_secs.saturating_sub(elapsed).max(1);
            return Err(retry);
        }
        self.hits.push_back(now);
        Ok(())
    }
}

// ── In-process Instant windows (IP-scoped HTTP only) ────────────────────────

#[derive(Default)]
struct InstantWindow {
    hits: VecDeque<Instant>,
}

impl InstantWindow {
    fn prune(&mut self, window: Duration, now: Instant) {
        while let Some(front) = self.hits.front() {
            if now.duration_since(*front) >= window {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    fn try_hit(&mut self, policy: Policy, now: Instant) -> Result<(), u64> {
        self.prune(policy.window, now);
        if self.hits.len() as u32 >= policy.max {
            let oldest = self.hits.front().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            let retry = policy
                .window
                .checked_sub(elapsed)
                .unwrap_or(Duration::from_secs(1));
            return Err(retry.as_secs().max(1));
        }
        self.hits.push_back(now);
        Ok(())
    }
}

#[derive(Default)]
struct MemStore {
    pair_status: HashMap<String, InstantWindow>,
    mesh_auth_challenge: HashMap<String, InstantWindow>,
}

impl MemStore {
    fn check(&mut self, kind: LimitKind, key: &str) -> Result<(), RateLimited> {
        let policy = kind.policy();
        let now = Instant::now();
        let map = match kind {
            LimitKind::PairStatus => &mut self.pair_status,
            LimitKind::MeshAuthChallenge => &mut self.mesh_auth_challenge,
            _ => {
                // Should use file-backed path; fail closed to process-local unix window.
                return Err(RateLimited {
                    kind,
                    key: key.to_string(),
                    retry_after_secs: 1,
                });
            }
        };
        let win = map.entry(key.to_string()).or_default();
        match win.try_hit(policy, now) {
            Ok(()) => Ok(()),
            Err(retry_after_secs) => Err(RateLimited {
                kind,
                key: key.to_string(),
                retry_after_secs,
            }),
        }
    }

    fn clear(&mut self) {
        *self = MemStore::default();
    }
}

// ── File-backed store ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FileStore {
    #[serde(default)]
    pair_decide: HashMap<String, UnixWindow>,
    #[serde(default)]
    owner_backup_unwrap: HashMap<String, UnixWindow>,
    #[serde(default)]
    grant_mutate: HashMap<String, UnixWindow>,
    #[serde(default)]
    admin_envelope: HashMap<String, UnixWindow>,
    #[serde(default)]
    enroll_write: HashMap<String, UnixWindow>,
    #[serde(default)]
    mailbox_bind: HashMap<String, UnixWindow>,
    #[serde(default)]
    mailbox_put: HashMap<String, UnixWindow>,
}

impl FileStore {
    fn path(metrics_dir: &Path) -> PathBuf {
        metrics_dir.join("rate-limits.json")
    }

    fn lock_path(metrics_dir: &Path) -> PathBuf {
        metrics_dir.join("rate-limits.lock")
    }

    fn load(metrics_dir: &Path) -> Self {
        let path = Self::path(metrics_dir);
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn save(&self, metrics_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(metrics_dir)?;
        let path = Self::path(metrics_dir);
        let tmp = metrics_dir.join(format!("rate-limits.{}.tmp", std::process::id()));
        std::fs::write(
            &tmp,
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into()),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn bucket_mut(&mut self, kind: LimitKind) -> Option<&mut HashMap<String, UnixWindow>> {
        match kind {
            LimitKind::PairDecide => Some(&mut self.pair_decide),
            LimitKind::OwnerBackupUnwrap => Some(&mut self.owner_backup_unwrap),
            LimitKind::GrantMutate => Some(&mut self.grant_mutate),
            LimitKind::AdminEnvelope => Some(&mut self.admin_envelope),
            LimitKind::EnrollWrite => Some(&mut self.enroll_write),
            LimitKind::MailboxBind => Some(&mut self.mailbox_bind),
            LimitKind::MailboxPut => Some(&mut self.mailbox_put),
            _ => None,
        }
    }

    fn check(&mut self, kind: LimitKind, key: &str) -> Result<(), RateLimited> {
        let policy = kind.policy();
        let now = now_unix();
        let map = self.bucket_mut(kind).expect("file-backed kind");
        let win = map.entry(key.to_string()).or_default();
        match win.try_hit(policy, now) {
            Ok(()) => Ok(()),
            Err(retry_after_secs) => Err(RateLimited {
                kind,
                key: key.to_string(),
                retry_after_secs,
            }),
        }
    }
}

/// Best-effort exclusive lock via create_new; removes stale locks (>2s).
struct DirLock {
    path: PathBuf,
}

impl DirLock {
    fn acquire(path: PathBuf) -> Self {
        for attempt in 0..80 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_f) => return Self { path },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt == 40 || attempt == 70 {
                        // Stale lock recovery: if mtime is old, remove.
                        if let Ok(meta) = std::fs::metadata(&path) {
                            if let Ok(modified) = meta.modified() {
                                if modified
                                    .elapsed()
                                    .map(|d| d > Duration::from_secs(2))
                                    .unwrap_or(true)
                                {
                                    let _ = std::fs::remove_file(&path);
                                }
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {
                    // Can't lock; proceed without (best-effort).
                    return Self { path };
                }
            }
        }
        // Last resort: force remove and proceed.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path);
        Self { path }
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// File-backed check for decide / backup unwrap / grant mutate.
///
/// Serializes updates under `metrics_dir/rate-limits.lock`.
pub fn check_shared(
    metrics_dir: impl AsRef<Path>,
    kind: LimitKind,
    key: &str,
) -> Result<(), RateLimited> {
    if !kind.is_file_backed() {
        // IP-scoped kinds stay process-local; fall back to in-memory.
        return check(kind, key);
    }
    let dir = metrics_dir.as_ref();
    let _ = std::fs::create_dir_all(dir);
    let _lock = DirLock::acquire(FileStore::lock_path(dir));
    let mut store = FileStore::load(dir);
    let result = store.check(kind, key);
    if result.is_ok() {
        let _ = store.save(dir);
    }
    // On rate-limited skip rewrite (no new hit recorded).
    result
}

fn fallback_store() -> &'static Mutex<HashMap<(LimitKind, String), UnixWindow>> {
    static FALLBACK: OnceLock<Mutex<HashMap<(LimitKind, String), UnixWindow>>> = OnceLock::new();
    FALLBACK.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Process-global in-memory check (tests / callers without metrics_dir).
/// Prefer [`check_shared`] for PairDecide / backup / grant across processes.
pub fn check(kind: LimitKind, key: &str) -> Result<(), RateLimited> {
    let mut g = fallback_store().lock().unwrap_or_else(|e| e.into_inner());
    let policy = kind.policy();
    let now = now_unix();
    let win = g.entry((kind, key.to_string())).or_default();
    match win.try_hit(policy, now) {
        Ok(()) => Ok(()),
        Err(retry_after_secs) => Err(RateLimited {
            kind,
            key: key.to_string(),
            retry_after_secs,
        }),
    }
}

/// Clear process-local fallback windows (tests only). Does **not** wipe disk files.
pub fn reset_for_tests() {
    fallback_store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

fn clear_fallback_for_tests() {
    reset_for_tests();
}

// Remove dead comment about re-bind

/// Host-local / CLI grant mutate key when no mesh session token exists.
pub const HOST_LOCAL_SESSION: &str = "host-local";

/// Isolated in-process limiter for IP-scoped HTTP limits (status / challenge).
#[derive(Default)]
pub struct RateLimitState {
    store: Mutex<MemStore>,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, kind: LimitKind, key: &str) -> Result<(), RateLimited> {
        let mut g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        g.check(kind, key)
    }

    pub fn reset(&self) {
        let mut g = self.store.lock().unwrap_or_else(|e| e.into_inner());
        g.clear();
    }
}

impl Clone for RateLimitState {
    fn clone(&self) -> Self {
        // Fresh windows on clone — carrier holds Arc<RateLimitState> instead.
        Self::new()
    }
}

// ── Client IP key ───────────────────────────────────────────────────────────

/// True when operator set `MYMESH_TRUST_PROXY=1|true|yes` (reverse-proxy front).
pub fn trust_proxy_enabled() -> bool {
    match std::env::var("MYMESH_TRUST_PROXY") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Build rate-limit key for IP-scoped limits.
///
/// 1. If `MYMESH_TRUST_PROXY` is set: first `X-Forwarded-For` hop, else `X-Real-IP`.
/// 2. Else (default, direct LAN carrier): TCP `peer` IP only — **ignore** client XFF.
/// 3. No peer (tests without `ConnectInfo`): `"unknown"`.
pub fn client_ip_key(
    peer: Option<SocketAddr>,
    headers_xff: Option<&str>,
    headers_real_ip: Option<&str>,
) -> String {
    if trust_proxy_enabled() {
        if let Some(xff) = headers_xff {
            if let Some(first) = xff.split(',').next() {
                let t = first.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
        if let Some(rip) = headers_real_ip {
            let t = rip.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Some(addr) = peer {
        return addr.ip().to_string();
    }
    "unknown".into()
}

/// Derive `metrics_dir` from a pair-sessions store root (`…/data/pair-sessions` → `…/data/metrics`).
pub fn metrics_dir_from_pair_sessions(pair_sessions_root: &Path) -> PathBuf {
    pair_sessions_root
        .parent()
        .map(|p| p.join("metrics"))
        .unwrap_or_else(|| PathBuf::from("metrics"))
}

/// Remove file-backed rate limit state (tests).
pub fn clear_shared_for_tests(metrics_dir: impl AsRef<Path>) {
    let dir = metrics_dir.as_ref();
    let _ = std::fs::remove_file(FileStore::path(dir));
    let _ = std::fs::remove_file(FileStore::lock_path(dir));
    clear_fallback_for_tests();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_metrics() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "mymesh-rl-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            n
        ));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn allows_up_to_max_then_blocks_shared_file() {
        let dir = tmp_metrics();
        clear_shared_for_tests(&dir);
        let key = "tok-file-shared";
        for i in 0..PAIR_DECIDE.max {
            check_shared(&dir, LimitKind::PairDecide, key)
                .unwrap_or_else(|e| panic!("hit {i}: {e}"));
        }
        let err = check_shared(&dir, LimitKind::PairDecide, key).expect_err("over limit");
        assert_eq!(err.kind, LimitKind::PairDecide);
        assert!(err.retry_after_secs >= 1);
        // Persisted — reload sees the budget
        let err2 = check_shared(&dir, LimitKind::PairDecide, key).expect_err("still limited");
        assert_eq!(err2.kind, LimitKind::PairDecide);
        // Other key ok
        check_shared(&dir, LimitKind::PairDecide, "other").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decide_and_confirm_share_file_budget() {
        let dir = tmp_metrics();
        clear_shared_for_tests(&dir);
        let key = "shared-token-hash";
        // Simulate 6 HTTP decides + 4 CLI confirms = 10, then block
        for _ in 0..6 {
            check_shared(&dir, LimitKind::PairDecide, key).unwrap();
        }
        for _ in 0..4 {
            check_shared(&dir, LimitKind::PairDecide, key).unwrap();
        }
        assert!(check_shared(&dir, LimitKind::PairDecide, key).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn f1_kinds_are_file_backed() {
        for kind in [
            LimitKind::AdminEnvelope,
            LimitKind::EnrollWrite,
            LimitKind::MailboxBind,
            LimitKind::MailboxPut,
        ] {
            assert!(kind.is_file_backed(), "{kind:?}");
        }
        assert_eq!(LimitKind::AdminEnvelope.policy().max, 30);
        assert_eq!(LimitKind::MailboxBind.policy().max, 10);
        assert_eq!(LimitKind::MailboxPut.policy().max, 30);
        assert_eq!(LimitKind::EnrollWrite.policy().max, 10);
    }

    #[test]
    fn admin_envelope_file_backed_persists() {
        let dir = tmp_metrics();
        clear_shared_for_tests(&dir);
        let key = "person-admin";
        for _ in 0..ADMIN_ENVELOPE.max {
            check_shared(&dir, LimitKind::AdminEnvelope, key).unwrap();
        }
        assert!(check_shared(&dir, LimitKind::AdminEnvelope, key).is_err());
        assert!(
            FileStore::path(&dir).exists(),
            "serve-owned rate-limits.json must exist"
        );
        let err = check_shared(&dir, LimitKind::AdminEnvelope, key).expect_err("reload");
        assert_eq!(err.kind, LimitKind::AdminEnvelope);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_unwrap_five_per_15min_file() {
        let dir = tmp_metrics();
        clear_shared_for_tests(&dir);
        let pid = "person-abc";
        for _ in 0..OWNER_BACKUP_UNWRAP.max {
            check_shared(&dir, LimitKind::OwnerBackupUnwrap, pid).unwrap();
        }
        assert!(check_shared(&dir, LimitKind::OwnerBackupUnwrap, pid).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ip_state_independent_kinds() {
        let st = RateLimitState::new();
        let key = "10.0.0.1";
        for _ in 0..PAIR_STATUS.max {
            st.check(LimitKind::PairStatus, key).unwrap();
        }
        st.check(LimitKind::MeshAuthChallenge, key).unwrap();
        assert!(st.check(LimitKind::PairStatus, key).is_err());
    }

    #[test]
    fn client_ip_prefers_peer_without_trust_proxy() {
        // Ensure trust proxy off for this test
        std::env::remove_var("MYMESH_TRUST_PROXY");
        let peer: SocketAddr = "192.0.2.10:4444".parse().unwrap();
        let key = client_ip_key(Some(peer), Some("203.0.113.9"), Some("198.51.100.1"));
        assert_eq!(key, "192.0.2.10", "XFF ignored without trust proxy");
        let key2 = client_ip_key(None, Some("203.0.113.9"), None);
        assert_eq!(key2, "unknown");
    }

    #[test]
    fn client_ip_honors_xff_when_trust_proxy() {
        std::env::set_var("MYMESH_TRUST_PROXY", "1");
        let peer: SocketAddr = "192.0.2.10:4444".parse().unwrap();
        let key = client_ip_key(Some(peer), Some("203.0.113.9, 10.0.0.1"), None);
        assert_eq!(key, "203.0.113.9");
        std::env::remove_var("MYMESH_TRUST_PROXY");
    }
}
