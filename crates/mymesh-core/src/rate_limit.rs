//! Process-local rate limits (S9 / CARRIER-NEXT defaults).
//!
//! Sliding windows keyed by token hash, IP, person_id, or session id.
//! Shared across pair HTTP, mesh auth, confirm CLI, grant mutate, and
//! backup unwrap so decide + confirm share the same per-token budget.
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

/// Which limiter bucket to consult.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    PairDecide,
    PairStatus,
    MeshAuthChallenge,
    OwnerBackupUnwrap,
    GrantMutate,
}

impl LimitKind {
    pub fn policy(self) -> Policy {
        match self {
            Self::PairDecide => PAIR_DECIDE,
            Self::PairStatus => PAIR_STATUS,
            Self::MeshAuthChallenge => MESH_AUTH_CHALLENGE,
            Self::OwnerBackupUnwrap => OWNER_BACKUP_UNWRAP,
            Self::GrantMutate => GRANT_MUTATE,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PairDecide => "pair_decide",
            Self::PairStatus => "pair_status",
            Self::MeshAuthChallenge => "mesh_auth_challenge",
            Self::OwnerBackupUnwrap => "owner_backup_unwrap",
            Self::GrantMutate => "grant_mutate",
        }
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

#[derive(Default)]
struct Window {
    hits: VecDeque<Instant>,
}

impl Window {
    fn prune(&mut self, window: Duration, now: Instant) {
        while let Some(front) = self.hits.front() {
            if now.duration_since(*front) >= window {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns Ok when under limit (records hit); Err with retry-after when over.
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
struct Store {
    pair_decide: HashMap<String, Window>,
    pair_status: HashMap<String, Window>,
    mesh_auth_challenge: HashMap<String, Window>,
    owner_backup_unwrap: HashMap<String, Window>,
    grant_mutate: HashMap<String, Window>,
}

impl Store {
    fn bucket_mut(&mut self, kind: LimitKind) -> &mut HashMap<String, Window> {
        match kind {
            LimitKind::PairDecide => &mut self.pair_decide,
            LimitKind::PairStatus => &mut self.pair_status,
            LimitKind::MeshAuthChallenge => &mut self.mesh_auth_challenge,
            LimitKind::OwnerBackupUnwrap => &mut self.owner_backup_unwrap,
            LimitKind::GrantMutate => &mut self.grant_mutate,
        }
    }

    fn check(&mut self, kind: LimitKind, key: &str) -> Result<(), RateLimited> {
        let policy = kind.policy();
        let now = Instant::now();
        let win = self.bucket_mut(kind).entry(key.to_string()).or_default();
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
        *self = Store::default();
    }
}

fn global() -> &'static Mutex<Store> {
    static G: OnceLock<Mutex<Store>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(Store::default()))
}

/// Record a hit for `key` under `kind` on the **process-global** store
/// (CLI confirm / grant / backup unwrap; shared with HTTP decide via token_hash).
pub fn check(kind: LimitKind, key: &str) -> Result<(), RateLimited> {
    let mut g = global().lock().unwrap_or_else(|e| e.into_inner());
    g.check(kind, key)
}

/// Clear all process-local windows (tests only).
pub fn reset_for_tests() {
    let mut g = global().lock().unwrap_or_else(|e| e.into_inner());
    g.clear();
}

/// Host-local / CLI grant mutate key when no mesh session token exists.
pub const HOST_LOCAL_SESSION: &str = "host-local";

/// Isolated limiter map for HTTP servers (avoids cross-test pollution).
/// Process-global [`check`] still used for decide/confirm token budget.
#[derive(Default)]
pub struct RateLimitState {
    store: Mutex<Store>,
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
        // Fresh windows on clone — intentional: each carrier process holds one Arc.
        // (CarrierState clones share Arc<RateLimitState> instead.)
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks() {
        reset_for_tests();
        let key = "tok-test-allow";
        for i in 0..PAIR_DECIDE.max {
            check(LimitKind::PairDecide, key)
                .unwrap_or_else(|e| panic!("hit {i} should pass: {e}"));
        }
        let err = check(LimitKind::PairDecide, key).expect_err("over limit");
        assert_eq!(err.kind, LimitKind::PairDecide);
        assert!(err.retry_after_secs >= 1);
        // Different key still ok
        check(LimitKind::PairDecide, "other-token").unwrap();
    }

    #[test]
    fn independent_kinds_same_key() {
        reset_for_tests();
        let key = "ip-1.2.3.4";
        for _ in 0..PAIR_STATUS.max {
            check(LimitKind::PairStatus, key).unwrap();
        }
        // Mesh challenge uses separate bucket
        check(LimitKind::MeshAuthChallenge, key).unwrap();
        assert!(check(LimitKind::PairStatus, key).is_err());
    }

    #[test]
    fn backup_unwrap_five_per_15min() {
        reset_for_tests();
        let pid = "person-abc";
        for _ in 0..OWNER_BACKUP_UNWRAP.max {
            check(LimitKind::OwnerBackupUnwrap, pid).unwrap();
        }
        assert!(check(LimitKind::OwnerBackupUnwrap, pid).is_err());
    }
}
