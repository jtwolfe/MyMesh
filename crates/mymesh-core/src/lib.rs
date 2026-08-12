//! Core types shared across the MyMesh stack.

mod config;
mod device;
mod error;
mod event_metrics;
mod grants;
mod identity;
mod join;
mod mesh;
mod mesh_ip;
mod metrics;
mod pair_confirm;
mod pair_session;
mod paths;
mod rate_limit;

pub use config::{Config, DaemonConfig, Limits, MagicConfig};
pub use device::{
    remote_admin_authority, AdminAuthority, Capability, DeviceRecord, DeviceStore, MeshRole,
    TrustState,
};
pub use error::{Error, Result};
pub use event_metrics::{
    record_grant_mutate, record_mesh_auth_challenge, record_owner_backup_unwrap,
    record_pair_decide, record_pair_status, with_counters, EventCounters,
};
pub use grants::{
    allows, allows_at, apply_guest_device_record, new_grant_id, not_after_days, parse_capabilities,
    Grant, GrantConstraints, GrantObject, GrantRole, GrantStore, IdentityFacet, IssuedBy,
};
pub use identity::{DeviceId, DeviceLabel, NodeFingerprint};
pub use join::{ArmState, JoinDecision, JoinStore, PendingJoin};
pub use mesh::{
    mark_mesh_dirty, mesh_dirty_mtime, KickNoticeRecord, MeshMember, MeshState, PendingKick,
    PendingKickStore,
};
pub use mesh_ip::{mesh_ip_string, mesh_ipv4};
pub use metrics::{BandwidthResult, HostStatsSnap, LatencySample, PeerMetrics};
pub use pair_confirm::{
    compute_confirm_code, compute_confirm_codes, confirm_code_material, confirm_codes_equal,
    crockford_base32_encode, format_confirm_code_display, normalize_confirm_code_input,
    ConfirmCodes, CONFIRM_DOMAIN, CONFIRM_FLAG_ACCEPT, CONFIRM_FLAG_DENY, CONFIRM_HMAC_TRUNCATE,
    PAIR_NONCE_LEN,
};
pub use pair_session::{
    apply_pair_confirm, ct_eq, hash_pair_token, new_pair_sid, ArmedPairSession, ConfirmApplyResult,
    PairConfirmError, PairEndpointClass, PairPhase, PairSessionFile, PairSessionStore,
};
pub use paths::Paths;
pub use rate_limit::{
    check as rate_limit_check, check_shared as rate_limit_check_shared,
    clear_shared_for_tests as rate_limit_clear_shared_for_tests, client_ip_key,
    metrics_dir_from_pair_sessions, reset_for_tests as rate_limit_reset_for_tests,
    trust_proxy_enabled, LimitKind, Policy, RateLimitState, RateLimited, GRANT_MUTATE,
    HOST_LOCAL_SESSION, MESH_AUTH_CHALLENGE, OWNER_BACKUP_UNWRAP, PAIR_DECIDE, PAIR_STATUS,
};
