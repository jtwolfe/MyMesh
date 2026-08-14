//! Pairing, join requests, sessions, agent, magic plane.
//!
//! Note: Carrier HTTP pairing (pair/v1, pair/v2, /mesh/v1) removed per REWORK-UNIFY.md.
//! 24-word device-to-device pairing retained.

mod agent;
mod host_metrics;
mod join;
mod magic;
mod mesh_sync;
mod pair;
mod session;
mod tcp_tunnel;

#[cfg(test)]
mod two_agent_harness;

pub use agent::Agent;
pub use host_metrics::sample_metrics;
pub use join::{
    handle_join_as_host, handle_join_as_host_with_grants, run_join_as_guest,
    spawn_join_as_guest_to_resident, JoinHostOutcome,
};
pub use magic::MagicPlane;
pub use mesh_sync::{
    apply_grant_revoke, apply_kick_notice_local, apply_kick_target, apply_membership,
    apply_membership_gossip, build_announce, build_grant_revoke, build_snapshot, bump_mesh_dirty,
    members_from_store, peer_may_mutate_grants, peer_receives_mesh_gossip, sign_grant_announce,
    sign_grant_revoke, sign_kick, sign_leave_ack, verify_grant_announce, verify_grant_revoke,
    verify_kick, verify_leave_ack, verify_membership,
};
pub use mymesh_crypto::MeshOwnerFile;
pub use pair::{run_guest_pair, run_host_pair, run_host_pair_code, PairOutcome};
pub use session::Session;
pub use tcp_tunnel::{client_bridge, host_bridge};
