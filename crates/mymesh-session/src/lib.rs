//! Pairing, join requests, sessions, agent, magic plane, carrier, mesh/v1 API.

mod agent;
mod carrier;
mod host_metrics;
mod join;
mod magic;
mod mesh_api;
mod mesh_sync;
mod pair;
mod session;
mod tcp_tunnel;

#[cfg(test)]
mod two_agent_harness;

pub use agent::Agent;
pub use carrier::{
    build_pair_qr, build_pair_qr_v2, carrier_pending_path, decode_pair_nonce, encode_pair_nonce,
    start_carrier, CarrierHandle, PairQrV2Params, PAIR_HTTP_PORT, PAIR_V1_PREFIX, PAIR_V2_PREFIX,
};
pub use mesh_api::{auth_challenge_preimage, mrk_admin_identity, AuthMethod, MESH_V1_PREFIX};
// Re-export owner types from crypto for callers that used mesh_api::MeshOwnerFile (B3).
pub use host_metrics::sample_metrics;
pub use join::{handle_join_as_host, handle_join_as_host_with_grants, run_join_as_guest};
pub use magic::MagicPlane;
pub use mesh_sync::{
    apply_grant_revoke, apply_kick_notice_local, apply_kick_target, apply_membership,
    build_announce, build_grant_revoke, build_snapshot, bump_mesh_dirty, members_from_store,
    sign_grant_announce, sign_grant_revoke, sign_kick, sign_leave_ack, verify_grant_announce,
    verify_grant_revoke, verify_kick, verify_leave_ack, verify_membership,
};
pub use mymesh_crypto::MeshOwnerFile;
pub use pair::{run_guest_pair, run_host_pair, run_host_pair_code, PairOutcome};
pub use session::Session;
pub use tcp_tunnel::{client_bridge, host_bridge};
