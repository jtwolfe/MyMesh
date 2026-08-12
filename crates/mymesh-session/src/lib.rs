//! Pairing, join requests, sessions, agent, magic plane, carrier.

mod agent;
mod carrier;
mod host_metrics;
mod join;
mod magic;
mod mesh_sync;
mod pair;
mod session;
mod tcp_tunnel;

pub use agent::Agent;
pub use carrier::{
    build_pair_qr, build_pair_qr_v2, carrier_pending_path, decode_pair_nonce, encode_pair_nonce,
    start_carrier, CarrierHandle, PairQrV2Params, PAIR_HTTP_PORT, PAIR_V1_PREFIX, PAIR_V2_PREFIX,
};
pub use host_metrics::sample_metrics;
pub use join::{handle_join_as_host, run_join_as_guest};
pub use magic::MagicPlane;
pub use mesh_sync::{
    apply_kick_notice_local, apply_kick_target, apply_membership, build_announce, build_snapshot,
    bump_mesh_dirty, members_from_store, sign_kick, sign_leave_ack, verify_kick, verify_leave_ack,
    verify_membership,
};
pub use pair::{run_guest_pair, run_host_pair, run_host_pair_code, PairOutcome};
pub use session::Session;
pub use tcp_tunnel::{client_bridge, host_bridge};
