//! Pairing, join requests, sessions, and agent accept loop.

mod agent;
mod join;
mod host_metrics;
mod mesh_sync;
mod pair;
mod session;

pub use agent::Agent;
pub use host_metrics::sample_metrics;
pub use join::{handle_join_as_host, run_join_as_guest};
pub use mesh_sync::{
    apply_kick_notice_local, apply_kick_target, apply_membership, build_announce, build_snapshot,
    members_from_store, sign_kick, verify_kick, verify_membership,
};
pub use pair::{run_guest_pair, run_host_pair, run_host_pair_code, PairOutcome};
pub use session::Session;
