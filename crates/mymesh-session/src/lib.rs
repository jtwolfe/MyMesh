//! Pairing and session lifecycle.
//!
//! Pairing mirrors Signal's linked-devices flow:
//! 1. Host shows a short code (`42-maple-orbit`)
//! 2. Guest enters the code
//! 3. SPAKE2 derives a shared secret over the rendezvous channel
//! 4. Peers exchange long-term identities + capability grants
//! 5. Both sides persist a trusted `DeviceRecord`

mod pair;
mod session;

pub use pair::{run_guest_pair, run_host_pair, PairOutcome};
pub use session::Session;
