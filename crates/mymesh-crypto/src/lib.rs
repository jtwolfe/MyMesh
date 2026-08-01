//! Cryptographic primitives for MyMesh.
//!
//! - Long-term Ed25519 identity (device id = public key bytes)
//! - SPAKE2 password-authenticated pairing from short codes
//! - HKDF session key derivation after pairing / handshake

mod identity;
mod pairing;
mod words;

pub use identity::{Identity, IdentityPublic};
pub use pairing::{PairingRole, PairingSession, SharedSecret};
pub use words::{code_from_entropy, parse_code, PairingCode};
