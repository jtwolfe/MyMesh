//! Cryptographic primitives for MyMesh.
//!
//! - Long-term Ed25519 identity (device id = public key bytes)
//! - SPAKE2 password-authenticated pairing from short codes
//! - BIP39 24-word display encoding of device ids
//! - HKDF session key derivation after pairing / handshake

mod identity;
mod pairing;
mod word_id;
mod words;

pub use identity::{Identity, IdentityPublic};
pub use pairing::{PairingRole, PairingSession, SharedSecret};
pub use word_id::{device_id_to_words, device_join_uri, parse_device_id};
pub use words::{code_from_entropy, parse_code, PairingCode};
