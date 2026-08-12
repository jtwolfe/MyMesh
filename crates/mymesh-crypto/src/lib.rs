//! Cryptographic primitives for MyMesh.
//!
//! - Long-term Ed25519 identity (device id = public key bytes)
//! - SPAKE2 password-authenticated pairing from short codes
//! - BIP39 24-word display encoding of device ids
//! - HKDF session key derivation after pairing / handshake
//! - Mesh master key (MMK): Argon2id wrap of mesh root key (MRK)

mod identity;
mod master_key;
mod pairing;
mod word_id;
mod words;

pub use identity::{Identity, IdentityPublic};
pub use master_key::{
    derive_wrap_key, find_recovery_code, generate_recovery_codes, mesh_init, mesh_recover_with_code,
    mesh_rotate_password, mesh_unlock_password, mrk_fingerprint, unwrap_mrk, wrap_mrk, KdfParams,
    MeshInitResult, MeshMasterFile, MmkRuntime, Mrk, RecoveryCode, WrappedMrk, DEFAULT_M_KIB,
    DEFAULT_P, DEFAULT_T, HKDF_ADMIN_MAC, HKDF_ADMIN_SIGN, RECOVERY_CODE_COUNT,
};
pub use pairing::{PairingRole, PairingSession, SharedSecret};
pub use word_id::{device_id_to_words, device_join_uri, parse_device_id};
pub use words::{code_from_entropy, parse_code, PairingCode};
