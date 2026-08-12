//! Cryptographic primitives for MyMesh.
//!
//! - Long-term Ed25519 identity (device id = public key bytes)
//! - SPAKE2 password-authenticated pairing from short codes
//! - BIP39 24-word display encoding of device ids
//! - HKDF session key derivation after pairing / handshake
//! - Mesh master key (MMK): Argon2id wrap of mesh root key (MRK)
//! - Owner claim preimage + sealed person backup (S4)

mod identity;
mod master_key;
mod owner;
mod pairing;
mod word_id;
mod words;

pub use identity::{Identity, IdentityPublic};
pub use master_key::{
    admin_mac_key, admin_signing_key, admin_verifying_key_bytes, derive_wrap_key,
    find_recovery_code, generate_recovery_codes, mesh_init, mesh_recover_with_code,
    mesh_rotate_password, mesh_unlock_password, mrk_fingerprint, mrk_proof_preimage,
    sign_mrk_proof_ed25519, sign_mrk_proof_hmac, unwrap_mrk, verify_mrk_admin_proof,
    verify_mrk_proof_ed25519, verify_mrk_proof_ed25519_with_vk, verify_mrk_proof_hmac, wrap_mrk,
    KdfParams, MeshInitResult, MeshMasterFile, MmkRuntime, Mrk, MrkAdminProof, MrkProofMethod,
    RecoveryCode, WrappedMrk, DEFAULT_M_KIB, DEFAULT_P, DEFAULT_T, HKDF_ADMIN_MAC,
    HKDF_ADMIN_SIGN, MRK_PROOF_DOMAIN, RECOVERY_CODE_COUNT,
};
pub use owner::{
    accept_owner_claim, check_claim_authorized, owner_claim_preimage, resolve_claim_fingerprint,
    seal_owner_backup, sign_owner_claim, unseal_owner_backup, verify_owner_claim_sig,
    ClaimAuthMethod, ClaimWindowFile, MeshOwnerFile, OwnerBackupSealed, OwnerClaimRequest,
    OWNER_CLAIM_DOMAIN,
};
pub use pairing::{PairingRole, PairingSession, SharedSecret};
pub use word_id::{device_id_to_words, device_join_uri, parse_device_id};
pub use words::{code_from_entropy, parse_code, PairingCode};
