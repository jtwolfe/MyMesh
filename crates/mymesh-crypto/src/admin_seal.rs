//! AdminEnvelope seal (F6): X25519 from device Ed25519 + XChaCha20-Poly1305.
//!
//! Same wrap family as continuity, domain-separated with `carrier-admin-seal-v1`.
//! Mailbox stores opaque bytes; only the target device seed unwraps.

use crate::continuity::{ed25519_pk_to_x25519, ed25519_seed_to_x25519};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mymesh_core::wire::{
    decode_nonce16, AdminSealPayload, AdminWireError, ADMIN_MAILBOX_MAX_BYTES, ADMIN_SEAL_DOMAIN,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const X25519_LEN: usize = 32;
const WRAP_NONCE_LEN: usize = 24;
const SEAL_NONCE_LEN: usize = 16;
const MAX_WRAP_BYTES: usize = 256;

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret32([u8; 32]);

impl Secret32 {
    fn random() -> Self {
        let mut s = Self([0u8; 32]);
        OsRng.fill_bytes(&mut s.0);
        s
    }

    fn from_array(a: [u8; 32]) -> Self {
        Self(a)
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Seal errors (wrong device key / corrupt / oversize).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminSealError {
    pub message: String,
}

impl AdminSealError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AdminSealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "admin seal: {}", self.message)
    }
}

impl std::error::Error for AdminSealError {}

impl From<AdminWireError> for AdminSealError {
    fn from(e: AdminWireError) -> Self {
        Self::new(e.message)
    }
}

fn derive_wrap_key(shared: &[u8; 32], eph_pk: &[u8; 32], recipient_x_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ADMIN_SEAL_DOMAIN);
    h.update([0u8]);
    h.update(shared);
    h.update(eph_pk);
    h.update(recipient_x_pk);
    let dig = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&dig);
    key
}

fn wrap_pack_key(
    recipient_x_pk: &[u8; 32],
    pack_key: &[u8; 32],
) -> Result<Vec<u8>, AdminSealError> {
    let mut eph_seed = Secret32::random();
    let eph_secret = StaticSecret::from(*eph_seed.as_array());
    eph_seed.zeroize();
    let eph_public = X25519Public::from(&eph_secret);
    let eph_pk = eph_public.to_bytes();

    let recipient = X25519Public::from(*recipient_x_pk);
    let shared = eph_secret.diffie_hellman(&recipient);
    let mut shared_bytes = Secret32::from_array(*shared.as_bytes());
    let mut key = Secret32::from_array(derive_wrap_key(
        shared_bytes.as_array(),
        &eph_pk,
        recipient_x_pk,
    ));
    shared_bytes.zeroize();

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_array())
        .map_err(|e| AdminSealError::new(format!("wrap cipher: {e}")))?;
    key.zeroize();
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), pack_key.as_slice())
        .map_err(|_| AdminSealError::new("wrap encrypt failed"))?;

    let mut out = Vec::with_capacity(X25519_LEN + WRAP_NONCE_LEN + ct.len());
    out.extend_from_slice(&eph_pk);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_pack_key(recipient_x_sk: &[u8; 32], wrap: &[u8]) -> Result<[u8; 32], AdminSealError> {
    let min = X25519_LEN + WRAP_NONCE_LEN + 16;
    if wrap.len() < min || wrap.len() > MAX_WRAP_BYTES {
        return Err(AdminSealError::new("wrap blob invalid"));
    }
    let mut eph_pk = [0u8; X25519_LEN];
    eph_pk.copy_from_slice(&wrap[..X25519_LEN]);
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    nonce.copy_from_slice(&wrap[X25519_LEN..X25519_LEN + WRAP_NONCE_LEN]);
    let ct = &wrap[X25519_LEN + WRAP_NONCE_LEN..];

    let sk = StaticSecret::from(*recipient_x_sk);
    let eph = X25519Public::from(eph_pk);
    let shared = sk.diffie_hellman(&eph);
    let mut shared_bytes = Secret32::from_array(*shared.as_bytes());
    let recipient_pk = X25519Public::from(&sk).to_bytes();
    let mut key = Secret32::from_array(derive_wrap_key(
        shared_bytes.as_array(),
        &eph_pk,
        &recipient_pk,
    ));
    shared_bytes.zeroize();

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_array())
        .map_err(|e| AdminSealError::new(format!("wrap cipher: {e}")))?;
    key.zeroize();
    let plain = cipher
        .decrypt(XNonce::from_slice(&nonce), ct)
        .map_err(|_| AdminSealError::new("wrap decrypt failed"))?;
    <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| AdminSealError::new("wrap key length"))
}

/// XChaCha nonce is `nonce_16 || 8 zero bytes`. AAD is the public seal domain + nonce.
fn payload_nonce(nonce16: &[u8; SEAL_NONCE_LEN]) -> [u8; WRAP_NONCE_LEN] {
    let mut n = [0u8; WRAP_NONCE_LEN];
    n[..SEAL_NONCE_LEN].copy_from_slice(nonce16);
    n
}

fn payload_aad(nonce16: &[u8; SEAL_NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ADMIN_SEAL_DOMAIN.len() + SEAL_NONCE_LEN);
    aad.extend_from_slice(ADMIN_SEAL_DOMAIN);
    aad.extend_from_slice(nonce16);
    aad
}

/// Seal AdminEnvelope JSON to the target device Ed25519 public key (`did`).
pub fn seal_admin_envelope(
    device_ed25519_pk: &[u8; 32],
    envelope_json: &[u8],
) -> Result<AdminSealPayload, AdminSealError> {
    if envelope_json.is_empty() {
        return Err(AdminSealError::new("empty envelope"));
    }
    if envelope_json.len() > ADMIN_MAILBOX_MAX_BYTES {
        return Err(AdminSealError::new("envelope too large"));
    }
    let x_pk =
        ed25519_pk_to_x25519(device_ed25519_pk).map_err(|e| AdminSealError::new(e.to_string()))?;
    let mut pack_key = Secret32::random();
    let wrap = wrap_pack_key(&x_pk, pack_key.as_array())?;

    let mut nonce16 = [0u8; SEAL_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce16);
    let aad = payload_aad(&nonce16);
    let xn = payload_nonce(&nonce16);
    let cipher = XChaCha20Poly1305::new_from_slice(pack_key.as_array())
        .map_err(|e| AdminSealError::new(format!("payload cipher: {e}")))?;
    pack_key.zeroize();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&xn),
            Payload {
                msg: envelope_json,
                aad: &aad,
            },
        )
        .map_err(|_| AdminSealError::new("payload encrypt failed"))?;

    Ok(AdminSealPayload {
        wrap: B64.encode(&wrap),
        nonce: mymesh_core::wire::encode_base64url(&nonce16),
        ciphertext: B64.encode(&ct),
    })
}

/// Open a sealed mailbox blob with the device Ed25519 seed.
pub fn open_admin_envelope(
    device_ed25519_seed: &[u8; 32],
    payload: &AdminSealPayload,
) -> Result<Vec<u8>, AdminSealError> {
    let wrap = B64
        .decode(payload.wrap.trim())
        .map_err(|e| AdminSealError::new(format!("wrap b64: {e}")))?;
    let ct = B64
        .decode(payload.ciphertext.trim())
        .map_err(|e| AdminSealError::new(format!("ciphertext b64: {e}")))?;
    let nonce16 = decode_nonce16(&payload.nonce)?;
    let x_sk = ed25519_seed_to_x25519(device_ed25519_seed);
    let mut pack_key = Secret32::from_array(unwrap_pack_key(&x_sk, &wrap)?);
    let aad = payload_aad(&nonce16);
    let xn = payload_nonce(&nonce16);
    let cipher = XChaCha20Poly1305::new_from_slice(pack_key.as_array())
        .map_err(|e| AdminSealError::new(format!("payload cipher: {e}")))?;
    pack_key.zeroize();
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&xn),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| AdminSealError::new("payload decrypt failed"))?;
    if plain.len() > ADMIN_MAILBOX_MAX_BYTES {
        return Err(AdminSealError::new("plaintext too large"));
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use mymesh_core::wire::parse_admin_seal_payload;

    #[test]
    fn seal_roundtrip_and_wrong_device() {
        let host = Identity::from_secret_bytes([0x11u8; 32]);
        let other = Identity::from_secret_bytes([0x22u8; 32]);
        let json = br#"{"v":1,"op":"introduce"}"#;
        let sealed = seal_admin_envelope(&host.verifying_key_bytes(), json).unwrap();
        let opened = open_admin_envelope(&host.to_secret_bytes(), &sealed).unwrap();
        assert_eq!(opened, json);
        assert!(open_admin_envelope(&other.to_secret_bytes(), &sealed).is_err());
        let wire = serde_json::to_vec(&sealed).unwrap();
        parse_admin_seal_payload(&wire).unwrap();
    }

    #[test]
    fn raw_envelope_is_not_a_seal() {
        let raw = br#"{"v":1,"op":"introduce","target_device_id_hex":"aa","ts":"t","nonce":"n","person_id":"p","facet":"personal","payload_json":"{}","sig_hex":"00"}"#;
        let err = parse_admin_seal_payload(raw).unwrap_err();
        assert!(err.message.contains("seal required"));
    }
}
