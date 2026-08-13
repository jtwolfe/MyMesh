//! AdminEnvelope, HintBlob, mailbox bind, seal preimage, `person_enrolled`.

use super::{decode_nonce16, parse_id32_hex, parse_rfc3339_unix, write_u16le_bytes};
use crate::wire::enroll::PersonFacet;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical AdminEnvelope domain.
pub const ADMIN_ENVELOPE_DOMAIN: &[u8] = b"carrier-admin-v1";
/// Envelope format version.
pub const ADMIN_ENVELOPE_VERSION: u32 = 1;
/// Max envelope size (JSON bytes).
pub const ADMIN_ENVELOPE_MAX_BYTES: usize = 64 * 1024;
/// Max opaque mailbox PUT (sealed blob). Same budget as the envelope.
pub const ADMIN_MAILBOX_MAX_BYTES: usize = ADMIN_ENVELOPE_MAX_BYTES;
/// Mailbox bind / message TTL (no disk log of bodies).
pub const ADMIN_MAILBOX_TTL_SECS: u64 = 15 * 60;
/// Inbox/outbox long-poll (serve poller).
pub const ADMIN_MAILBOX_POLL_MS: u64 = 25_000;
/// Bind `ts` skew (±5 min), same as enroll / AdminEnvelope.
pub const ADMIN_BIND_SKEW_SECS: i64 = 5 * 60;
/// HKDF info / AAD prefix for HintBlob.
pub const ADMIN_HINT_INFO: &[u8] = b"carrier-admin-hint-v1";
/// HintBlob format version.
pub const HINT_BLOB_VERSION: u32 = 1;
/// Mailbox device-bind domain.
pub const MAILBOX_BIND_DOMAIN: &[u8] = b"carrier-mailbox-bind-v1";
/// Seal preimage domain.
pub const ADMIN_SEAL_DOMAIN: &[u8] = b"carrier-admin-seal-v1";
/// Standing-session method string (device-scoped).
pub const PERSON_ENROLLED_METHOD: &str = "person_enrolled";
/// Mesh auth domain (same as B3/B4).
pub const MESH_AUTH_DOMAIN: &[u8] = b"mymesh-mesh-auth-v1";

const HINT_KEY_LEN: usize = 32;
const HINT_NONCE_LEN: usize = 24;

/// Fail-closed envelope ops. Unknown `op` → parse error / `bad_request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOp {
    EnrollAck,
    CreateMesh,
    OverlapGuest,
    Introduce,
    OwnerClaimFwd,
    MembershipsSelf,
    EnrollRevokeSelf,
}

impl AdminOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnrollAck => "enroll_ack",
            Self::CreateMesh => "create_mesh",
            Self::OverlapGuest => "overlap_guest",
            Self::Introduce => "introduce",
            Self::OwnerClaimFwd => "owner_claim_fwd",
            Self::MembershipsSelf => "memberships_self",
            Self::EnrollRevokeSelf => "enroll_revoke_self",
        }
    }
}

/// `op=introduce` payload. Last-mile dest is always the joiner (KD-F20).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroducePayload {
    pub resident_did: String,
    pub joiner_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident_fp: Option<String>,
}

/// Person-signed admin RPC (Wave F1 wire freeze).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEnvelope {
    pub v: u32,
    pub op: AdminOp,
    pub target_device_id_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_id: Option<String>,
    /// RFC3339.
    pub ts: String,
    /// 16B base64url.
    pub nonce: String,
    pub person_id: String,
    pub facet: PersonFacet,
    /// Raw JSON object text; hashed as UTF-8 (not re-serialized).
    pub payload_json: String,
    pub sig_hex: String,
}

/// Parse envelope JSON. Unknown `op` / schema → `bad_request`.
pub fn parse_admin_envelope_json(s: &str) -> Result<AdminEnvelope, AdminWireError> {
    if s.len() > ADMIN_ENVELOPE_MAX_BYTES {
        return Err(AdminWireError::bad_request("admin envelope too large"));
    }
    let env: AdminEnvelope = serde_json::from_str(s.trim())
        .map_err(|e| AdminWireError::bad_request(format!("admin envelope: {e}")))?;
    if env.v != ADMIN_ENVELOPE_VERSION {
        return Err(AdminWireError::bad_request(format!(
            "unsupported admin envelope v={}",
            env.v
        )));
    }
    Ok(env)
}

impl AdminEnvelope {
    /// `carrier-admin-v1` preimage using this envelope's fields.
    pub fn preimage(&self, person_pk: &[u8; 32]) -> Result<Vec<u8>, AdminWireError> {
        let target = parse_id32_hex(&self.target_device_id_hex)?;
        let nonce = decode_nonce16(&self.nonce)?;
        let ts = parse_rfc3339_unix(&self.ts)?;
        admin_envelope_preimage(
            self.op,
            &target,
            self.mesh_id.as_deref().unwrap_or(""),
            ts,
            &nonce,
            person_pk,
            self.payload_json.as_bytes(),
        )
    }
}

/// Canonical AdminEnvelope preimage:
///
/// ```text
/// carrier-admin-v1 || u16le(len) || op_utf8
///   || target_did_32
///   || u16le(len) || mesh_id_utf8_or_empty
///   || i64le(ts_unix)
///   || nonce_16
///   || person_pk_32
///   || sha256(payload_json_bytes)
/// ```
pub fn admin_envelope_preimage(
    op: AdminOp,
    target_did: &[u8; 32],
    mesh_id: &str,
    ts_unix: i64,
    nonce: &[u8; 16],
    person_pk: &[u8; 32],
    payload_json: &[u8],
) -> Result<Vec<u8>, AdminWireError> {
    let payload_hash = Sha256::digest(payload_json);
    let mut out = Vec::with_capacity(
        ADMIN_ENVELOPE_DOMAIN.len()
            + 2
            + op.as_str().len()
            + 32
            + 2
            + mesh_id.len()
            + 8
            + 16
            + 32
            + 32,
    );
    out.extend_from_slice(ADMIN_ENVELOPE_DOMAIN);
    write_u16le_bytes(&mut out, op.as_str().as_bytes())?;
    out.extend_from_slice(target_did);
    write_u16le_bytes(&mut out, mesh_id.as_bytes())?;
    out.extend_from_slice(&ts_unix.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(person_pk);
    out.extend_from_slice(&payload_hash);
    Ok(out)
}

/// Private last-mile wrap of a host URL.
///
/// Never log or render `plaintext`. JSON: `{ v, nonce_b64, ct_b64 }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HintBlob {
    pub v: u32,
    pub nonce_b64: String,
    pub ct_b64: String,
}

fn hint_key(facet_seed: &[u8; 32]) -> Result<[u8; HINT_KEY_LEN], AdminWireError> {
    let hk = Hkdf::<Sha256>::new(None, facet_seed);
    let mut key = [0u8; HINT_KEY_LEN];
    hk.expand(ADMIN_HINT_INFO, &mut key)
        .map_err(|_| AdminWireError::bad_request("hint HKDF expand"))?;
    Ok(key)
}

fn hint_aad(device_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ADMIN_HINT_INFO.len() + 32);
    aad.extend_from_slice(ADMIN_HINT_INFO);
    aad.extend_from_slice(device_id);
    aad
}

/// Wrap `plaintext_url` with HKDF-SHA256 + XChaCha20-Poly1305.
///
/// `nonce` of 24 bytes is required so goldens are deterministic; callers
/// supply random bytes in production.
pub fn wrap_hint_blob(
    facet_seed: &[u8; 32],
    device_id: &[u8; 32],
    plaintext_url: &str,
    nonce: &[u8; HINT_NONCE_LEN],
) -> Result<HintBlob, AdminWireError> {
    let key = hint_key(facet_seed)?;
    let aad = hint_aad(device_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AdminWireError::bad_request(format!("hint cipher: {e}")))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext_url.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| AdminWireError::bad_request("hint encrypt failed"))?;
    Ok(HintBlob {
        v: HINT_BLOB_VERSION,
        nonce_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
        ct_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ct),
    })
}

/// Unwrap a HintBlob to the plaintext URL (never log).
pub fn unwrap_hint_blob(
    facet_seed: &[u8; 32],
    device_id: &[u8; 32],
    blob: &HintBlob,
) -> Result<String, AdminWireError> {
    if blob.v != HINT_BLOB_VERSION {
        return Err(AdminWireError::bad_request(format!(
            "unsupported hint blob v={}",
            blob.v
        )));
    }
    let nonce = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        blob.nonce_b64.trim(),
    )
    .map_err(|e| AdminWireError::bad_request(format!("hint nonce b64: {e}")))?;
    let ct = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        blob.ct_b64.trim(),
    )
    .map_err(|e| AdminWireError::bad_request(format!("hint ct b64: {e}")))?;
    if nonce.len() != HINT_NONCE_LEN {
        return Err(AdminWireError::bad_request("hint nonce must be 24 bytes"));
    }
    let key = hint_key(facet_seed)?;
    let aad = hint_aad(device_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| AdminWireError::bad_request(format!("hint cipher: {e}")))?;
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| AdminWireError::bad_request("hint decrypt failed"))?;
    String::from_utf8(plain).map_err(|_| AdminWireError::bad_request("hint plaintext not utf8"))
}

/// Device bind presented to a self-host mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxBind {
    /// Device id, 64 hex.
    pub did: String,
    /// Unix seconds.
    pub ts: i64,
    pub sig_hex: String,
}

/// `carrier-mailbox-bind-v1 || did_32 || i64le(ts)`.
pub fn mailbox_bind_preimage(did: &[u8; 32], ts: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAILBOX_BIND_DOMAIN.len() + 32 + 8);
    out.extend_from_slice(MAILBOX_BIND_DOMAIN);
    out.extend_from_slice(did);
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

impl MailboxBind {
    pub fn preimage(&self) -> Result<Vec<u8>, AdminWireError> {
        let did = parse_id32_hex(&self.did)?;
        Ok(mailbox_bind_preimage(&did, self.ts))
    }
}

/// Sealed mailbox / last-mile payload (`wrap` + AEAD of AdminEnvelope JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSealPayload {
    pub wrap: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Parse a mailbox inbox body. Raw `AdminEnvelope` JSON is rejected (seal required).
pub fn parse_admin_seal_payload(bytes: &[u8]) -> Result<AdminSealPayload, AdminWireError> {
    if bytes.len() > ADMIN_MAILBOX_MAX_BYTES {
        return Err(AdminWireError::bad_request("admin mailbox blob too large"));
    }
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| AdminWireError::bad_request("seal required"))?;
    if v.get("wrap").and_then(|x| x.as_str()).is_none()
        || v.get("nonce").and_then(|x| x.as_str()).is_none()
        || v.get("ciphertext").and_then(|x| x.as_str()).is_none()
    {
        return Err(AdminWireError::bad_request("seal required"));
    }
    serde_json::from_value(v).map_err(|_| AdminWireError::bad_request("seal required"))
}

/// `mailbox_id = sha256(url)[0..16]` hex. Never store the URL on a device row.
pub fn mailbox_id_from_url(url: &str) -> String {
    let digest = Sha256::digest(url.trim().as_bytes());
    hex::encode(&digest[..16])
}

/// `carrier-admin-seal-v1 || nonce_16 || sha256(envelope_canonical_bytes)`.
pub fn admin_seal_preimage(nonce: &[u8; 16], envelope_canonical_bytes: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(envelope_canonical_bytes);
    let mut out = Vec::with_capacity(ADMIN_SEAL_DOMAIN.len() + 16 + 32);
    out.extend_from_slice(ADMIN_SEAL_DOMAIN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&hash);
    out
}

/// `person_enrolled` challenge preimage (device-scoped, not mesh-scoped):
///
/// ```text
/// mymesh-mesh-auth-v1 || 0x00 || challenge_id_utf8
///   || 0x00 || nonce_32
///   || 0x00 || device_id_32
///   || 0x00 || "person_enrolled"
/// ```
pub fn person_enrolled_auth_preimage(
    challenge_id: &str,
    nonce: &[u8; 32],
    device_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        MESH_AUTH_DOMAIN.len()
            + 1
            + challenge_id.len()
            + 1
            + 32
            + 1
            + 32
            + 1
            + PERSON_ENROLLED_METHOD.len(),
    );
    out.extend_from_slice(MESH_AUTH_DOMAIN);
    out.push(0);
    out.extend_from_slice(challenge_id.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce);
    out.push(0);
    out.extend_from_slice(device_id);
    out.push(0);
    out.extend_from_slice(PERSON_ENROLLED_METHOD.as_bytes());
    out
}

/// Wire parse / preimage error. `code` is always `bad_request` (fail closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminWireError {
    pub code: &'static str,
    pub message: String,
}

impl AdminWireError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: "bad_request",
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AdminWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AdminWireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_op_fail_closed() {
        let json = r#"{
            "v":1,
            "op":"topology",
            "target_device_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ts":"2026-08-13T12:00:00Z",
            "nonce":"MzMzMzMzMzMzMzMzMzMzMw",
            "person_id":"p",
            "facet":"personal",
            "payload_json":"{}",
            "sig_hex":"00"
        }"#;
        let err = parse_admin_envelope_json(json).expect_err("unknown op");
        assert_eq!(err.code, "bad_request");
    }

    #[test]
    fn known_op_parses() {
        let json = r#"{
            "v":1,
            "op":"introduce",
            "target_device_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ts":"2026-08-13T12:00:00Z",
            "nonce":"MzMzMzMzMzMzMzMzMzMzMw",
            "person_id":"p",
            "facet":"work",
            "payload_json":"{}",
            "sig_hex":"00"
        }"#;
        let env = parse_admin_envelope_json(json).unwrap();
        assert_eq!(env.op, AdminOp::Introduce);
        assert_eq!(env.facet, PersonFacet::Work);
    }

    #[test]
    fn person_enrolled_uses_device_id_not_mesh_string() {
        let n = [0x44u8; 32];
        let did = [0xa1u8; 32];
        let pre = person_enrolled_auth_preimage("cid", &n, &did);
        assert!(pre.starts_with(MESH_AUTH_DOMAIN));
        assert!(pre.ends_with(PERSON_ENROLLED_METHOD.as_bytes()));
        // device id bytes appear raw (0xa1…), not as hex ASCII.
        assert!(pre.windows(32).any(|w| w == did));
        assert!(!pre.windows(2).any(|w| w == b"a1"));
    }

    #[test]
    fn hint_wrap_roundtrip() {
        let seed = [0x42u8; 32];
        let did = [0xa1u8; 32];
        let nonce = [0x55u8; 24];
        let url = "http://192.168.1.10:17878";
        let blob = wrap_hint_blob(&seed, &did, url, &nonce).unwrap();
        assert_eq!(blob.v, 1);
        assert_eq!(unwrap_hint_blob(&seed, &did, &blob).unwrap(), url);
        let other = [0x00u8; 32];
        assert!(unwrap_hint_blob(&other, &did, &blob).is_err());
    }

    #[test]
    fn mailbox_bind_layout() {
        let did = [0xa1u8; 32];
        let pre = mailbox_bind_preimage(&did, 1_786_622_400);
        assert!(pre.starts_with(MAILBOX_BIND_DOMAIN));
        assert_eq!(
            &pre[MAILBOX_BIND_DOMAIN.len()..MAILBOX_BIND_DOMAIN.len() + 32],
            &did
        );
    }

    #[test]
    fn parse_seal_rejects_raw_envelope() {
        let json = br#"{"v":1,"op":"introduce","target_device_id_hex":"aa","ts":"t","nonce":"n","person_id":"p","facet":"personal","payload_json":"{}","sig_hex":"00"}"#;
        let err = parse_admin_seal_payload(json).expect_err("seal required");
        assert_eq!(err.code, "bad_request");
        assert!(err.message.contains("seal required"));
    }

    #[test]
    fn mailbox_id_is_truncated_sha256_hex() {
        let id = mailbox_id_from_url("https://mailbox.example");
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, mailbox_id_from_url("https://other.example"));
    }
}
