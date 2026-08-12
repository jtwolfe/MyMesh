//! Continuity pack v1 — seal / open + host-pubkey wrap (S8).
//!
//! Compatible with Carrier E3 sealed pack layout ([docs/CONTINUITY.md] on carrier).
//!
//! ```text
//! pack_key ← random 32B
//! ciphertext = XChaCha20-Poly1305(pack_key, fields_json)   // nonce || ct (b64)
//! wrap = seal pack_key to host Ed25519 pk via X25519 sealed box
//! wipe_token_hash = hex(SHA-256(domain || wipe_token))
//! ```
//!
//! **Never log `pack_key` or wipe tokens.** Only the host device private key unwraps.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Continuity pack format version.
pub const CONTINUITY_PACK_VERSION: u32 = 1;

/// AEAD for pack field ciphertext (whole `fields` JSON as one AEAD).
pub const CONTINUITY_PAYLOAD_ALG: &str = "xchacha20poly1305";

/// Host-pubkey wrap of `pack_key` (X25519 sealed box + XChaCha20-Poly1305).
pub const CONTINUITY_WRAP_ALG: &str = "x25519-xchacha20poly1305-seal-v1";

/// Domain separation for wrap-key derivation (KDF info).
pub const CONTINUITY_WRAP_DOMAIN: &[u8] = b"carrier-continuity-wrap-v1";

/// Domain separation for wipe-token hash (SHA-256).
pub const CONTINUITY_WIPE_DOMAIN: &[u8] = b"carrier-continuity-wipe-v1";

/// Max ciphertext size v1 (1 MiB).
pub const CONTINUITY_MAX_CIPHERTEXT_BYTES: usize = 1_048_576;

/// Max wrap blob after base64 decode.
const CONTINUITY_MAX_WRAP_BYTES: usize = 256;

/// `pack_key` length.
pub const CONTINUITY_PACK_KEY_LEN: usize = 32;

/// Wipe token length (random; phone holds until leave).
pub const CONTINUITY_WIPE_TOKEN_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length.
pub const CONTINUITY_NONCE_LEN: usize = 24;

/// X25519 public key length (ephemeral in wrap).
pub const CONTINUITY_X25519_PK_LEN: usize = 32;

// ── Secret buffers ──────────────────────────────────────────────────────────

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secret32([u8; 32]);

impl Secret32 {
    fn zeroed() -> Self {
        Self([0u8; 32])
    }

    fn random() -> Self {
        let mut s = Self::zeroed();
        OsRng.fill_bytes(&mut s.0);
        s
    }

    fn from_array(a: [u8; 32]) -> Self {
        Self(a)
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    fn as_mut_array(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Continuity seal / open errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityError {
    /// Crypto / AEAD failure (wrong key, corrupt blob).
    Crypto(String),
    /// Schema / length / version.
    BadInput(String),
    /// Ciphertext exceeds v1 budget (1 MiB).
    TooLarge { bytes: usize, max: usize },
}

impl fmt::Display for ContinuityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContinuityError::Crypto(m) => write!(f, "continuity crypto: {m}"),
            ContinuityError::BadInput(m) => write!(f, "continuity bad input: {m}"),
            ContinuityError::TooLarge { bytes, max } => {
                write!(f, "continuity ciphertext {bytes} exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for ContinuityError {}

// ── Wire types (match carrier wire/continuity.rs) ───────────────────────────

/// Manifest describing the encrypted home subset (not secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityManifest {
    /// User-visible label (e.g. "hotel bag").
    pub label: String,
    /// RFC3339 creation time (phone clock).
    pub created_at: String,
    /// Person id that sealed the pack.
    pub person_id: String,
    /// Optional facet id (S7 multi-id bind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet_id: Option<String>,
    /// Non-secret field names present in plaintext JSON.
    #[serde(default)]
    pub fields_summary: Vec<String>,
    /// Ciphertext byte length (budget accounting).
    pub byte_length: u64,
}

/// On-disk / materialize body: encrypted pack + host wrap (S8).
///
/// `wrap` and `ciphertext` are standard-base64 opaque blobs (nonce embedded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityPack {
    /// ULID pack id.
    pub pack_id: String,
    /// Always [`CONTINUITY_PACK_VERSION`] in v1.
    pub version: u32,
    /// Standard-base64 sealed `pack_key` (see seal layout).
    pub wrap: String,
    /// Standard-base64 XChaCha20-Poly1305 of fields JSON (`nonce || ct`).
    pub ciphertext: String,
    pub manifest: ContinuityManifest,
    /// Hex SHA-256 over domain-separated wipe token (not the token itself).
    pub wipe_token_hash: String,
    /// Host device id (64 hex) the wrap targets.
    pub host_device_id_hex: String,
}

/// Pack presence on host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityStatus {
    Present,
    Wiped,
    Absent,
}

impl ContinuityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Wiped => "wiped",
            Self::Absent => "absent",
        }
    }
}

// ── Ed25519 ↔ X25519 ────────────────────────────────────────────────────────

/// Convert Ed25519 verifying key bytes to X25519 (Montgomery) public key.
pub fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> Result<[u8; 32], ContinuityError> {
    let compressed = CompressedEdwardsY(*ed_pk);
    let point = compressed
        .decompress()
        .ok_or_else(|| ContinuityError::BadInput("invalid ed25519 public key".into()))?;
    Ok(point.to_montgomery().to_bytes())
}

/// Convert Ed25519 seed (32B) to X25519 scalar bytes (SHA-512 + clamp).
///
/// Matches libsodium `crypto_sign_ed25519_sk_to_curve25519` for the seed form.
pub fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn parse_ed25519_pk_hex(hex_str: &str) -> Result<[u8; 32], ContinuityError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| ContinuityError::BadInput("host pubkey: bad hex".into()))?;
    if bytes.len() != 32 {
        return Err(ContinuityError::BadInput(format!(
            "host pubkey must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    ed25519_pk_to_x25519(&a)?;
    Ok(a)
}

fn parse_device_id_hex(s: &str) -> Result<String, ContinuityError> {
    let t = s.trim().to_ascii_lowercase();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ContinuityError::BadInput(
            "host_device_id_hex must be 64 hex chars".into(),
        ));
    }
    Ok(t)
}

// ── Wrap KDF ────────────────────────────────────────────────────────────────

fn derive_wrap_aead_key(
    shared: &[u8; 32],
    eph_pk: &[u8; 32],
    recipient_x25519_pk: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTINUITY_WRAP_DOMAIN);
    h.update([0u8]);
    h.update(shared);
    h.update(eph_pk);
    h.update(recipient_x25519_pk);
    let dig = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&dig);
    key
}

/// Sealed-box binary: `eph_x25519_pk (32) || nonce (24) || aead_ct`.
fn seal_to_host_x25519(
    recipient_x25519_pk: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, ContinuityError> {
    let mut eph_seed = Secret32::random();
    let eph_secret = StaticSecret::from(*eph_seed.as_array());
    eph_seed.zeroize();
    let eph_public = X25519Public::from(&eph_secret);
    let eph_pk_bytes = eph_public.to_bytes();

    let recipient = X25519Public::from(*recipient_x25519_pk);
    let shared = eph_secret.diffie_hellman(&recipient);
    let mut shared_bytes = Secret32::from_array(*shared.as_bytes());
    let mut key = Secret32::from_array(derive_wrap_aead_key(
        shared_bytes.as_array(),
        &eph_pk_bytes,
        recipient_x25519_pk,
    ));
    shared_bytes.zeroize();

    let mut nonce = [0u8; CONTINUITY_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_array())
        .map_err(|e| ContinuityError::Crypto(format!("wrap cipher: {e}")))?;
    key.zeroize();

    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| ContinuityError::Crypto("wrap encrypt failed".into()))?;

    let mut out = Vec::with_capacity(CONTINUITY_X25519_PK_LEN + CONTINUITY_NONCE_LEN + ct.len());
    out.extend_from_slice(&eph_pk_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_from_host_x25519(
    recipient_x25519_sk: &[u8; 32],
    wrap: &[u8],
) -> Result<Vec<u8>, ContinuityError> {
    let min = CONTINUITY_X25519_PK_LEN + CONTINUITY_NONCE_LEN + 16;
    if wrap.len() < min {
        return Err(ContinuityError::Crypto("wrap blob too short".into()));
    }
    if wrap.len() > CONTINUITY_MAX_WRAP_BYTES {
        return Err(ContinuityError::Crypto(format!(
            "wrap blob too large ({} > {CONTINUITY_MAX_WRAP_BYTES})",
            wrap.len()
        )));
    }
    let mut eph_pk = [0u8; CONTINUITY_X25519_PK_LEN];
    eph_pk.copy_from_slice(&wrap[..CONTINUITY_X25519_PK_LEN]);
    let mut nonce = [0u8; CONTINUITY_NONCE_LEN];
    nonce.copy_from_slice(
        &wrap[CONTINUITY_X25519_PK_LEN..CONTINUITY_X25519_PK_LEN + CONTINUITY_NONCE_LEN],
    );
    let ct = &wrap[CONTINUITY_X25519_PK_LEN + CONTINUITY_NONCE_LEN..];

    let sk = StaticSecret::from(*recipient_x25519_sk);
    let eph = X25519Public::from(eph_pk);
    let shared = sk.diffie_hellman(&eph);
    let mut shared_bytes = Secret32::from_array(*shared.as_bytes());

    let recipient_pk = X25519Public::from(&sk).to_bytes();
    let mut key = Secret32::from_array(derive_wrap_aead_key(
        shared_bytes.as_array(),
        &eph_pk,
        &recipient_pk,
    ));
    shared_bytes.zeroize();

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_array())
        .map_err(|e| ContinuityError::Crypto(format!("wrap cipher: {e}")))?;
    key.zeroize();

    cipher
        .decrypt(XNonce::from_slice(&nonce), ct)
        .map_err(|_| {
            ContinuityError::Crypto("wrap decrypt failed (wrong host key or corrupt)".into())
        })
}

// ── Payload AEAD ────────────────────────────────────────────────────────────

fn encrypt_payload(
    pack_key: &[u8; CONTINUITY_PACK_KEY_LEN],
    plain: &[u8],
) -> Result<Vec<u8>, ContinuityError> {
    let mut nonce = [0u8; CONTINUITY_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(pack_key)
        .map_err(|e| ContinuityError::Crypto(format!("payload cipher: {e}")))?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| ContinuityError::Crypto("payload encrypt failed".into()))?;
    let mut out = Vec::with_capacity(CONTINUITY_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_payload(
    pack_key: &[u8; CONTINUITY_PACK_KEY_LEN],
    blob: &[u8],
) -> Result<Vec<u8>, ContinuityError> {
    if blob.len() < CONTINUITY_NONCE_LEN + 16 {
        return Err(ContinuityError::Crypto("ciphertext too short".into()));
    }
    let nonce = &blob[..CONTINUITY_NONCE_LEN];
    let ct = &blob[CONTINUITY_NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new_from_slice(pack_key)
        .map_err(|e| ContinuityError::Crypto(format!("payload cipher: {e}")))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| ContinuityError::Crypto("payload decrypt failed".into()))
}

// ── Wipe token ──────────────────────────────────────────────────────────────

/// Domain-separated SHA-256 hex of wipe token (stored on pack / host).
pub fn wipe_token_hash(wipe_token: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(CONTINUITY_WIPE_DOMAIN);
    h.update([0u8]);
    h.update(wipe_token);
    hex::encode(h.finalize())
}

/// Constant-time-ish verify of wipe token against pack hash.
pub fn verify_wipe_token(
    wipe_token_hash_hex: &str,
    wipe_token_hex: &str,
) -> Result<(), ContinuityError> {
    let token = hex::decode(wipe_token_hex.trim())
        .map_err(|_| ContinuityError::BadInput("wipe_token: bad hex".into()))?;
    if token.len() != CONTINUITY_WIPE_TOKEN_LEN {
        return Err(ContinuityError::BadInput(format!(
            "wipe_token must be {CONTINUITY_WIPE_TOKEN_LEN} bytes"
        )));
    }
    let expect = wipe_token_hash(&token);
    if !hex_eq_fold(&expect, wipe_token_hash_hex.trim()) {
        return Err(ContinuityError::Crypto("wipe token mismatch".into()));
    }
    Ok(())
}

/// Verify wipe token against a pack envelope.
pub fn verify_wipe_token_for_pack(
    pack: &ContinuityPack,
    wipe_token_hex: &str,
) -> Result<(), ContinuityError> {
    verify_wipe_token(&pack.wipe_token_hash, wipe_token_hex)
}

fn hex_eq_fold(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| {
            acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())
        })
        == 0
}

// ── Public seal / open API ──────────────────────────────────────────────────

/// Inputs for sealing a continuity pack (phone / tests).
pub struct SealContinuityInput<'a> {
    /// Host device Ed25519 verifying key (32B hex).
    pub host_device_public_key_hex: &'a str,
    /// Host device id (64 hex) recorded on the pack.
    pub host_device_id_hex: &'a str,
    /// Person id sealing the pack.
    pub person_id: &'a str,
    /// Optional facet id (S7).
    pub facet_id: Option<&'a str>,
    /// User label.
    pub label: &'a str,
    /// Application-defined fields JSON (encrypted as one AEAD).
    pub fields_json: &'a str,
    /// Non-secret field names for manifest summary.
    pub fields_summary: Vec<String>,
    /// Optional fixed pack_id (tests); random ULID-like when None.
    pub pack_id: Option<&'a str>,
}

/// Sealed pack plus phone-only wipe token (never send token in materialize body).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealedContinuity {
    /// Materialize body (no secrets in the clear).
    #[zeroize(skip)]
    pub pack: ContinuityPack,
    /// 32-byte wipe token (phone holds until leave).
    pub wipe_token: [u8; CONTINUITY_WIPE_TOKEN_LEN],
}

impl SealedContinuity {
    /// Hex encoding of wipe token for `POST .../wipe`.
    pub fn wipe_token_hex(&self) -> String {
        hex::encode(self.wipe_token)
    }
}

impl fmt::Debug for SealedContinuity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedContinuity")
            .field("pack_id", &self.pack.pack_id)
            .field("host_device_id_hex", &self.pack.host_device_id_hex)
            .field("wipe_token", &"<redacted>")
            .finish()
    }
}

/// Seal fields under a fresh `pack_key`, wrap to host pubkey, mint wipe token.
pub fn seal_continuity_pack(
    input: SealContinuityInput<'_>,
) -> Result<SealedContinuity, ContinuityError> {
    if input.fields_json.is_empty() {
        return Err(ContinuityError::BadInput(
            "fields_json must not be empty".into(),
        ));
    }
    if input.fields_json.len() > CONTINUITY_MAX_CIPHERTEXT_BYTES {
        return Err(ContinuityError::TooLarge {
            bytes: input.fields_json.len(),
            max: CONTINUITY_MAX_CIPHERTEXT_BYTES,
        });
    }
    if input.person_id.trim().is_empty() {
        return Err(ContinuityError::BadInput("person_id required".into()));
    }
    if input.label.len() > 256 {
        return Err(ContinuityError::BadInput("label too long".into()));
    }

    let host_id = parse_device_id_hex(input.host_device_id_hex)?;
    let ed_pk = parse_ed25519_pk_hex(input.host_device_public_key_hex)?;
    let x_pk = ed25519_pk_to_x25519(&ed_pk)?;

    let mut pack_key = Secret32::random();

    let cipher_blob = encrypt_payload(pack_key.as_array(), input.fields_json.as_bytes())?;
    if cipher_blob.len() > CONTINUITY_MAX_CIPHERTEXT_BYTES {
        return Err(ContinuityError::TooLarge {
            bytes: cipher_blob.len(),
            max: CONTINUITY_MAX_CIPHERTEXT_BYTES,
        });
    }

    let wrap_blob = seal_to_host_x25519(&x_pk, pack_key.as_array())?;
    pack_key.zeroize();

    let mut wipe_token = [0u8; CONTINUITY_WIPE_TOKEN_LEN];
    OsRng.fill_bytes(&mut wipe_token);
    let wipe_hash = wipe_token_hash(&wipe_token);

    let pack_id = input
        .pack_id
        .map(|s| s.to_string())
        .unwrap_or_else(new_pack_id);
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let pack = ContinuityPack {
        pack_id,
        version: CONTINUITY_PACK_VERSION,
        wrap: B64.encode(&wrap_blob),
        ciphertext: B64.encode(&cipher_blob),
        manifest: ContinuityManifest {
            label: input.label.to_string(),
            created_at,
            person_id: input.person_id.to_string(),
            facet_id: input.facet_id.map(|s| s.to_string()),
            fields_summary: input.fields_summary,
            byte_length: cipher_blob.len() as u64,
        },
        wipe_token_hash: wipe_hash,
        host_device_id_hex: host_id,
    };

    Ok(SealedContinuity { pack, wipe_token })
}

/// Open pack with host device Ed25519 seed (32B). Returns fields JSON bytes.
pub fn open_continuity_pack(
    host_ed25519_seed: &[u8],
    pack: &ContinuityPack,
) -> Result<Vec<u8>, ContinuityError> {
    if pack.version != CONTINUITY_PACK_VERSION {
        return Err(ContinuityError::BadInput(format!(
            "unsupported continuity pack version {}",
            pack.version
        )));
    }
    if host_ed25519_seed.len() != 32 {
        return Err(ContinuityError::BadInput(format!(
            "host seed must be 32 bytes, got {}",
            host_ed25519_seed.len()
        )));
    }
    let mut seed = Secret32::zeroed();
    seed.as_mut_array().copy_from_slice(host_ed25519_seed);

    let wrap = B64
        .decode(pack.wrap.trim())
        .map_err(|e| ContinuityError::Crypto(format!("wrap b64: {e}")))?;
    let cipher_blob = B64
        .decode(pack.ciphertext.trim())
        .map_err(|e| ContinuityError::Crypto(format!("ciphertext b64: {e}")))?;

    if cipher_blob.len() > CONTINUITY_MAX_CIPHERTEXT_BYTES {
        return Err(ContinuityError::TooLarge {
            bytes: cipher_blob.len(),
            max: CONTINUITY_MAX_CIPHERTEXT_BYTES,
        });
    }
    if pack.manifest.byte_length as usize != cipher_blob.len() {
        return Err(ContinuityError::BadInput(
            "manifest.byte_length does not match ciphertext".into(),
        ));
    }

    let mut x_sk = Secret32::from_array(ed25519_seed_to_x25519(seed.as_array()));
    seed.zeroize();

    let mut pack_key_bytes = open_from_host_x25519(x_sk.as_array(), &wrap)?;
    x_sk.zeroize();

    if pack_key_bytes.len() != CONTINUITY_PACK_KEY_LEN {
        pack_key_bytes.zeroize();
        return Err(ContinuityError::Crypto(
            "unwrapped pack_key wrong length".into(),
        ));
    }
    let mut pack_key = Secret32::zeroed();
    pack_key.as_mut_array().copy_from_slice(&pack_key_bytes);
    pack_key_bytes.zeroize();

    let plain = decrypt_payload(pack_key.as_array(), &cipher_blob);
    pack_key.zeroize();
    plain
}

/// Open pack after checking `host_device_id_hex` matches the pack envelope.
pub fn open_continuity_pack_for_device(
    host_ed25519_seed: &[u8],
    host_device_id_hex: &str,
    pack: &ContinuityPack,
) -> Result<Vec<u8>, ContinuityError> {
    let expect_id = parse_device_id_hex(host_device_id_hex)?;
    if expect_id != pack.host_device_id_hex.to_ascii_lowercase() {
        return Err(ContinuityError::BadInput(
            "pack host_device_id_hex mismatch".into(),
        ));
    }
    open_continuity_pack(host_ed25519_seed, pack)
}

/// Parse continuity pack JSON (materialize body / disk).
pub fn parse_continuity_pack_json(json: &str) -> Result<ContinuityPack, ContinuityError> {
    serde_json::from_str(json.trim())
        .map_err(|e| ContinuityError::BadInput(format!("pack json: {e}")))
}

/// Validate pack_id for filesystem use (no path separators / traversal).
pub fn validate_pack_id(pack_id: &str) -> Result<(), ContinuityError> {
    let t = pack_id.trim();
    if t.is_empty() || t.len() > 64 {
        return Err(ContinuityError::BadInput(
            "pack_id must be 1..=64 chars".into(),
        ));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ContinuityError::BadInput(
            "pack_id has invalid characters".into(),
        ));
    }
    Ok(())
}

fn new_pack_id() -> String {
    // Time-sortable-ish ULID-like 26 Crockford chars (not full ULID lib).
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let mut entropy = [0u8; 10];
    OsRng.fill_bytes(&mut entropy);
    let mut bytes = [0u8; 16];
    bytes[0] = ((ms >> 40) & 0xff) as u8;
    bytes[1] = ((ms >> 32) & 0xff) as u8;
    bytes[2] = ((ms >> 24) & 0xff) as u8;
    bytes[3] = ((ms >> 16) & 0xff) as u8;
    bytes[4] = ((ms >> 8) & 0xff) as u8;
    bytes[5] = (ms & 0xff) as u8;
    bytes[6..].copy_from_slice(&entropy);
    let mut acc: u128 = 0;
    for b in bytes {
        acc = (acc << 8) | u128::from(b);
    }
    acc <<= 2;
    let mut chars = String::with_capacity(26);
    for i in (0..26).rev() {
        let shift = i * 5;
        let idx = ((acc >> shift) & 0x1f) as usize;
        chars.push(CROCKFORD[idx] as char);
    }
    chars
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn host_keypair() -> (SigningKey, String, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let device_id = hex::encode([0x11u8; 32]);
        (sk, pk_hex, device_id)
    }

    fn sample_fields() -> &'static str {
        r#"{"profile":{"name":"Ada"},"prefs":{"theme":"dark"}}"#
    }

    #[test]
    fn seal_open_roundtrip() {
        let (sk, pk_hex, device_id) = host_keypair();
        let sealed = seal_continuity_pack(SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &device_id,
            person_id: "01PERSONTEST",
            facet_id: Some("personal"),
            label: "hotel bag",
            fields_json: sample_fields(),
            fields_summary: vec!["profile".into(), "prefs".into()],
            pack_id: None,
        })
        .unwrap();

        assert_eq!(sealed.pack.version, CONTINUITY_PACK_VERSION);
        assert_eq!(sealed.pack.manifest.label, "hotel bag");
        assert_eq!(sealed.pack.manifest.facet_id.as_deref(), Some("personal"));
        assert_eq!(sealed.pack.host_device_id_hex, device_id);

        let plain = open_continuity_pack(sk.as_bytes(), &sealed.pack).unwrap();
        assert_eq!(plain, sample_fields().as_bytes());

        verify_wipe_token_for_pack(&sealed.pack, &sealed.wipe_token_hex()).unwrap();
        assert!(verify_wipe_token_for_pack(&sealed.pack, &"00".repeat(32)).is_err());
    }

    #[test]
    fn wrong_host_key_fails_closed() {
        let (_sk, pk_hex, device_id) = host_keypair();
        let sealed = seal_continuity_pack(SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &device_id,
            person_id: "01P",
            facet_id: None,
            label: "bag",
            fields_json: sample_fields(),
            fields_summary: vec![],
            pack_id: None,
        })
        .unwrap();

        let other = SigningKey::generate(&mut OsRng);
        let err = open_continuity_pack(other.as_bytes(), &sealed.pack).unwrap_err();
        assert!(matches!(err, ContinuityError::Crypto(_)));
    }

    #[test]
    fn size_budget_rejects_huge_plaintext() {
        let (_sk, pk_hex, device_id) = host_keypair();
        let huge = "x".repeat(CONTINUITY_MAX_CIPHERTEXT_BYTES + 1);
        let err = seal_continuity_pack(SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &device_id,
            person_id: "01P",
            facet_id: None,
            label: "bag",
            fields_json: &huge,
            fields_summary: vec![],
            pack_id: None,
        })
        .unwrap_err();
        assert!(matches!(err, ContinuityError::TooLarge { .. }));
    }

    #[test]
    fn ed25519_x25519_agrees_with_dalek_seed() {
        let sk = SigningKey::generate(&mut OsRng);
        let seed = sk.to_bytes();
        let x_sk = ed25519_seed_to_x25519(&seed);
        let x_pk_from_sk = X25519Public::from(&StaticSecret::from(x_sk)).to_bytes();
        let x_pk_from_ed = ed25519_pk_to_x25519(&sk.verifying_key().to_bytes()).unwrap();
        assert_eq!(x_pk_from_sk, x_pk_from_ed);
    }

    #[test]
    fn json_pack_roundtrip_no_pack_key() {
        let (sk, pk_hex, device_id) = host_keypair();
        let sealed = seal_continuity_pack(SealContinuityInput {
            host_device_public_key_hex: &pk_hex,
            host_device_id_hex: &device_id,
            person_id: "01JSON",
            facet_id: None,
            label: "json",
            fields_json: r#"{"a":1}"#,
            fields_summary: vec!["a".into()],
            pack_id: Some("01TESTPACK0000000000000000"),
        })
        .unwrap();
        let json = serde_json::to_string(&sealed.pack).unwrap();
        assert!(!json.contains("pack_key"));
        let parsed = parse_continuity_pack_json(&json).unwrap();
        let plain = open_continuity_pack(sk.as_bytes(), &parsed).unwrap();
        assert_eq!(plain, br#"{"a":1}"#);
    }

    #[test]
    fn status_serde_snake() {
        let j = serde_json::to_string(&ContinuityStatus::Present).unwrap();
        assert_eq!(j, "\"present\"");
        let s: ContinuityStatus = serde_json::from_str("\"wiped\"").unwrap();
        assert_eq!(s, ContinuityStatus::Wiped);
    }

    #[test]
    fn validate_pack_id_rejects_traversal() {
        assert!(validate_pack_id("../etc").is_err());
        assert!(validate_pack_id("a/b").is_err());
        assert!(validate_pack_id("01HXYZTESTPACK000000000000").is_ok());
    }
}
