//! Mesh master key (MMK) — Argon2id wrap of the 32-byte mesh root key (MRK).
//!
//! Contract: [docs/MASTER-KEY.md](../../../docs/MASTER-KEY.md) (S0 / S3).
//!
//! - KDF: Argon2id within S0 ranges (default m=65536 KiB, t=3, p=1)
//! - Wrap: XChaCha20-Poly1305 over MRK
//! - Recovery codes: 256-bit; SHA-256 hashes stored in `mesh-master.json`
//! - Default unlock: re-prompt (host-local runtime cache is not OS keyring)

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use mymesh_core::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// S0 default Argon2id memory cost (KiB) — within 64_000–256_000.
pub const DEFAULT_M_KIB: u32 = 65_536;
/// S0 default iterations — within 2–4.
pub const DEFAULT_T: u32 = 3;
/// S0 default parallelism — within 1–4.
pub const DEFAULT_P: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20
const MRK_LEN: usize = 32;
const WRAP_KEY_LEN: usize = 32;
/// Number of one-time recovery codes printed at `mesh init`.
pub const RECOVERY_CODE_COUNT: usize = 8;

/// HKDF info for admin Ed25519 seed (MRK hierarchy — never person seed).
pub const HKDF_ADMIN_SIGN: &[u8] = b"mymesh/mrk/admin-sign";
/// HKDF info for admin MAC key.
pub const HKDF_ADMIN_MAC: &[u8] = b"mymesh/mrk/admin-mac";

/// Domain separation for MRK admin proof challenge preimage (B2 / mesh auth).
pub const MRK_PROOF_DOMAIN: &[u8] = b"mymesh-mrk-proof-v1";

const KDF_NAME: &str = "argon2id";
const WRAP_ALG: &str = "xchacha20poly1305";

// ── Argon2id params ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: DEFAULT_M_KIB,
            t: DEFAULT_T,
            p: DEFAULT_P,
        }
    }
}

impl KdfParams {
    pub fn validate(self) -> Result<Self> {
        if !(64_000..=256_000).contains(&self.m) {
            return Err(Error::MasterKey(format!(
                "argon2id m={} out of range 64000–256000 KiB",
                self.m
            )));
        }
        if !(2..=4).contains(&self.t) {
            return Err(Error::MasterKey(format!(
                "argon2id t={} out of range 2–4",
                self.t
            )));
        }
        if !(1..=4).contains(&self.p) {
            return Err(Error::MasterKey(format!(
                "argon2id p={} out of range 1–4",
                self.p
            )));
        }
        Ok(self)
    }
}

// ── MRK ─────────────────────────────────────────────────────────────────────

/// 32-byte mesh root key. Zeroized on drop. Exists only in process memory
/// (or host-local runtime cache after explicit unlock — not OS keyring).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mrk([u8; MRK_LEN]);

impl Mrk {
    pub fn generate() -> Self {
        let mut b = [0u8; MRK_LEN];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(bytes: [u8; MRK_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MRK_LEN] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; MRK_LEN] {
        self.0
    }

    /// Short display/bind fingerprint: first 8 hex chars of SHA-256(MRK).
    pub fn fingerprint(&self) -> String {
        mrk_fingerprint(&self.0)
    }

    /// HKDF-SHA256 expand with domain-separated `info` (e.g. [`HKDF_ADMIN_SIGN`]).
    pub fn derive(&self, info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out)
            .expect("hkdf expand 32 bytes always succeeds");
        out
    }
}

/// First 8 hex chars of SHA-256(mrk).
pub fn mrk_fingerprint(mrk: &[u8; MRK_LEN]) -> String {
    let dig = Sha256::digest(mrk);
    hex::encode(&dig[..4])
}

// ── MRK admin proof (B2 / KD15) ──────────────────────────────────────────────
//
// Remote mesh API admin uses `mrk_proof`: challenge signed with MRK-derived
// admin Ed25519 **or** HMAC-SHA256 (S0). Host-local CLI does **not** need this
// (filesystem trust). Never derive person-seed material from MRK.

/// Which proof method produced an [`MrkAdminProof`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MrkProofMethod {
    /// Ed25519 over domain-separated challenge (preferred for wire auth).
    Ed25519,
    /// HMAC-SHA256 over domain-separated challenge (requires MRK on verifier).
    Hmac,
}

/// Detached admin proof over a challenge (agent-local or mesh API).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrkAdminProof {
    pub method: MrkProofMethod,
    /// Hex-encoded signature (64B Ed25519) or MAC (32B HMAC-SHA256).
    pub proof_hex: String,
    /// Hex-encoded Ed25519 verifying key (32B). Present for [`MrkProofMethod::Ed25519`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
}

/// Canonical preimage: `mymesh-mrk-proof-v1 || challenge`.
pub fn mrk_proof_preimage(challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MRK_PROOF_DOMAIN.len() + challenge.len());
    m.extend_from_slice(MRK_PROOF_DOMAIN);
    m.extend_from_slice(challenge);
    m
}

/// Derive Ed25519 admin signing key from MRK (`mymesh/mrk/admin-sign`).
pub fn admin_signing_key(mrk: &Mrk) -> SigningKey {
    let seed = mrk.derive(HKDF_ADMIN_SIGN);
    SigningKey::from_bytes(&seed)
}

/// Derive Ed25519 admin verifying key bytes (32) from MRK.
pub fn admin_verifying_key_bytes(mrk: &Mrk) -> [u8; 32] {
    admin_signing_key(mrk).verifying_key().to_bytes()
}

/// Derive 32-byte HMAC admin key from MRK (`mymesh/mrk/admin-mac`).
pub fn admin_mac_key(mrk: &Mrk) -> [u8; 32] {
    mrk.derive(HKDF_ADMIN_MAC)
}

/// Sign challenge with MRK-derived admin Ed25519 key.
pub fn sign_mrk_proof_ed25519(mrk: &Mrk, challenge: &[u8]) -> MrkAdminProof {
    let sk = admin_signing_key(mrk);
    let pre = mrk_proof_preimage(challenge);
    let sig: Signature = sk.sign(&pre);
    MrkAdminProof {
        method: MrkProofMethod::Ed25519,
        proof_hex: hex::encode(sig.to_bytes()),
        public_key_hex: Some(hex::encode(sk.verifying_key().to_bytes())),
    }
}

/// Verify Ed25519 admin proof using the MRK (re-derives verifying key).
pub fn verify_mrk_proof_ed25519(mrk: &Mrk, challenge: &[u8], proof: &MrkAdminProof) -> bool {
    if proof.method != MrkProofMethod::Ed25519 {
        return false;
    }
    let vk = admin_verifying_key_bytes(mrk);
    verify_mrk_proof_ed25519_with_vk(&vk, challenge, proof)
}

/// Verify Ed25519 admin proof with an external verifying key (no MRK needed).
pub fn verify_mrk_proof_ed25519_with_vk(
    verifying_key: &[u8; 32],
    challenge: &[u8],
    proof: &MrkAdminProof,
) -> bool {
    if proof.method != MrkProofMethod::Ed25519 {
        return false;
    }
    if let Some(pk_hex) = &proof.public_key_hex {
        let Ok(pk_bytes) = hex::decode(pk_hex) else {
            return false;
        };
        if pk_bytes.as_slice() != verifying_key.as_slice() {
            return false;
        }
    }
    let Ok(sig_bytes) = hex::decode(&proof.proof_hex) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let Ok(sig) = Signature::from_slice(&sig_arr) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(verifying_key) else {
        return false;
    };
    let pre = mrk_proof_preimage(challenge);
    vk.verify(&pre, &sig).is_ok()
}

/// HMAC-SHA256 admin proof over challenge (verifier must hold MRK).
pub fn sign_mrk_proof_hmac(mrk: &Mrk, challenge: &[u8]) -> MrkAdminProof {
    let key = admin_mac_key(mrk);
    let pre = mrk_proof_preimage(challenge);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(&pre);
    let tag = mac.finalize().into_bytes();
    MrkAdminProof {
        method: MrkProofMethod::Hmac,
        proof_hex: hex::encode(tag),
        public_key_hex: None,
    }
}

/// Verify HMAC admin proof (constant-time tag compare).
pub fn verify_mrk_proof_hmac(mrk: &Mrk, challenge: &[u8], proof: &MrkAdminProof) -> bool {
    if proof.method != MrkProofMethod::Hmac {
        return false;
    }
    let Ok(got) = hex::decode(&proof.proof_hex) else {
        return false;
    };
    if got.len() != 32 {
        return false;
    }
    let expected = sign_mrk_proof_hmac(mrk, challenge);
    let Ok(want) = hex::decode(&expected.proof_hex) else {
        return false;
    };
    ct_eq_bytes(&got, &want)
}

/// Verify any supported [`MrkAdminProof`] method using the MRK.
pub fn verify_mrk_admin_proof(mrk: &Mrk, challenge: &[u8], proof: &MrkAdminProof) -> bool {
    match proof.method {
        MrkProofMethod::Ed25519 => verify_mrk_proof_ed25519(mrk, challenge, proof),
        MrkProofMethod::Hmac => verify_mrk_proof_hmac(mrk, challenge, proof),
    }
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

// ── Wrap / unwrap ───────────────────────────────────────────────────────────

/// Result of wrapping an MRK (ciphertext + salt/nonce for on-disk form).
#[derive(Clone, Debug)]
pub struct WrappedMrk {
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext includes Poly1305 tag (MRK_LEN + 16).
    pub ciphertext: Vec<u8>,
}

/// Derive 32-byte wrap key via Argon2id.
pub fn derive_wrap_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; WRAP_KEY_LEN]> {
    let params = params.validate()?;
    let argon_params = argon2::Params::new(params.m, params.t, params.p, Some(WRAP_KEY_LEN))
        .map_err(|e| Error::MasterKey(format!("argon2 params: {e}")))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = [0u8; WRAP_KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::MasterKey(format!("argon2id: {e}")))?;
    Ok(key)
}

/// Wrap MRK under password (fresh salt + nonce).
pub fn wrap_mrk(password: &[u8], mrk: &Mrk, params: &KdfParams) -> Result<WrappedMrk> {
    if password.is_empty() {
        return Err(Error::MasterKey("password must not be empty".into()));
    }
    let params = params.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_wrap_key(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| Error::MasterKey(format!("cipher init: {e}")))?;
    key.zeroize();

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), mrk.as_bytes().as_ref())
        .map_err(|_| Error::MasterKey("wrap encrypt failed".into()))?;

    Ok(WrappedMrk {
        kdf_params: params,
        salt,
        nonce,
        ciphertext,
    })
}

/// Unwrap MRK with password. Wrong password fails closed (AEAD tag).
pub fn unwrap_mrk(password: &[u8], wrapped: &WrappedMrk) -> Result<Mrk> {
    if password.is_empty() {
        return Err(Error::MasterKey("password must not be empty".into()));
    }
    let mut key = derive_wrap_key(password, &wrapped.salt, &wrapped.kdf_params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| Error::MasterKey(format!("cipher init: {e}")))?;
    key.zeroize();

    let plain = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            wrapped.ciphertext.as_ref(),
        )
        .map_err(|_| Error::MasterKey("wrong password or corrupt mesh-master.json".into()))?;

    if plain.len() != MRK_LEN {
        return Err(Error::MasterKey(format!(
            "unwrapped MRK must be {MRK_LEN} bytes, got {}",
            plain.len()
        )));
    }
    let mut bytes = [0u8; MRK_LEN];
    bytes.copy_from_slice(&plain);
    Ok(Mrk(bytes))
}

// ── Recovery codes ──────────────────────────────────────────────────────────

/// One 256-bit recovery code (display = lowercase hex).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    raw: [u8; 32],
}

impl RecoveryCode {
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        Self { raw }
    }

    pub fn from_raw(raw: [u8; 32]) -> Self {
        Self { raw }
    }

    /// Parse from hex (64 hex chars) or whitespace-tolerant hex.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let bytes = hex::decode(cleaned.to_lowercase())
            .map_err(|e| Error::MasterKey(format!("recovery code hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::MasterKey(format!(
                "recovery code must be 256-bit (64 hex chars), got {} bytes",
                bytes.len()
            )));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        Ok(Self { raw })
    }

    pub fn display_hex(&self) -> String {
        hex::encode(self.raw)
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(Sha256::digest(self.raw))
    }

    pub fn as_raw(&self) -> &[u8; 32] {
        &self.raw
    }
}

/// Generate `n` independent 256-bit recovery codes.
pub fn generate_recovery_codes(n: usize) -> Vec<RecoveryCode> {
    (0..n).map(|_| RecoveryCode::generate()).collect()
}

/// Constant-time match of a recovery code against stored SHA-256 hex hashes.
/// Returns the index of the matching hash, if any.
pub fn find_recovery_code(code: &RecoveryCode, hashes: &[String]) -> Option<usize> {
    let want = code.hash_hex();
    let want_b = want.as_bytes();
    for (i, h) in hashes.iter().enumerate() {
        if ct_eq_str(h, want_b) {
            return Some(i);
        }
    }
    None
}

fn ct_eq_str(a: &str, b: &[u8]) -> bool {
    let a = a.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

// ── On-disk: mesh-master.json ───────────────────────────────────────────────

/// On-disk mesh master key wrap (mode 0600). Never contains plaintext MRK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshMasterFile {
    pub kdf: String,
    pub kdf_params: KdfParams,
    /// Base64 salt.
    pub salt: String,
    pub wrap_alg: String,
    /// Base64 XChaCha nonce (24 bytes).
    pub nonce: String,
    /// Base64 AEAD ciphertext (MRK + tag).
    pub wrapped_mrk: String,
    /// 8 hex chars.
    pub mrk_fingerprint: String,
    /// SHA-256 hex of each recovery code (raw 32 bytes).
    pub recovery_code_hashes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

impl MeshMasterFile {
    pub fn from_wrap(
        wrapped: &WrappedMrk,
        fingerprint: String,
        recovery_code_hashes: Vec<String>,
    ) -> Self {
        Self {
            kdf: KDF_NAME.into(),
            kdf_params: wrapped.kdf_params,
            salt: B64.encode(wrapped.salt),
            wrap_alg: WRAP_ALG.into(),
            nonce: B64.encode(wrapped.nonce),
            wrapped_mrk: B64.encode(&wrapped.ciphertext),
            mrk_fingerprint: fingerprint,
            recovery_code_hashes,
            created_at: Utc::now(),
            rotated_at: None,
        }
    }

    pub fn to_wrapped(&self) -> Result<WrappedMrk> {
        if self.kdf != KDF_NAME {
            return Err(Error::MasterKey(format!("unsupported kdf: {}", self.kdf)));
        }
        if self.wrap_alg != WRAP_ALG {
            return Err(Error::MasterKey(format!(
                "unsupported wrap_alg: {}",
                self.wrap_alg
            )));
        }
        let salt_v = B64
            .decode(&self.salt)
            .map_err(|e| Error::MasterKey(format!("salt b64: {e}")))?;
        let nonce_v = B64
            .decode(&self.nonce)
            .map_err(|e| Error::MasterKey(format!("nonce b64: {e}")))?;
        let ct = B64
            .decode(&self.wrapped_mrk)
            .map_err(|e| Error::MasterKey(format!("wrapped_mrk b64: {e}")))?;
        if salt_v.len() != SALT_LEN {
            return Err(Error::MasterKey(format!(
                "salt must be {SALT_LEN} bytes, got {}",
                salt_v.len()
            )));
        }
        if nonce_v.len() != NONCE_LEN {
            return Err(Error::MasterKey(format!(
                "nonce must be {NONCE_LEN} bytes, got {}",
                nonce_v.len()
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&salt_v);
        nonce.copy_from_slice(&nonce_v);
        Ok(WrappedMrk {
            kdf_params: self.kdf_params.validate()?,
            salt,
            nonce,
            ciphertext: ct,
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::NotFound(format!(
                "mesh-master.json missing at {} — run `mymesh mesh init`",
                path.display()
            )));
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn try_load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// First-init only: `create_new` so a second writer cannot overwrite.
    ///
    /// Recover/rotate keep [`Self::save`]. Failure is `mesh_already_inited`.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::PermissionDenied("mesh_already_inited".into()));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::PermissionDenied("mesh_already_inited".into())
            } else {
                e.into()
            }
        })?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode != 0o600 {
                let _ = std::fs::remove_file(path);
                return Err(Error::MasterKey(format!(
                    "mesh-master.json expected mode 0600, got {mode:04o}"
                )));
            }
        }
        Ok(())
    }

    pub fn exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }
}

// ── High-level operations ───────────────────────────────────────────────────

/// Result of `mesh init`: file written + recovery codes to print **once**.
pub struct MeshInitResult {
    pub file: MeshMasterFile,
    pub mrk: Mrk,
    /// Print once; never stored in plaintext.
    pub recovery_codes: Vec<RecoveryCode>,
}

/// Create a new mesh master: random MRK, wrap with password, generate recovery codes.
pub fn mesh_init(password: &[u8], params: Option<KdfParams>) -> Result<MeshInitResult> {
    let params = params.unwrap_or_default().validate()?;
    let mrk = Mrk::generate();
    let wrapped = wrap_mrk(password, &mrk, &params)?;
    let recovery_codes = generate_recovery_codes(RECOVERY_CODE_COUNT);
    let hashes: Vec<String> = recovery_codes.iter().map(|c| c.hash_hex()).collect();
    let fingerprint = mrk.fingerprint();
    let file = MeshMasterFile::from_wrap(&wrapped, fingerprint, hashes);
    Ok(MeshInitResult {
        file,
        mrk,
        recovery_codes,
    })
}

/// Unlock with password → MRK.
pub fn mesh_unlock_password(file: &MeshMasterFile, password: &[u8]) -> Result<Mrk> {
    let wrapped = file.to_wrapped()?;
    let mrk = unwrap_mrk(password, &wrapped)?;
    if mrk.fingerprint() != file.mrk_fingerprint {
        return Err(Error::MasterKey(
            "fingerprint mismatch after unwrap (corrupt file?)".into(),
        ));
    }
    Ok(mrk)
}

/// `recover-master --code`: verify recovery code, generate new MRK, wrap with new password,
/// consume the used recovery code hash. Returns updated file + new MRK + remaining codes count.
pub fn mesh_recover_with_code(
    file: &MeshMasterFile,
    code: &RecoveryCode,
    new_password: &[u8],
    params: Option<KdfParams>,
) -> Result<(MeshMasterFile, Mrk)> {
    let idx = find_recovery_code(code, &file.recovery_code_hashes)
        .ok_or_else(|| Error::MasterKey("invalid recovery code".into()))?;
    let params = params.unwrap_or(file.kdf_params).validate()?;
    let mrk = Mrk::generate();
    let wrapped = wrap_mrk(new_password, &mrk, &params)?;
    let mut hashes = file.recovery_code_hashes.clone();
    hashes.remove(idx);
    let mut new_file = MeshMasterFile::from_wrap(&wrapped, mrk.fingerprint(), hashes);
    // Preserve original created_at; mark rotation.
    new_file.created_at = file.created_at;
    new_file.rotated_at = Some(Utc::now());
    Ok((new_file, mrk))
}

/// Rotate master password (requires current password). Same MRK re-wrapped.
pub fn mesh_rotate_password(
    file: &MeshMasterFile,
    current_password: &[u8],
    new_password: &[u8],
    params: Option<KdfParams>,
) -> Result<(MeshMasterFile, Mrk)> {
    let mrk = mesh_unlock_password(file, current_password)?;
    let params = params.unwrap_or(file.kdf_params).validate()?;
    let wrapped = wrap_mrk(new_password, &mrk, &params)?;
    let mut new_file = MeshMasterFile::from_wrap(
        &wrapped,
        mrk.fingerprint(),
        file.recovery_code_hashes.clone(),
    );
    new_file.created_at = file.created_at;
    new_file.rotated_at = Some(Utc::now());
    Ok((new_file, mrk))
}

// ── Host-local unlock runtime cache (not OS keyring) ────────────────────────

/// Ephemeral host-local unlock state. Mode 0600. Cleared by `mesh lock`.
/// Distinct from opt-in OS keyring (KD30) — never written by default at init.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MmkRuntime {
    /// Hex-encoded 32-byte MRK.
    pub mrk_hex: String,
    pub mrk_fingerprint: String,
    pub unlocked_at: DateTime<Utc>,
}

impl MmkRuntime {
    pub fn from_mrk(mrk: &Mrk) -> Self {
        Self {
            mrk_hex: hex::encode(mrk.as_bytes()),
            mrk_fingerprint: mrk.fingerprint(),
            unlocked_at: Utc::now(),
        }
    }

    pub fn to_mrk(&self) -> Result<Mrk> {
        let bytes = hex::decode(&self.mrk_hex)
            .map_err(|e| Error::MasterKey(format!("runtime mrk hex: {e}")))?;
        if bytes.len() != MRK_LEN {
            return Err(Error::MasterKey(format!(
                "runtime MRK must be {MRK_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; MRK_LEN];
        arr.copy_from_slice(&bytes);
        let mrk = Mrk(arr);
        if mrk.fingerprint() != self.mrk_fingerprint {
            return Err(Error::MasterKey("runtime fingerprint mismatch".into()));
        }
        Ok(mrk)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn clear(path: impl AsRef<Path>) -> Result<bool> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast params for unit tests (still within S0 ranges).
    fn test_params() -> KdfParams {
        KdfParams {
            m: 64_000,
            t: 2,
            p: 1,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let password = b"correct horse battery staple";
        let mrk = Mrk::generate();
        let fp = mrk.fingerprint();
        let wrapped = wrap_mrk(password, &mrk, &test_params()).unwrap();
        let out = unwrap_mrk(password, &wrapped).unwrap();
        assert_eq!(out.as_bytes(), mrk.as_bytes());
        assert_eq!(out.fingerprint(), fp);
    }

    #[test]
    fn wrong_password_fails_closed() {
        let mrk = Mrk::generate();
        let wrapped = wrap_mrk(b"right-password", &mrk, &test_params()).unwrap();
        let err = match unwrap_mrk(b"wrong-password", &wrapped) {
            Ok(_) => panic!("wrong password must not unwrap"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("wrong password") || msg.contains("master key"),
            "unexpected err: {msg}"
        );
    }

    #[test]
    fn empty_password_rejected() {
        let mrk = Mrk::generate();
        assert!(wrap_mrk(b"", &mrk, &test_params()).is_err());
    }

    #[test]
    fn mesh_master_file_json_roundtrip() {
        let password = b"test-pass-1234";
        let init = mesh_init(password, Some(test_params())).unwrap();
        assert_eq!(init.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(init.file.recovery_code_hashes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(init.file.kdf, "argon2id");
        assert_eq!(init.file.wrap_alg, "xchacha20poly1305");
        assert_eq!(init.file.mrk_fingerprint.len(), 8);

        let dir = std::env::temp_dir().join(format!("mymesh-mmk-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mesh-master.json");
        init.file.save(&path).unwrap();

        let loaded = MeshMasterFile::load(&path).unwrap();
        let mrk = mesh_unlock_password(&loaded, password).unwrap();
        assert_eq!(mrk.as_bytes(), init.mrk.as_bytes());

        // recovery code hashes match
        for (code, h) in init
            .recovery_codes
            .iter()
            .zip(loaded.recovery_code_hashes.iter())
        {
            assert_eq!(&code.hash_hex(), h);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_code_find_and_recover() {
        let password = b"original-pass";
        let init = mesh_init(password, Some(test_params())).unwrap();
        let code = &init.recovery_codes[3];
        assert!(find_recovery_code(code, &init.file.recovery_code_hashes).is_some());

        let bad = RecoveryCode::generate();
        assert!(find_recovery_code(&bad, &init.file.recovery_code_hashes).is_none());

        let new_pass = b"new-pass-after-recovery";
        let (new_file, new_mrk) =
            mesh_recover_with_code(&init.file, code, new_pass, Some(test_params())).unwrap();
        assert_ne!(new_mrk.as_bytes(), init.mrk.as_bytes());
        assert_eq!(new_file.recovery_code_hashes.len(), RECOVERY_CODE_COUNT - 1);
        assert!(new_file.rotated_at.is_some());
        // used code no longer valid
        assert!(find_recovery_code(code, &new_file.recovery_code_hashes).is_none());
        // new password unlocks
        let unlocked = mesh_unlock_password(&new_file, new_pass).unwrap();
        assert_eq!(unlocked.as_bytes(), new_mrk.as_bytes());
        // old password fails
        assert!(mesh_unlock_password(&new_file, password).is_err());
    }

    #[test]
    fn hkdf_admin_labels_deterministic_and_distinct() {
        let mrk = Mrk::from_bytes([0x42; 32]);
        let sign1 = mrk.derive(HKDF_ADMIN_SIGN);
        let sign2 = mrk.derive(HKDF_ADMIN_SIGN);
        let mac = mrk.derive(HKDF_ADMIN_MAC);
        assert_eq!(sign1, sign2);
        assert_ne!(sign1, mac);
        // Must not equal person-backup style labels if someone mis-keys
        let other = mrk.derive(b"mymesh/person-backup");
        assert_ne!(sign1, other);
        assert_ne!(mac, other);
    }

    #[test]
    fn fingerprint_is_8_hex() {
        let mrk = Mrk::generate();
        let fp = mrk.fingerprint();
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn kdf_params_range_enforced() {
        assert!(KdfParams {
            m: 1000,
            t: 3,
            p: 1
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m: 65_536,
            t: 1,
            p: 1
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m: 65_536,
            t: 3,
            p: 8
        }
        .validate()
        .is_err());
        assert!(KdfParams::default().validate().is_ok());
    }

    #[test]
    fn runtime_cache_roundtrip() {
        let mrk = Mrk::generate();
        let rt = MmkRuntime::from_mrk(&mrk);
        let dir = std::env::temp_dir().join(format!("mymesh-mmk-rt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mmk-runtime.json");
        rt.save(&path).unwrap();
        let loaded = MmkRuntime::load(&path).unwrap().unwrap();
        let out = loaded.to_mrk().unwrap();
        assert_eq!(out.as_bytes(), mrk.as_bytes());
        assert!(MmkRuntime::clear(&path).unwrap());
        assert!(MmkRuntime::load(&path).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_person_seed_in_mrk_hierarchy() {
        // Golden: admin labels only; MRK hierarchy must not include person-seed labels.
        let labels = [HKDF_ADMIN_SIGN, HKDF_ADMIN_MAC];
        for l in labels {
            let s = std::str::from_utf8(l).unwrap();
            assert!(
                !s.contains("person"),
                "label {s} must not be person hierarchy"
            );
            assert!(s.starts_with("mymesh/mrk/"));
        }
    }

    #[test]
    fn recovery_code_parse_hex() {
        let c = RecoveryCode::generate();
        let disp = c.display_hex();
        let parsed = RecoveryCode::parse(&disp).unwrap();
        assert_eq!(parsed.as_raw(), c.as_raw());
        // whitespace tolerant
        let spaced = format!("{} {}", &disp[..32], &disp[32..]);
        let parsed2 = RecoveryCode::parse(&spaced).unwrap();
        assert_eq!(parsed2.as_raw(), c.as_raw());
    }

    #[test]
    fn mrk_admin_proof_ed25519_roundtrip() {
        let mrk = Mrk::from_bytes([0x11; 32]);
        let challenge = b"mesh-auth-challenge-v1-test";
        let proof = sign_mrk_proof_ed25519(&mrk, challenge);
        assert_eq!(proof.method, MrkProofMethod::Ed25519);
        assert!(proof.public_key_hex.is_some());
        assert!(verify_mrk_proof_ed25519(&mrk, challenge, &proof));
        assert!(verify_mrk_admin_proof(&mrk, challenge, &proof));
        // wrong challenge fails
        assert!(!verify_mrk_proof_ed25519(&mrk, b"other", &proof));
        // wrong MRK fails
        let other = Mrk::from_bytes([0x22; 32]);
        assert!(!verify_mrk_proof_ed25519(&other, challenge, &proof));
        // external vk path
        let vk = admin_verifying_key_bytes(&mrk);
        assert!(verify_mrk_proof_ed25519_with_vk(&vk, challenge, &proof));
        let bad_vk = [0u8; 32];
        assert!(!verify_mrk_proof_ed25519_with_vk(
            &bad_vk, challenge, &proof
        ));
    }

    #[test]
    fn mrk_admin_proof_hmac_roundtrip() {
        let mrk = Mrk::from_bytes([0x33; 32]);
        let challenge = b"hmac-challenge";
        let proof = sign_mrk_proof_hmac(&mrk, challenge);
        assert_eq!(proof.method, MrkProofMethod::Hmac);
        assert!(proof.public_key_hex.is_none());
        assert!(verify_mrk_proof_hmac(&mrk, challenge, &proof));
        assert!(!verify_mrk_proof_hmac(&mrk, b"nope", &proof));
        let other = Mrk::from_bytes([0x44; 32]);
        assert!(!verify_mrk_proof_hmac(&other, challenge, &proof));
    }

    #[test]
    fn admin_sign_and_mac_keys_distinct() {
        let mrk = Mrk::from_bytes([0x55; 32]);
        let sign_seed = mrk.derive(HKDF_ADMIN_SIGN);
        let mac_key = admin_mac_key(&mrk);
        assert_ne!(sign_seed, mac_key);
        let vk = admin_verifying_key_bytes(&mrk);
        // verifying key is not raw seed
        assert_ne!(vk, sign_seed);
    }

    #[test]
    fn mrk_proof_preimage_domain_separated() {
        let pre = mrk_proof_preimage(b"abc");
        assert!(pre.starts_with(MRK_PROOF_DOMAIN));
        assert!(pre.ends_with(b"abc"));
        assert_ne!(pre, b"abc");
    }
}
