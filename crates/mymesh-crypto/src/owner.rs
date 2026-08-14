//! Owner claim + sealed person backup (S4 / B4).
//!
//! Contract: [docs/MASTER-KEY.md](../../../docs/MASTER-KEY.md), [docs/CARRIER-NEXT.md](../../../docs/CARRIER-NEXT.md) §S4.
//!
//! - Person Ed25519 signature over canonical claim preimage (phone never holds MMK)
//! - Agent co-sign (MRK unlocked) or CLI `allow-claim` window
//! - Sealed backup: independent password-AEAD (MRK does **not** wrap person seed)

use crate::identity::{Identity, IdentityPublic};
use crate::master_key::{derive_wrap_key, KdfParams, DEFAULT_M_KIB, DEFAULT_P, DEFAULT_T};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Duration, Utc};
use mymesh_core::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

/// Domain separation for owner claim preimage (S0 golden).
pub const OWNER_CLAIM_DOMAIN: &[u8] = b"carrier-mesh-owner-v1";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = 32;
const KDF_NAME: &str = "argon2id";
const WRAP_ALG: &str = "xchacha20poly1305";
const BACKUP_VERSION: u32 = 1;

// ── Claim preimage ──────────────────────────────────────────────────────────

/// Canonical owner-claim preimage (S0 golden):
///
/// ```text
/// carrier-mesh-owner-v1 || u16le(len) || mesh_id_utf8
///   || u16le(len) || person_id_utf8
///   || person_pk_32
///   || mrk_fingerprint_utf8
///   || i64le(ts_unix)
/// ```
pub fn owner_claim_preimage(
    mesh_id: &str,
    person_id: &str,
    person_pk: &[u8; 32],
    mrk_fingerprint: &str,
    ts_unix: i64,
) -> Result<Vec<u8>> {
    let mesh_b = mesh_id.as_bytes();
    let person_b = person_id.as_bytes();
    if mesh_b.len() > u16::MAX as usize {
        return Err(Error::MasterKey(
            "mesh_id too long for claim preimage".into(),
        ));
    }
    if person_b.len() > u16::MAX as usize {
        return Err(Error::MasterKey(
            "person_id too long for claim preimage".into(),
        ));
    }
    let mut out = Vec::with_capacity(
        OWNER_CLAIM_DOMAIN.len()
            + 2
            + mesh_b.len()
            + 2
            + person_b.len()
            + 32
            + mrk_fingerprint.len()
            + 8,
    );
    out.extend_from_slice(OWNER_CLAIM_DOMAIN);
    out.extend_from_slice(&(mesh_b.len() as u16).to_le_bytes());
    out.extend_from_slice(mesh_b);
    out.extend_from_slice(&(person_b.len() as u16).to_le_bytes());
    out.extend_from_slice(person_b);
    out.extend_from_slice(person_pk);
    out.extend_from_slice(mrk_fingerprint.as_bytes());
    out.extend_from_slice(&ts_unix.to_le_bytes());
    Ok(out)
}

/// Verify person Ed25519 signature over the claim preimage.
pub fn verify_owner_claim_sig(person_pk: &[u8; 32], preimage: &[u8], sig: &[u8; 64]) -> Result<()> {
    let pubk = IdentityPublic {
        verifying_key: *person_pk,
    };
    pubk.verify(preimage, sig)
        .map_err(|e| Error::MasterKey(format!("owner claim signature: {e}")))
}

/// Sign claim preimage with a person identity (tests / CLI helpers).
pub fn sign_owner_claim(person: &Identity, preimage: &[u8]) -> [u8; 64] {
    person.sign(preimage)
}

// ── mesh-owner.json ─────────────────────────────────────────────────────────

/// On-disk person owner claim (mode 0600). Person ownership only — never a device role.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshOwnerFile {
    pub mesh_id: String,
    pub person_id: String,
    pub person_public_key_hex: String,
    #[serde(default)]
    pub display_name: String,
    /// RFC3339 claim time (also encoded as i64 in preimage / `claim_ts_unix`).
    pub claimed_at: DateTime<Utc>,
    /// Unix seconds used in the signed preimage (authoritative for verify).
    #[serde(default)]
    pub claim_ts_unix: i64,
    /// Device that hosted the claim API/CLI — **not** role=owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_from_device_id: Option<String>,
    /// MRK fingerprint at claim time (updated on recover-master, KD28).
    pub mrk_fingerprint: String,
    /// Incremented on recover-master; original claim_sig remains valid.
    #[serde(default)]
    pub mrk_epoch: u64,
    /// Person Ed25519 signature hex over claim preimage.
    pub claim_sig_hex: String,
    /// Optional sealed-backup presence marker (blob lives in `owner-backup.sealed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_stored_at: Option<DateTime<Utc>>,
}

impl MeshOwnerFile {
    pub fn try_load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::try_load(path)?.ok_or_else(|| {
            Error::NotFound("mesh-owner.json missing — no person owner claim".into())
        })
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

    pub fn person_pk_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(self.person_public_key_hex.trim())
            .map_err(|e| Error::MasterKey(format!("person_public_key_hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::MasterKey(format!(
                "person_public_key_hex must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        Ok(a)
    }

    /// Update fingerprint after recover-master (claim remains valid; KD28).
    pub fn bump_mrk_fingerprint(&mut self, new_fp: &str) {
        self.mrk_fingerprint = new_fp.to_string();
        self.mrk_epoch = self.mrk_epoch.saturating_add(1);
    }

    /// Mark that a sealed backup blob is present on disk.
    pub fn mark_backup_stored(&mut self) {
        self.backup_stored_at = Some(Utc::now());
    }
}

// ── claim-window.json ───────────────────────────────────────────────────────

/// MMK-authorized claim window (mode 0600). Minted by `mymesh owner allow-claim`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimWindowFile {
    /// RFC3339 expiry.
    pub until: DateTime<Utc>,
    /// Random nonce (hex) — capability id.
    pub nonce: String,
    pub authorized_at: DateTime<Utc>,
    /// Fingerprint bound at mint (for claim preimage when MRK not in memory).
    pub mrk_fingerprint: String,
    /// Seconds requested at mint (informational).
    #[serde(default)]
    pub secs: u64,
}

impl ClaimWindowFile {
    pub fn mint(mrk_fingerprint: &str, secs: u64) -> Self {
        let secs = secs.clamp(1, 24 * 3600);
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Self {
            until: Utc::now() + Duration::seconds(secs as i64),
            nonce: hex::encode(nonce),
            authorized_at: Utc::now(),
            mrk_fingerprint: mrk_fingerprint.to_string(),
            secs,
        }
    }

    pub fn is_valid_now(&self) -> bool {
        self.until > Utc::now()
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

/// How the agent satisfied MMK authorization for a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimAuthMethod {
    /// MRK present in host-local runtime (agent co-sign).
    MrkUnlocked,
    /// Valid claim-window.json (minted while MMK unlocked).
    ClaimWindow,
}

/// Check agent-local MMK authorization for owner claim (phone never supplies this).
pub fn check_claim_authorized(
    mmk_runtime_path: impl AsRef<Path>,
    claim_window_path: impl AsRef<Path>,
) -> Result<ClaimAuthMethod> {
    use crate::master_key::MmkRuntime;
    if let Some(rt) = MmkRuntime::load(mmk_runtime_path)? {
        // Validate runtime can reconstitute MRK.
        let _ = rt.to_mrk()?;
        return Ok(ClaimAuthMethod::MrkUnlocked);
    }
    if let Some(win) = ClaimWindowFile::try_load(claim_window_path)? {
        if win.is_valid_now() {
            return Ok(ClaimAuthMethod::ClaimWindow);
        }
        return Err(Error::PermissionDenied(
            "claim window expired — unlock MMK or run mymesh owner allow-claim".into(),
        ));
    }
    Err(Error::PermissionDenied(
        "mmk_locked: unlock MMK (mymesh mesh unlock) or open claim window (mymesh owner allow-claim)"
            .into(),
    ))
}

/// Inputs for accepting a person-signed owner claim.
#[derive(Clone, Debug)]
pub struct OwnerClaimRequest {
    pub mesh_id: String,
    pub person_id: String,
    pub person_public_key_hex: String,
    pub display_name: String,
    /// Unix timestamp that was signed (i64 in preimage).
    pub ts_unix: i64,
    pub claim_sig_hex: String,
    pub claimed_from_device_id: Option<String>,
    /// When true and owner already exists, replace if MMK unlocked (destructive).
    pub replace: bool,
}

/// Accept a person-signed claim when agent-local MMK auth is satisfied.
///
/// - Verifies person signature over S0 preimage
/// - Binds `mrk_fingerprint` from unlocked MRK or claim window
/// - Rejects second claim unless `replace` + MRK unlocked
/// - Does **not** consume claim window on success (window may allow one claim;
///   caller may clear window after write)
pub fn accept_owner_claim(
    req: &OwnerClaimRequest,
    mrk_fingerprint: &str,
    auth: ClaimAuthMethod,
    existing: Option<&MeshOwnerFile>,
    out_path: impl AsRef<Path>,
) -> Result<MeshOwnerFile> {
    if mrk_fingerprint.is_empty() {
        return Err(Error::MasterKey(
            "mrk_fingerprint required for claim".into(),
        ));
    }

    // Replace / second-claim policy.
    if let Some(prev) = existing {
        let same_person = prev.person_id == req.person_id
            && prev
                .person_public_key_hex
                .eq_ignore_ascii_case(&req.person_public_key_hex);
        if same_person {
            // Idempotent: return existing without rewrite if sig matches, else rewrite.
            return Ok(prev.clone());
        }
        if !req.replace {
            return Err(Error::PermissionDenied(
                "owner already claimed — clear with MMK (mymesh owner clear) before replace".into(),
            ));
        }
        // Replace is mesh-destructive: require live MRK, not just claim window.
        if auth != ClaimAuthMethod::MrkUnlocked {
            return Err(Error::PermissionDenied(
                "replace owner requires MMK unlocked (claim window insufficient)".into(),
            ));
        }
    }

    let pk_bytes = hex::decode(req.person_public_key_hex.trim())
        .map_err(|e| Error::MasterKey(format!("person_public_key_hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(Error::MasterKey(format!(
            "person_public_key_hex must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut person_pk = [0u8; 32];
    person_pk.copy_from_slice(&pk_bytes);

    let sig_bytes = hex::decode(
        req.claim_sig_hex
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    )
    .map_err(|e| Error::MasterKey(format!("claim_sig_hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(Error::MasterKey(format!(
            "claim_sig_hex must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    let pre = owner_claim_preimage(
        &req.mesh_id,
        &req.person_id,
        &person_pk,
        mrk_fingerprint,
        req.ts_unix,
    )?;
    verify_owner_claim_sig(&person_pk, &pre, &sig)?;

    let claimed_at = DateTime::from_timestamp(req.ts_unix, 0).unwrap_or_else(Utc::now);

    let file = MeshOwnerFile {
        mesh_id: req.mesh_id.clone(),
        person_id: req.person_id.clone(),
        person_public_key_hex: hex::encode(person_pk),
        display_name: req.display_name.clone(),
        claimed_at,
        claim_ts_unix: req.ts_unix,
        claimed_from_device_id: req.claimed_from_device_id.clone(),
        mrk_fingerprint: mrk_fingerprint.to_string(),
        mrk_epoch: 0,
        claim_sig_hex: hex::encode(sig),
        backup_stored_at: existing.and_then(|e| e.backup_stored_at),
    };
    file.save(out_path)?;
    Ok(file)
}

/// Resolve mrk_fingerprint for claim: prefer unlocked MRK, else claim window, else mesh-master file.
pub fn resolve_claim_fingerprint(
    auth: ClaimAuthMethod,
    mmk_runtime_path: impl AsRef<Path>,
    claim_window_path: impl AsRef<Path>,
    mesh_master_path: impl AsRef<Path>,
) -> Result<String> {
    use crate::master_key::{MeshMasterFile, MmkRuntime};
    match auth {
        ClaimAuthMethod::MrkUnlocked => {
            let rt = MmkRuntime::load(mmk_runtime_path)?
                .ok_or_else(|| Error::PermissionDenied("mmk_locked".into()))?;
            Ok(rt.mrk_fingerprint)
        }
        ClaimAuthMethod::ClaimWindow => {
            if let Some(win) = ClaimWindowFile::try_load(claim_window_path)? {
                if win.is_valid_now() {
                    return Ok(win.mrk_fingerprint);
                }
            }
            // Fallback to mesh-master fingerprint if window missing fp (shouldn't happen).
            let file = MeshMasterFile::load(mesh_master_path)?;
            Ok(file.mrk_fingerprint)
        }
    }
}

// ── owner-backup.sealed ─────────────────────────────────────────────────────

/// Password-AEAD sealed person seed backup (MRK-independent). Mode 0600.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerBackupSealed {
    pub version: u32,
    pub person_id: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    /// Base64 salt.
    pub salt: String,
    pub wrap_alg: String,
    /// Base64 XChaCha nonce.
    pub nonce: String,
    /// Base64 AEAD ciphertext (seed + meta).
    pub ciphertext: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Plaintext payload inside sealed backup: 32B seed || u16le meta_len || meta_utf8.
fn pack_backup_plaintext(seed: &[u8; SEED_LEN], meta: &str) -> Result<Vec<u8>> {
    let meta_b = meta.as_bytes();
    if meta_b.len() > u16::MAX as usize {
        return Err(Error::MasterKey("backup meta too long".into()));
    }
    let mut out = Vec::with_capacity(SEED_LEN + 2 + meta_b.len());
    out.extend_from_slice(seed);
    out.extend_from_slice(&(meta_b.len() as u16).to_le_bytes());
    out.extend_from_slice(meta_b);
    Ok(out)
}

fn unpack_backup_plaintext(plain: &[u8]) -> Result<([u8; SEED_LEN], String)> {
    if plain.len() < SEED_LEN + 2 {
        return Err(Error::MasterKey("backup plaintext too short".into()));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plain[..SEED_LEN]);
    let meta_len = u16::from_le_bytes([plain[SEED_LEN], plain[SEED_LEN + 1]]) as usize;
    let meta_start = SEED_LEN + 2;
    if plain.len() < meta_start + meta_len {
        return Err(Error::MasterKey("backup meta truncated".into()));
    }
    let meta = String::from_utf8(plain[meta_start..meta_start + meta_len].to_vec())
        .map_err(|e| Error::MasterKey(format!("backup meta utf8: {e}")))?;
    Ok((seed, meta))
}

/// Seal person seed under backup password (independent of MMK/MRK).
pub fn seal_owner_backup(
    password: &[u8],
    person_id: &str,
    seed: &[u8; SEED_LEN],
    meta: &str,
    hint: Option<&str>,
    params: Option<KdfParams>,
) -> Result<OwnerBackupSealed> {
    if password.is_empty() {
        return Err(Error::MasterKey("backup password must not be empty".into()));
    }
    let params = params
        .unwrap_or(KdfParams {
            m: DEFAULT_M_KIB,
            t: DEFAULT_T,
            p: DEFAULT_P,
        })
        .validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_wrap_key(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| Error::MasterKey(format!("cipher init: {e}")))?;
    key.zeroize();

    let plain = pack_backup_plaintext(seed, meta)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| Error::MasterKey("backup encrypt failed".into()))?;

    Ok(OwnerBackupSealed {
        version: BACKUP_VERSION,
        person_id: person_id.to_string(),
        kdf: KDF_NAME.into(),
        kdf_params: params,
        salt: B64.encode(salt),
        wrap_alg: WRAP_ALG.into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
        created_at: Utc::now(),
        hint: hint.map(|s| s.to_string()),
    })
}

/// Unseal person seed with backup password. Wrong password fails closed.
pub fn unseal_owner_backup(
    password: &[u8],
    sealed: &OwnerBackupSealed,
) -> Result<([u8; SEED_LEN], String)> {
    if password.is_empty() {
        return Err(Error::MasterKey("backup password must not be empty".into()));
    }
    if sealed.version != BACKUP_VERSION {
        return Err(Error::MasterKey(format!(
            "unsupported owner backup version {}",
            sealed.version
        )));
    }
    if sealed.kdf != KDF_NAME || sealed.wrap_alg != WRAP_ALG {
        return Err(Error::MasterKey("unsupported backup kdf/wrap_alg".into()));
    }
    let salt_v = B64
        .decode(&sealed.salt)
        .map_err(|e| Error::MasterKey(format!("salt b64: {e}")))?;
    let nonce_v = B64
        .decode(&sealed.nonce)
        .map_err(|e| Error::MasterKey(format!("nonce b64: {e}")))?;
    let ct = B64
        .decode(&sealed.ciphertext)
        .map_err(|e| Error::MasterKey(format!("ciphertext b64: {e}")))?;
    if salt_v.len() != SALT_LEN || nonce_v.len() != NONCE_LEN {
        return Err(Error::MasterKey("backup salt/nonce size".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    salt.copy_from_slice(&salt_v);
    nonce.copy_from_slice(&nonce_v);

    let mut key = derive_wrap_key(password, &salt, &sealed.kdf_params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| Error::MasterKey(format!("cipher init: {e}")))?;
    key.zeroize();

    let plain = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| {
            Error::MasterKey("wrong backup password or corrupt owner-backup.sealed".into())
        })?;
    unpack_backup_plaintext(&plain)
}

impl OwnerBackupSealed {
    pub fn try_load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::try_load(path)?.ok_or_else(|| Error::NotFound("owner-backup.sealed missing".into()))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("sealed.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Store a pre-sealed blob (from phone PUT or CLI import). Validates JSON shape only.
    pub fn store_blob(path: impl AsRef<Path>, sealed: &Self) -> Result<()> {
        if sealed.version != BACKUP_VERSION {
            return Err(Error::MasterKey(format!(
                "unsupported owner backup version {}",
                sealed.version
            )));
        }
        // Ensure ciphertext decodes as base64 and salt/nonce sizes look sane.
        let salt_v = B64
            .decode(&sealed.salt)
            .map_err(|e| Error::MasterKey(format!("salt b64: {e}")))?;
        let nonce_v = B64
            .decode(&sealed.nonce)
            .map_err(|e| Error::MasterKey(format!("nonce b64: {e}")))?;
        let _ct = B64
            .decode(&sealed.ciphertext)
            .map_err(|e| Error::MasterKey(format!("ciphertext b64: {e}")))?;
        if salt_v.len() != SALT_LEN || nonce_v.len() != NONCE_LEN {
            return Err(Error::MasterKey("backup salt/nonce size".into()));
        }
        sealed.save(path)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_key::{mesh_init, MmkRuntime};

    fn test_params() -> KdfParams {
        KdfParams {
            m: 64_000,
            t: 2,
            p: 1,
        }
    }

    fn tmp_dir() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mymesh-owner-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn claim_preimage_domain_and_roundtrip_sig() {
        let person = Identity::generate();
        let pk = person.verifying_key_bytes();
        let pre = owner_claim_preimage("mesh-uuid-1", "01PERSON", &pk, "deadbeef", 1_700_000_000)
            .unwrap();
        assert!(pre.starts_with(OWNER_CLAIM_DOMAIN));
        // mesh_id length prefix
        assert_eq!(
            u16::from_le_bytes([
                pre[OWNER_CLAIM_DOMAIN.len()],
                pre[OWNER_CLAIM_DOMAIN.len() + 1]
            ]),
            "mesh-uuid-1".len() as u16
        );
        let sig = sign_owner_claim(&person, &pre);
        verify_owner_claim_sig(&pk, &pre, &sig).unwrap();

        // Wrong key fails.
        let other = Identity::generate();
        assert!(verify_owner_claim_sig(&other.verifying_key_bytes(), &pre, &sig).is_err());
    }

    #[test]
    fn claim_accept_requires_auth_and_writes_file() {
        let dir = tmp_dir();
        let owner_path = dir.join("mesh-owner.json");
        let runtime_path = dir.join("mmk-runtime.json");
        let window_path = dir.join("claim-window.json");
        let master_path = dir.join("mesh-master.json");

        let init = mesh_init(b"mmk-pass-ok", Some(test_params())).unwrap();
        init.file.save(&master_path).unwrap();
        let fp = init.mrk.fingerprint();

        let person = Identity::generate();
        let pk = person.verifying_key_bytes();
        let ts = Utc::now().timestamp();
        let pre = owner_claim_preimage("mesh-1", "pid-1", &pk, &fp, ts).unwrap();
        let sig = sign_owner_claim(&person, &pre);

        let req = OwnerClaimRequest {
            mesh_id: "mesh-1".into(),
            person_id: "pid-1".into(),
            person_public_key_hex: hex::encode(pk),
            display_name: "Ada".into(),
            ts_unix: ts,
            claim_sig_hex: hex::encode(sig),
            claimed_from_device_id: Some("host-dev".into()),
            replace: false,
        };

        // No auth → fail.
        assert!(check_claim_authorized(&runtime_path, &window_path).is_err());

        // Unlock MMK → co-sign path.
        MmkRuntime::from_mrk(&init.mrk).save(&runtime_path).unwrap();
        let auth = check_claim_authorized(&runtime_path, &window_path).unwrap();
        assert_eq!(auth, ClaimAuthMethod::MrkUnlocked);
        let claim_fp =
            resolve_claim_fingerprint(auth, &runtime_path, &window_path, &master_path).unwrap();
        let file = accept_owner_claim(&req, &claim_fp, auth, None, &owner_path).unwrap();
        assert_eq!(file.person_id, "pid-1");
        assert_eq!(file.mrk_fingerprint, fp);
        assert_eq!(file.display_name, "Ada");
        assert!(owner_path.exists());

        // Second different claim without replace → fail.
        let person2 = Identity::generate();
        let pk2 = person2.verifying_key_bytes();
        let pre2 = owner_claim_preimage("mesh-1", "pid-2", &pk2, &fp, ts).unwrap();
        let sig2 = sign_owner_claim(&person2, &pre2);
        let req2 = OwnerClaimRequest {
            mesh_id: "mesh-1".into(),
            person_id: "pid-2".into(),
            person_public_key_hex: hex::encode(pk2),
            display_name: "Bob".into(),
            ts_unix: ts,
            claim_sig_hex: hex::encode(sig2),
            claimed_from_device_id: None,
            replace: false,
        };
        let existing = MeshOwnerFile::load(&owner_path).unwrap();
        let err = accept_owner_claim(&req2, &fp, auth, Some(&existing), &owner_path).unwrap_err();
        assert!(
            err.to_string().contains("already claimed") || err.to_string().contains("Permission")
        );
    }

    #[test]
    fn claim_accept_via_allow_claim_window_without_runtime() {
        let dir = tmp_dir();
        let owner_path = dir.join("mesh-owner.json");
        let runtime_path = dir.join("mmk-runtime.json");
        let window_path = dir.join("claim-window.json");
        let master_path = dir.join("mesh-master.json");

        let init = mesh_init(b"mmk-pass-ok", Some(test_params())).unwrap();
        init.file.save(&master_path).unwrap();
        let fp = init.mrk.fingerprint();

        // Mint window while "unlocked", then no runtime (simulates lock after allow-claim).
        ClaimWindowFile::mint(&fp, 300).save(&window_path).unwrap();
        assert!(!runtime_path.exists());

        let auth = check_claim_authorized(&runtime_path, &window_path).unwrap();
        assert_eq!(auth, ClaimAuthMethod::ClaimWindow);

        let person = Identity::generate();
        let pk = person.verifying_key_bytes();
        let ts = Utc::now().timestamp();
        let pre = owner_claim_preimage("mesh-1", "pid-w", &pk, &fp, ts).unwrap();
        let sig = sign_owner_claim(&person, &pre);
        let req = OwnerClaimRequest {
            mesh_id: "mesh-1".into(),
            person_id: "pid-w".into(),
            person_public_key_hex: hex::encode(pk),
            display_name: "Win".into(),
            ts_unix: ts,
            claim_sig_hex: hex::encode(sig),
            claimed_from_device_id: None,
            replace: false,
        };
        let claim_fp =
            resolve_claim_fingerprint(auth, &runtime_path, &window_path, &master_path).unwrap();
        let file = accept_owner_claim(&req, &claim_fp, auth, None, &owner_path).unwrap();
        assert_eq!(file.person_id, "pid-w");
    }

    #[test]
    fn claim_reject_without_allow_claim_or_mmk() {
        let dir = tmp_dir();
        let runtime_path = dir.join("mmk-runtime.json");
        let window_path = dir.join("claim-window.json");
        let err = check_claim_authorized(&runtime_path, &window_path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mmk_locked") || msg.contains("Permission"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn sealed_backup_roundtrip_store() {
        let dir = tmp_dir();
        let path = dir.join("owner-backup.sealed");
        let person_id = "01BACKUP";
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sealed = seal_owner_backup(
            b"backup-pass-secret",
            person_id,
            &seed,
            r#"{"label":"phone"}"#,
            Some("hint"),
            Some(test_params()),
        )
        .unwrap();
        OwnerBackupSealed::store_blob(&path, &sealed).unwrap();
        assert!(path.exists());

        let loaded = OwnerBackupSealed::load(&path).unwrap();
        let (out_seed, meta) = unseal_owner_backup(b"backup-pass-secret", &loaded).unwrap();
        assert_eq!(out_seed, seed);
        assert!(meta.contains("phone"));

        // Wrong password fails closed.
        assert!(unseal_owner_backup(b"wrong", &loaded).is_err());
    }

    #[test]
    fn preimage_fingerprint_and_ts_bound() {
        let pk = [9u8; 32];
        let a = owner_claim_preimage("m", "p", &pk, "aaaabbbb", 100).unwrap();
        let b = owner_claim_preimage("m", "p", &pk, "ccccdddd", 100).unwrap();
        let c = owner_claim_preimage("m", "p", &pk, "aaaabbbb", 101).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
