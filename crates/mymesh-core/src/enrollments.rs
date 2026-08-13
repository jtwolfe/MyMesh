//! Enrollment store (`enrollments.json` mode 0600).
//!
//! Host-local `mymesh enroll add` verifies `carrier-enroll-v1` and writes a
//! row. HTTP decide / POST /enrollments reuse this store.
use crate::wire::{
    enroll_write_preimage, EnrollWriteBody, EnrollmentRecord, EnrollmentsFile, PersonFacet,
    ENROLLMENTS_FILE_VERSION,
};
use crate::{DeviceId, Error, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::{Path, PathBuf};

/// Quantified budget: enrollments per node (CARRIER-ADMIN-NEXT).
pub const MAX_ENROLLMENTS: usize = 8;

/// On-disk person drive bindings under agent Paths (`enrollments.json`, mode 0600).
#[derive(Debug)]
pub struct EnrollmentStore {
    path: PathBuf,
    file: EnrollmentsFile,
}

impl EnrollmentStore {
    /// Load existing file, or an empty in-memory store if missing. Does not write.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: EnrollmentsFile = serde_json::from_str(&raw)?;
            if file.version != ENROLLMENTS_FILE_VERSION {
                return Err(Error::Config(format!(
                    "unsupported enrollments.json version {}",
                    file.version
                )));
            }
            file
        } else {
            EnrollmentsFile {
                version: ENROLLMENTS_FILE_VERSION,
                enrollments: Vec::new(),
            }
        };
        Ok(Self { path, file })
    }

    /// Like [`open`], and persist an empty schema-v1 file (0600) when missing.
    /// Serve / agent start uses this so the path exists without writing a pair enroll.
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let store = Self::open(path)?;
        if !store.path.exists() {
            store.flush()?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list(&self) -> Vec<&EnrollmentRecord> {
        let mut v: Vec<_> = self.file.enrollments.iter().collect();
        v.sort_by(|a, b| {
            a.enrolled_at
                .cmp(&b.enrolled_at)
                .then(a.person_id.cmp(&b.person_id))
        });
        v
    }

    pub fn get(&self, person_id: &str) -> Option<&EnrollmentRecord> {
        self.file
            .enrollments
            .iter()
            .find(|e| e.person_id == person_id)
    }

    /// True when this person has a row with `can_drive`.
    pub fn can_drive(&self, person_id: &str) -> bool {
        self.get(person_id).is_some_and(|e| e.can_drive)
    }

    /// Verify `carrier-enroll-v1` against `target_did` (this node) and upsert.
    ///
    /// Fail closed: bad / unknown facet is rejected by wire parse; bad sig,
    /// `target_did` mismatch, or malformed preimage fields do not write.
    pub fn add(
        &mut self,
        target_did: &DeviceId,
        body: &EnrollWriteBody,
    ) -> Result<EnrollmentRecord> {
        let rec = verify_enroll_write(target_did, body)?;
        if let Some(pos) = self
            .file
            .enrollments
            .iter()
            .position(|e| e.person_id == rec.person_id)
        {
            self.file.enrollments[pos] = rec.clone();
        } else {
            if self.file.enrollments.len() >= MAX_ENROLLMENTS {
                return Err(Error::Config(format!(
                    "enrollments budget is {MAX_ENROLLMENTS} persons"
                )));
            }
            self.file.enrollments.push(rec.clone());
        }
        self.flush()?;
        Ok(rec)
    }

    /// Drop the person row (host-local revoke). Idempotent-not: missing → NotFound.
    pub fn revoke(&mut self, person_id: &str) -> Result<EnrollmentRecord> {
        let pos = self
            .file
            .enrollments
            .iter()
            .position(|e| e.person_id == person_id)
            .ok_or_else(|| Error::NotFound(format!("enrollment {person_id}")))?;
        let mut rec = self.file.enrollments.remove(pos);
        rec.can_drive = false;
        self.flush()?;
        Ok(rec)
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(&self.file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Verify body against this node's device id. Does not persist.
pub fn verify_enroll_write(
    target_did: &DeviceId,
    body: &EnrollWriteBody,
) -> Result<EnrollmentRecord> {
    let claimed = crate::wire::parse_id32_hex(&body.target_device_id_hex)
        .map_err(|e| Error::PermissionDenied(e.to_string()))?;
    if &claimed != target_did.as_bytes() {
        return Err(Error::PermissionDenied(
            "target_device_id_hex is not this node".into(),
        ));
    }
    let pre = enroll_write_preimage(body).map_err(|e| Error::PermissionDenied(e.to_string()))?;
    let pk = crate::wire::parse_id32_hex(&body.person_public_key_hex)
        .map_err(|e| Error::PermissionDenied(e.to_string()))?;
    let sig = parse_sig64_hex(&body.sig_hex)?;
    verify_ed25519(&pk, &pre, &sig)?;
    Ok(EnrollmentRecord {
        enrollment_id: new_enrollment_id(),
        person_id: body.person_id.clone(),
        person_public_key_hex: hex::encode(pk),
        facet: body.facet,
        enrolled_at: body.ts.clone(),
        can_drive: true,
        label: body.label.clone(),
    })
}

fn verify_ed25519(person_pk: &[u8; 32], preimage: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(person_pk)
        .map_err(|_| Error::PermissionDenied("invalid person public key".into()))?;
    let signature = Signature::from_bytes(sig);
    vk.verify(preimage, &signature)
        .map_err(|_| Error::PermissionDenied("bad enroll signature".into()))
}

fn parse_sig64_hex(sig_hex: &str) -> Result<[u8; 64]> {
    let t: String = sig_hex.chars().filter(|c| !c.is_whitespace()).collect();
    if t.len() != 128 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::PermissionDenied(
            "sig_hex must be 128 hex chars (64 bytes)".into(),
        ));
    }
    let bytes = hex::decode(&t).map_err(|_| Error::PermissionDenied("invalid sig_hex".into()))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn new_enrollment_id() -> String {
    crate::new_grant_id()
}

/// Parse `--sig-file`: 128 hex chars (whitespace ignored) or raw 64 bytes.
pub fn read_enroll_sig_hex(path: impl AsRef<Path>) -> Result<String> {
    let raw = std::fs::read(path.as_ref())?;
    if raw.len() == 64 {
        return Ok(hex::encode(raw));
    }
    let s = std::str::from_utf8(&raw)
        .map_err(|_| Error::PermissionDenied("sig-file is not 64 raw bytes or hex".into()))?;
    let hex_s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let _ = parse_sig64_hex(&hex_s)?;
    Ok(hex_s.to_ascii_lowercase())
}

pub fn parse_enroll_facet(s: &str) -> Result<PersonFacet> {
    PersonFacet::parse(s.trim())
        .ok_or_else(|| Error::Config(format!("unknown facet '{}' (want personal|work)", s.trim())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_base64url, encode_hex, PersonFacet};
    use ed25519_dalek::{Signer, SigningKey};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-enroll-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn target() -> DeviceId {
        DeviceId::from_bytes([0xa1u8; 32])
    }

    fn sign_body(sk: &SigningKey, body: &mut EnrollWriteBody) {
        let pre = enroll_write_preimage(body).unwrap();
        body.sig_hex = encode_hex(&sk.sign(&pre).to_bytes());
    }

    fn signed_body(sk: &SigningKey, person_id: &str) -> EnrollWriteBody {
        let mut body = EnrollWriteBody {
            person_id: person_id.into(),
            facet: PersonFacet::Personal,
            target_device_id_hex: hex::encode(target().as_bytes()),
            ts: "2026-08-13T12:00:00Z".into(),
            nonce: encode_base64url(&[0x33u8; 16]),
            person_public_key_hex: hex::encode(sk.verifying_key().to_bytes()),
            sig_hex: String::new(),
            label: Some("kitchen-phone".into()),
        };
        sign_body(sk, &mut body);
        body
    }

    #[test]
    fn open_missing_is_empty() {
        let dir = temp_dir("missing");
        let path = dir.join("enrollments.json");
        let store = EnrollmentStore::open(&path).unwrap();
        assert!(store.list().is_empty());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_or_create_writes_empty_0600() {
        let dir = temp_dir("create");
        let path = dir.join("enrollments.json");
        let store = EnrollmentStore::open_or_create(&path).unwrap();
        assert!(path.exists());
        assert!(store.list().is_empty());
        let parsed: EnrollmentsFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.version, ENROLLMENTS_FILE_VERSION);
        assert!(parsed.enrollments.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn add_list_revoke_roundtrip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("enrollments.json");
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let body = signed_body(&sk, "01HZXPERSON0000000000000");
        let mut store = EnrollmentStore::open(&path).unwrap();
        let rec = store.add(&target(), &body).unwrap();
        assert!(rec.can_drive);
        assert_eq!(rec.person_id, body.person_id);
        assert_eq!(rec.facet, PersonFacet::Personal);
        assert_eq!(store.list().len(), 1);
        assert!(store.can_drive(&body.person_id));

        let store2 = EnrollmentStore::open(&path).unwrap();
        let loaded = store2.get(&body.person_id).unwrap();
        assert_eq!(loaded.enrollment_id, rec.enrollment_id);
        assert_eq!(loaded.label.as_deref(), Some("kitchen-phone"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let mut store3 = EnrollmentStore::open(&path).unwrap();
        let revoked = store3.revoke(&body.person_id).unwrap();
        assert!(!revoked.can_drive);
        assert!(store3.get(&body.person_id).is_none());
        assert!(!store3.can_drive(&body.person_id));
        assert!(store3.list().is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bad_sig_rejected_no_write() {
        let dir = temp_dir("badsig");
        let path = dir.join("enrollments.json");
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let mut body = signed_body(&sk, "pid-bad");
        // flip one nibble
        let last = body.sig_hex.pop().unwrap();
        body.sig_hex.push(if last == '0' { '1' } else { '0' });
        let mut store = EnrollmentStore::open(&path).unwrap();
        let err = store.add(&target(), &body).unwrap_err();
        assert!(
            err.to_string().contains("signature") || err.to_string().contains("denied"),
            "{err}"
        );
        assert!(!path.exists());
        assert!(store.list().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_target_rejected() {
        let dir = temp_dir("target");
        let path = dir.join("enrollments.json");
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let body = signed_body(&sk, "pid-tgt");
        let other = DeviceId::from_bytes([0xb2u8; 32]);
        let mut store = EnrollmentStore::open(&path).unwrap();
        let err = store.add(&other, &body).unwrap_err();
        assert!(err.to_string().contains("not this node"), "{err}");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn f1_golden_body_verifies() {
        let dir = temp_dir("golden");
        let path = dir.join("enrollments.json");
        let raw = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/wire/carrier-enroll-v1.json"),
        )
        .unwrap();
        let body: EnrollWriteBody = serde_json::from_str(&raw).unwrap();
        let mut store = EnrollmentStore::open(&path).unwrap();
        let rec = store.add(&target(), &body).unwrap();
        assert_eq!(rec.person_id, "01HZXPERSON0000000000000");
        assert_eq!(rec.facet, PersonFacet::Personal);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn enrollments_file_path() {
        let paths = crate::Paths {
            config_dir: PathBuf::from("/tmp/cfg"),
            data_dir: PathBuf::from("/tmp/data"),
            cache_dir: PathBuf::from("/tmp/cache"),
        };
        assert_eq!(
            paths.enrollments_file(),
            PathBuf::from("/tmp/data/enrollments.json")
        );
    }

    #[test]
    fn read_sig_file_hex_or_raw() {
        let dir = temp_dir("sigfile");
        let hex_path = dir.join("sig.hex");
        let raw_path = dir.join("sig.bin");
        let sig = [0xabu8; 64];
        std::fs::write(&hex_path, format!("{}\n", encode_hex(&sig))).unwrap();
        std::fs::write(&raw_path, sig).unwrap();
        assert_eq!(read_enroll_sig_hex(&hex_path).unwrap(), encode_hex(&sig));
        assert_eq!(read_enroll_sig_hex(&raw_path).unwrap(), encode_hex(&sig));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_version_fail_closed() {
        let dir = temp_dir("ver");
        let path = dir.join("enrollments.json");
        std::fs::write(&path, "{\"version\":99,\"enrollments\":[]}\n").unwrap();
        let err = EnrollmentStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
