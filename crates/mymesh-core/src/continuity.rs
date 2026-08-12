//! Continuity pack host storage (S8): materialize / wipe / status.
//!
//! Layout under `paths.data_dir/continuity/<pack_id>/` (mode **0700**):
//!
//! ```text
//! state.json   # { pack_id, status, wipe_token_hash, manifest, host_device_id_hex, ... }
//! fields.json  # decrypted fields JSON (mode 0600; present only when status=present)
//! pack.json    # original ContinuityPack envelope (mode 0600; no pack_key in clear)
//! ```
//!
//! Wipe: best-effort zero-overwrite of secrets + unlink; leave status=`wiped`.
//! Forensic-secure erase is **not** guaranteed on all filesystems.

use crate::{Error, Paths, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// On-disk pack presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityHostStatus {
    Present,
    Wiped,
    Absent,
}

impl ContinuityHostStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Wiped => "wiped",
            Self::Absent => "absent",
        }
    }
}

/// Manifest subset stored on host (mirrors wire; not secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityHostManifest {
    pub label: String,
    pub created_at: String,
    pub person_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet_id: Option<String>,
    #[serde(default)]
    pub fields_summary: Vec<String>,
    pub byte_length: u64,
}

/// Persisted host state for one pack (mode 0600).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuityHostState {
    pub pack_id: String,
    pub version: u32,
    pub status: ContinuityHostStatus,
    pub wipe_token_hash: String,
    pub host_device_id_hex: String,
    pub manifest: ContinuityHostManifest,
    pub materialized_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiped_at: Option<DateTime<Utc>>,
}

/// Result of materialize.
#[derive(Clone, Debug)]
pub struct MaterializeResult {
    pub pack_id: String,
    pub status: ContinuityHostStatus,
    /// Relative path hint under data_dir (e.g. `continuity/<id>/`).
    pub path_hint: String,
    pub pack_dir: PathBuf,
}

/// Validate pack_id for path use (no traversal).
pub fn validate_pack_id(pack_id: &str) -> Result<()> {
    let t = pack_id.trim();
    if t.is_empty() || t.len() > 64 {
        return Err(Error::Config("pack_id must be 1..=64 chars".into()));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Error::Config("pack_id has invalid characters".into()));
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    set_mode(path, 0o600);
    Ok(())
}

fn ensure_pack_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    set_mode(dir, 0o700);
    // Also lock down root continuity/ when created as parent.
    if let Some(parent) = dir.parent() {
        set_mode(parent, 0o700);
    }
    Ok(())
}

fn state_path(pack_dir: &Path) -> PathBuf {
    pack_dir.join("state.json")
}

fn fields_path(pack_dir: &Path) -> PathBuf {
    pack_dir.join("fields.json")
}

fn pack_json_path(pack_dir: &Path) -> PathBuf {
    pack_dir.join("pack.json")
}

/// Best-effort: overwrite file with zeros once, fsync, unlink.
fn secure_unlink(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(path)?.len() as usize;
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; len.clamp(1, 1024 * 1024)];
        let mut remaining = len;
        f.seek(SeekFrom::Start(0))?;
        while remaining > 0 {
            let n = remaining.min(zeros.len());
            f.write_all(&zeros[..n])?;
            remaining -= n;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    if let Some(parent) = path.parent() {
        // Best-effort fsync parent dir (Unix).
        #[cfg(unix)]
        {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
        }
    }
    Ok(())
}

/// Inputs for [`materialize_pack`].
pub struct MaterializeInput<'a> {
    pub pack_id: &'a str,
    pub version: u32,
    pub wipe_token_hash: &'a str,
    pub host_device_id_hex: &'a str,
    pub manifest: ContinuityHostManifest,
    pub fields_json: &'a [u8],
    pub pack_envelope_json: &'a [u8],
}

/// Materialize decrypted fields + state under `paths.continuity_pack_dir(pack_id)`.
///
/// Caller must have already opened the pack with the host private key.
pub fn materialize_pack(paths: &Paths, input: MaterializeInput<'_>) -> Result<MaterializeResult> {
    validate_pack_id(input.pack_id)?;
    if input.wipe_token_hash.trim().is_empty() {
        return Err(Error::Config("wipe_token_hash required".into()));
    }
    if input.fields_json.is_empty() {
        return Err(Error::Config("fields_json must not be empty".into()));
    }

    let pack_dir = paths.continuity_pack_dir(input.pack_id);
    ensure_pack_dir(&pack_dir)?;

    // If already present, reject overwrite (re-materialize only after wipe).
    let existing = status_pack(paths, input.pack_id)?;
    if existing == ContinuityHostStatus::Present {
        return Err(Error::Config(format!(
            "pack {} already present; wipe first",
            input.pack_id
        )));
    }

    write_file_0600(&fields_path(&pack_dir), input.fields_json)?;
    write_file_0600(&pack_json_path(&pack_dir), input.pack_envelope_json)?;

    let state = ContinuityHostState {
        pack_id: input.pack_id.to_string(),
        version: input.version,
        status: ContinuityHostStatus::Present,
        wipe_token_hash: input.wipe_token_hash.to_string(),
        host_device_id_hex: input.host_device_id_hex.to_ascii_lowercase(),
        manifest: input.manifest,
        materialized_at: Utc::now(),
        wiped_at: None,
    };
    let state_raw = serde_json::to_vec_pretty(&state)?;
    write_file_0600(&state_path(&pack_dir), &state_raw)?;

    Ok(MaterializeResult {
        pack_id: input.pack_id.to_string(),
        status: ContinuityHostStatus::Present,
        path_hint: format!("continuity/{}/", input.pack_id),
        pack_dir,
    })
}

/// Read host status for a pack id.
pub fn status_pack(paths: &Paths, pack_id: &str) -> Result<ContinuityHostStatus> {
    validate_pack_id(pack_id)?;
    let pack_dir = paths.continuity_pack_dir(pack_id);
    if !pack_dir.exists() {
        return Ok(ContinuityHostStatus::Absent);
    }
    let sp = state_path(&pack_dir);
    if !sp.exists() {
        // Directory without state — treat as absent / incomplete.
        if fields_path(&pack_dir).exists() {
            return Ok(ContinuityHostStatus::Present);
        }
        return Ok(ContinuityHostStatus::Absent);
    }
    let raw = fs::read(&sp)?;
    let state: ContinuityHostState = serde_json::from_slice(&raw)?;
    Ok(state.status)
}

/// Load full host state if directory exists.
pub fn load_state(paths: &Paths, pack_id: &str) -> Result<Option<ContinuityHostState>> {
    validate_pack_id(pack_id)?;
    let sp = state_path(&paths.continuity_pack_dir(pack_id));
    if !sp.exists() {
        return Ok(None);
    }
    let raw = fs::read(&sp)?;
    let state: ContinuityHostState = serde_json::from_slice(&raw)?;
    Ok(Some(state))
}

/// Read materialized fields JSON (errors if not present).
pub fn read_fields(paths: &Paths, pack_id: &str) -> Result<Vec<u8>> {
    validate_pack_id(pack_id)?;
    let fp = fields_path(&paths.continuity_pack_dir(pack_id));
    if !fp.exists() {
        return Err(Error::NotFound(format!(
            "continuity fields for pack {pack_id}"
        )));
    }
    Ok(fs::read(fp)?)
}

/// Wipe pack secrets. Leaves status=`wiped` marker; removes fields + pack envelope.
///
/// Does **not** verify wipe_token — caller must authorize.
pub fn wipe_pack(paths: &Paths, pack_id: &str) -> Result<ContinuityHostStatus> {
    validate_pack_id(pack_id)?;
    let pack_dir = paths.continuity_pack_dir(pack_id);
    if !pack_dir.exists() {
        return Ok(ContinuityHostStatus::Absent);
    }

    // Zero + unlink secrets first.
    let _ = secure_unlink(&fields_path(&pack_dir));
    let _ = secure_unlink(&pack_json_path(&pack_dir));

    // Update or create wiped state (retain wipe_token_hash for late token checks).
    let mut state = match load_state(paths, pack_id)? {
        Some(mut s) => {
            s.status = ContinuityHostStatus::Wiped;
            s.wiped_at = Some(Utc::now());
            s
        }
        None => ContinuityHostState {
            pack_id: pack_id.to_string(),
            version: 1,
            status: ContinuityHostStatus::Wiped,
            wipe_token_hash: String::new(),
            host_device_id_hex: String::new(),
            manifest: ContinuityHostManifest {
                label: String::new(),
                created_at: String::new(),
                person_id: String::new(),
                facet_id: None,
                fields_summary: vec![],
                byte_length: 0,
            },
            materialized_at: Utc::now(),
            wiped_at: Some(Utc::now()),
        },
    };

    let raw = serde_json::to_vec_pretty(&state)?;
    write_file_0600(&state_path(&pack_dir), &raw)?;
    // Ensure no residual fields.
    let _ = secure_unlink(&fields_path(&pack_dir));

    // Clear hash from memory copy (state on disk still has it for token verify-on-wipe races).
    state.wipe_token_hash.clear();

    Ok(ContinuityHostStatus::Wiped)
}

/// Stored wipe_token_hash for a present (or wiped) pack, if known.
pub fn wipe_token_hash_for(paths: &Paths, pack_id: &str) -> Result<Option<String>> {
    Ok(load_state(paths, pack_id)?.map(|s| s.wipe_token_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_paths() -> Paths {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mymesh-cont-{n}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        }
    }

    #[test]
    fn materialize_status_wipe() {
        let paths = tmp_paths();
        paths.ensure().unwrap();
        let pack_id = "01TESTPACK0000000000000000";
        let manifest = ContinuityHostManifest {
            label: "hotel bag".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            person_id: "01PERSON".into(),
            facet_id: None,
            fields_summary: vec!["profile".into()],
            byte_length: 12,
        };
        let fields = br#"{"profile":"Ada"}"#;
        let envelope = br#"{"pack_id":"01TESTPACK0000000000000000","version":1}"#;

        assert_eq!(
            status_pack(&paths, pack_id).unwrap(),
            ContinuityHostStatus::Absent
        );

        let r = materialize_pack(
            &paths,
            MaterializeInput {
                pack_id,
                version: 1,
                wipe_token_hash: &"ab".repeat(32),
                host_device_id_hex: &"cd".repeat(32),
                manifest,
                fields_json: fields,
                pack_envelope_json: envelope,
            },
        )
        .unwrap();
        assert_eq!(r.status, ContinuityHostStatus::Present);
        assert!(r.pack_dir.exists());
        assert_eq!(
            status_pack(&paths, pack_id).unwrap(),
            ContinuityHostStatus::Present
        );
        assert_eq!(read_fields(&paths, pack_id).unwrap(), fields);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&r.pack_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        // Duplicate materialize fails.
        assert!(materialize_pack(
            &paths,
            MaterializeInput {
                pack_id,
                version: 1,
                wipe_token_hash: &"ab".repeat(32),
                host_device_id_hex: &"cd".repeat(32),
                manifest: ContinuityHostManifest {
                    label: "x".into(),
                    created_at: "t".into(),
                    person_id: "p".into(),
                    facet_id: None,
                    fields_summary: vec![],
                    byte_length: 1,
                },
                fields_json: fields,
                pack_envelope_json: envelope,
            },
        )
        .is_err());

        let st = wipe_pack(&paths, pack_id).unwrap();
        assert_eq!(st, ContinuityHostStatus::Wiped);
        assert_eq!(
            status_pack(&paths, pack_id).unwrap(),
            ContinuityHostStatus::Wiped
        );
        assert!(read_fields(&paths, pack_id).is_err());
        assert!(!fields_path(&paths.continuity_pack_dir(pack_id)).exists());

        // Wipe absent → absent.
        let paths2 = tmp_paths();
        paths2.ensure().unwrap();
        assert_eq!(
            wipe_pack(&paths2, pack_id).unwrap(),
            ContinuityHostStatus::Absent
        );

        let _ = fs::remove_dir_all(paths.data_dir.parent().unwrap());
        let _ = fs::remove_dir_all(paths2.data_dir.parent().unwrap());
    }

    #[test]
    fn pack_id_rejects_traversal() {
        assert!(validate_pack_id("../x").is_err());
        assert!(validate_pack_id("a/b").is_err());
        assert!(validate_pack_id("ok-pack_1").is_ok());
    }
}
