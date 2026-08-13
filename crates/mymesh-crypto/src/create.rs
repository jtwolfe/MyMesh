//! First-mesh create window + recovery-once delivery (Wave F7).
//!
//! Phone never receives MMK. `allow-create` (or TUI) mints a 0600 window on the
//! box; `POST /meshes` / `mesh init` wrap a new MRK only when `mesh-master.json`
//! is absent.

use crate::master_key::{
    mesh_init, KdfParams, MeshInitResult, MeshMasterFile, MmkRuntime, RecoveryCode,
};
use crate::Identity;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mymesh_core::{write_init_primary, Capability, DeviceStore, Error, MeshState, Paths, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

/// MMK-authorized first-create window (mode 0600). Minted by
/// `mymesh mesh allow-create` or the TUI password modal.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateWindowFile {
    pub until: DateTime<Utc>,
    pub nonce: String,
    pub authorized_at: DateTime<Utc>,
    #[serde(default)]
    pub secs: u64,
    /// Operator-chosen MMK password. Absent → POST generates one into recovery-once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Tests only — production CLI never writes this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<KdfParams>,
}

impl fmt::Debug for CreateWindowFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateWindowFile")
            .field("until", &self.until)
            .field("nonce", &self.nonce)
            .field("authorized_at", &self.authorized_at)
            .field("secs", &self.secs)
            .field("has_password", &self.password.is_some())
            .field("kdf_params", &self.kdf_params)
            .finish()
    }
}

impl Drop for CreateWindowFile {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.password {
            p.zeroize();
        }
    }
}

impl CreateWindowFile {
    pub fn mint(secs: u64, password: Option<String>) -> Self {
        let secs = secs.clamp(1, 24 * 3600);
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Self {
            until: Utc::now() + Duration::seconds(secs as i64),
            nonce: hex::encode(nonce),
            authorized_at: Utc::now(),
            secs,
            password: password.filter(|s| !s.is_empty()),
            kdf_params: None,
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

/// How first-create was authorized on the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateAuthMethod {
    CreateWindow,
}

/// Load a still-valid create window. Missing / expired fail closed.
pub fn check_create_authorized(
    create_window_path: impl AsRef<Path>,
) -> Result<(CreateAuthMethod, CreateWindowFile)> {
    match CreateWindowFile::try_load(create_window_path)? {
        Some(win) if win.is_valid_now() => Ok((CreateAuthMethod::CreateWindow, win)),
        Some(_) => Err(Error::PermissionDenied(
            "create window expired — run mymesh mesh allow-create".into(),
        )),
        None => Err(Error::PermissionDenied(
            "create_window_required: run mymesh mesh allow-create --secs 300 or enter password in TUI"
                .into(),
        )),
    }
}

/// Result of first mesh init (codes must be shown once; never logged).
pub struct FirstMeshInit {
    pub init: MeshInitResult,
    pub mesh_id: String,
    pub display_name: String,
    pub created_on: String,
    /// Set only when the node generated the daily password (no operator password).
    pub generated_password: Option<String>,
}

impl fmt::Debug for FirstMeshInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstMeshInit")
            .field("mesh_id", &self.mesh_id)
            .field("display_name", &self.display_name)
            .field("created_on", &self.created_on)
            .field("has_generated_password", &self.generated_password.is_some())
            .field("recovery_code_count", &self.init.recovery_codes.len())
            .finish()
    }
}

impl Drop for FirstMeshInit {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.generated_password {
            p.zeroize();
        }
    }
}

/// Wrap a new MRK, write `mesh-master.json`, set `mesh.json` display name,
/// and persist a single primary `mesh-memberships.json` row.
///
/// Refuses if `mesh-master.json` already exists (`mesh_already_inited`).
pub fn apply_first_mesh_init(
    paths: &Paths,
    password: &[u8],
    display_name: &str,
    params: Option<KdfParams>,
    keep_unlocked: bool,
) -> Result<FirstMeshInit> {
    if MeshMasterFile::exists(paths.mesh_master_file()) {
        return Err(Error::PermissionDenied("mesh_already_inited".into()));
    }
    if password.is_empty() {
        return Err(Error::MasterKey("password must not be empty".into()));
    }
    let name = sanitize_display_name(display_name)?;
    paths.ensure()?;
    let init = mesh_init(password, params)?;
    init.file.save(paths.mesh_master_file())?;

    let identity = Identity::load_or_create(paths.identity_file())?;
    let mut mesh = MeshState::load(paths.mesh_file())?;
    mesh.mrk_fingerprint = Some(init.file.mrk_fingerprint.clone());
    mesh.creator_device_id = Some(identity.device_id());
    mesh.display_name = Some(name.clone());
    mesh.save(paths.mesh_file())?;

    write_init_primary(paths.mesh_memberships_file(), &mesh.mesh_id)?;

    if let Ok(mut store) = DeviceStore::open(paths.devices_file()) {
        if let Some(mut rec) = store.get(&identity.device_id()).cloned() {
            if !rec.capabilities.contains(&Capability::Admin) {
                rec.capabilities.push(Capability::Admin);
            }
            rec.mesh_id = Some(mesh.mesh_id.clone());
            rec.mesh_role = mymesh_core::MeshRole::Member;
            let _ = store.upsert(rec);
        }
    }

    if keep_unlocked {
        MmkRuntime::from_mrk(&init.mrk).save(paths.mmk_runtime_file())?;
    } else {
        let _ = MmkRuntime::clear(paths.mmk_runtime_file());
    }

    let created_on = mesh.created_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    Ok(FirstMeshInit {
        init,
        mesh_id: mesh.mesh_id,
        display_name: name,
        created_on,
        generated_password: None,
    })
}

/// Generate a 256-bit hex daily password (never logged).
pub fn generate_mmk_password() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Write one-shot recovery material (0600). Never log `body`.
pub fn write_recovery_once(
    path: impl AsRef<Path>,
    codes: &[RecoveryCode],
    generated_password: Option<&str>,
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = String::from(
        "# mesh-recovery-once.txt — save offline, then delete (or run mymesh mesh recovery-show-once)\n\
         # Never share. Never commit. This file is mode 0600.\n",
    );
    if let Some(pw) = generated_password.filter(|s| !s.is_empty()) {
        body.push_str("# Daily MMK password (generated on this box):\n");
        body.push_str(pw);
        body.push('\n');
    }
    body.push_str("# Recovery codes (256-bit hex; one code recovers the master):\n");
    for (i, code) in codes.iter().enumerate() {
        body.push_str(&format!("{:>2}.  {}\n", i + 1, code.display_hex()));
    }
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    // Best-effort wipe of the in-memory copy we just wrote.
    body.zeroize();
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Read and delete `mesh-recovery-once.txt`. `None` if missing.
pub fn take_recovery_once(path: impl AsRef<Path>) -> Result<Option<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    std::fs::remove_file(path)?;
    Ok(Some(raw))
}

pub fn sanitize_display_name(name: &str) -> Result<String> {
    let t = name.trim();
    if t.is_empty() {
        return Err(Error::Config("display_name required".into()));
    }
    if t.len() > 64 {
        return Err(Error::Config("display_name must be ≤ 64 bytes".into()));
    }
    if t.chars().any(|c| c.is_control()) {
        return Err(Error::Config(
            "display_name must not contain control chars".into(),
        ));
    }
    Ok(t.to_string())
}

/// Heartbeat so HTTP init can detect a live TUI (best-effort).
pub fn mark_tui_attached(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"1")?;
    Ok(())
}

pub fn clear_tui_attached(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn tui_is_attached(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return path.exists();
    };
    match std::time::SystemTime::now().duration_since(modified) {
        Ok(age) => age.as_secs() < 300,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths() -> Paths {
        let mut n = [0u8; 8];
        OsRng.fill_bytes(&mut n);
        let root = std::env::temp_dir().join(format!(
            "mymesh-create-{}-{}",
            std::process::id(),
            u64::from_le_bytes(n)
        ));
        let paths = Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        };
        paths.ensure().unwrap();
        paths
    }

    fn test_params() -> KdfParams {
        KdfParams {
            m: 64_000,
            t: 2,
            p: 1,
        }
    }

    #[test]
    fn window_debug_redacts_password() {
        let w = CreateWindowFile::mint(60, Some("super-secret".into()));
        let d = format!("{w:?}");
        assert!(!d.contains("super-secret"));
        assert!(d.contains("has_password: true"));
    }

    #[test]
    fn first_init_then_refuse() {
        let paths = tmp_paths();
        let first = apply_first_mesh_init(
            &paths,
            b"test-mmk-password-ok",
            "Home",
            Some(test_params()),
            false,
        )
        .unwrap();
        assert_eq!(first.display_name, "Home");
        assert!(MeshMasterFile::exists(paths.mesh_master_file()));
        let cat = mymesh_core::MembershipCatalog::try_load(paths.mesh_memberships_file())
            .unwrap()
            .unwrap();
        assert_eq!(cat.file().primary_mesh_id, first.mesh_id);
        assert_eq!(cat.file().memberships[0].source, "init");

        let err = apply_first_mesh_init(
            &paths,
            b"test-mmk-password-ok",
            "Studio",
            Some(test_params()),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mesh_already_inited"));
        let _ = std::fs::remove_dir_all(paths.data_dir.parent().unwrap());
    }

    #[test]
    fn recovery_once_write_take() {
        let paths = tmp_paths();
        let codes = crate::generate_recovery_codes(2);
        write_recovery_once(
            paths.mesh_recovery_once_file(),
            &codes,
            Some("generated-pw"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.mesh_recovery_once_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let shown = take_recovery_once(paths.mesh_recovery_once_file())
            .unwrap()
            .unwrap();
        assert!(shown.contains(&codes[0].display_hex()));
        assert!(shown.contains("generated-pw"));
        assert!(take_recovery_once(paths.mesh_recovery_once_file())
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(paths.data_dir.parent().unwrap());
    }
}
