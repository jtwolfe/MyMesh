//! This-node membership catalog (`mesh-memberships.json`, mode 0600).
//!
//! F7 writes a single primary row at first mesh init. Guest overlap is F8.

use crate::wire::{
    CatalogMembership, CatalogRole, MeshMembershipsFile, MESH_MEMBERSHIPS_FILE_VERSION,
};
use crate::{Error, Result};
use chrono::{SecondsFormat, Utc};
use std::path::{Path, PathBuf};

/// Persist / load this node's membership catalog.
#[derive(Debug)]
pub struct MembershipCatalog {
    path: PathBuf,
    file: MeshMembershipsFile,
}

impl MembershipCatalog {
    /// Load existing file, or `None` if missing.
    pub fn try_load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)?;
        let file: MeshMembershipsFile = serde_json::from_str(&raw)?;
        if file.version != MESH_MEMBERSHIPS_FILE_VERSION {
            return Err(Error::Config(format!(
                "unsupported mesh-memberships.json version {}",
                file.version
            )));
        }
        Ok(Some(Self { path, file }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self) -> &MeshMembershipsFile {
        &self.file
    }
}

/// Write (or replace) the single primary `source=init` row for first mesh init.
///
/// F7 is first-init only: one primary membership. F8 may add guest rows later.
pub fn write_init_primary(path: impl AsRef<Path>, mesh_id: &str) -> Result<MeshMembershipsFile> {
    let mesh_id = mesh_id.trim();
    if mesh_id.is_empty() {
        return Err(Error::Config(
            "mesh_id required for memberships init".into(),
        ));
    }
    let joined_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let file = MeshMembershipsFile {
        version: MESH_MEMBERSHIPS_FILE_VERSION,
        primary_mesh_id: mesh_id.to_string(),
        memberships: vec![CatalogMembership {
            mesh_id: mesh_id.to_string(),
            role: CatalogRole::Member,
            primary: true,
            joined_at,
            via_grant_id: None,
            source: "init".into(),
        }],
    };
    save_memberships(path, &file)?;
    Ok(file)
}

fn save_memberships(path: impl AsRef<Path>, file: &MeshMembershipsFile) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(file)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_init_primary_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-memb-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mesh-memberships.json");
        let file = write_init_primary(&path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(file.primary_mesh_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(file.memberships.len(), 1);
        assert!(file.memberships[0].primary);
        assert_eq!(file.memberships[0].source, "init");
        assert_eq!(file.memberships[0].role, CatalogRole::Member);

        let loaded = MembershipCatalog::try_load(&path).unwrap().unwrap();
        assert_eq!(loaded.file().primary_mesh_id, file.primary_mesh_id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
