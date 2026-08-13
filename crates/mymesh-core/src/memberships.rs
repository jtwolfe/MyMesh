//! Membership catalog (`mesh-memberships.json` mode 0600).
//!
//! Primary row mirrors `mesh.json`. Extra rows this wave are **guest** only
//! (existing Grant). Extra `role=member` is F8b (`not_implemented`).
use crate::wire::{
    CatalogMembership, CatalogRole, MeshMembershipsFile, MESH_MEMBERSHIPS_FILE_VERSION,
};
use crate::{Error, Result};
use chrono::{SecondsFormat, Utc};
use std::path::{Path, PathBuf};

/// Quantified budget: catalog rows per node (CARRIER-ADMIN-NEXT).
pub const MAX_CATALOG_ROWS: usize = 8;

/// `source` for the primary row written from `mesh init` / first migrate.
pub const MEMBERSHIP_SOURCE_INIT: &str = "init";
/// `source` for guest overlap rows.
pub const MEMBERSHIP_SOURCE_OVERLAP: &str = "overlap";

/// On-disk this-node catalog under agent Paths (`mesh-memberships.json`, 0600).
#[derive(Debug)]
pub struct MembershipStore {
    path: PathBuf,
    file: MeshMembershipsFile,
}

impl MembershipStore {
    /// Load existing file. Missing → empty in-memory store (no write).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: MeshMembershipsFile = serde_json::from_str(&raw)?;
            if file.version != MESH_MEMBERSHIPS_FILE_VERSION {
                return Err(Error::Config(format!(
                    "unsupported mesh-memberships.json version {}",
                    file.version
                )));
            }
            file
        } else {
            MeshMembershipsFile {
                version: MESH_MEMBERSHIPS_FILE_VERSION,
                primary_mesh_id: String::new(),
                memberships: Vec::new(),
            }
        };
        Ok(Self { path, file })
    }

    /// Load, or write a single primary row from `mesh.json`'s id (F8 migrate).
    pub fn open_or_migrate(path: impl AsRef<Path>, primary_mesh_id: &str) -> Result<Self> {
        let mut store = Self::open(path)?;
        if store.file.primary_mesh_id.is_empty() || store.file.memberships.is_empty() {
            store.file.primary_mesh_id = primary_mesh_id.to_string();
            if !store
                .file
                .memberships
                .iter()
                .any(|m| m.primary || m.mesh_id == primary_mesh_id)
            {
                store
                    .file
                    .memberships
                    .insert(0, primary_row(primary_mesh_id));
            }
            store.flush()?;
        } else if store.file.primary_mesh_id != primary_mesh_id && !store.has_extra_rows() {
            // mesh.json is source of truth for primary when no overlap extras.
            store.rebind_primary(primary_mesh_id)?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn primary_mesh_id(&self) -> &str {
        &self.file.primary_mesh_id
    }

    pub fn file(&self) -> &MeshMembershipsFile {
        &self.file
    }

    pub fn list(&self) -> Vec<&CatalogMembership> {
        let mut v: Vec<_> = self.file.memberships.iter().collect();
        v.sort_by(|a, b| {
            b.primary
                .cmp(&a.primary)
                .then(a.joined_at.cmp(&b.joined_at))
                .then(a.mesh_id.cmp(&b.mesh_id))
        });
        v
    }

    pub fn get(&self, mesh_id: &str) -> Option<&CatalogMembership> {
        self.file.memberships.iter().find(|m| m.mesh_id == mesh_id)
    }

    /// Any non-primary catalog row (guest overlap this wave).
    pub fn has_extra_rows(&self) -> bool {
        self.file.memberships.iter().any(|m| !m.primary)
    }

    /// True when gossip must not `adopt_mesh_id` a foreign mesh.
    pub fn blocks_adopt(&self, foreign_mesh_id: &str) -> bool {
        self.has_extra_rows() && foreign_mesh_id != self.file.primary_mesh_id
    }

    /// Add a guest overlap row. Extra `role=member` is F8b.
    pub fn add_guest(
        &mut self,
        mesh_id: &str,
        via_grant_id: Option<String>,
    ) -> Result<CatalogMembership> {
        self.add_row(mesh_id, CatalogRole::Guest, via_grant_id)
    }

    /// Insert an extra catalog row. `role=member` extra → not_implemented.
    pub fn add_row(
        &mut self,
        mesh_id: &str,
        role: CatalogRole,
        via_grant_id: Option<String>,
    ) -> Result<CatalogMembership> {
        let mesh_id = mesh_id.trim();
        if mesh_id.is_empty() {
            return Err(Error::Config("mesh_id must not be empty".into()));
        }
        if mesh_id == self.file.primary_mesh_id {
            return Err(Error::Conflict(
                "cannot add extra membership on primary mesh".into(),
            ));
        }
        if role == CatalogRole::Member {
            return Err(Error::NotImplemented(
                "member overlap is F8b (DeviceRecord.memberships)".into(),
            ));
        }
        if let Some(existing) = self.get(mesh_id) {
            return Err(Error::Conflict(format!(
                "membership for {mesh_id} already exists ({})",
                existing.role.as_str()
            )));
        }
        if self.file.memberships.len() >= MAX_CATALOG_ROWS {
            return Err(Error::Config(format!(
                "memberships budget is {MAX_CATALOG_ROWS} rows"
            )));
        }
        let row = CatalogMembership {
            mesh_id: mesh_id.to_string(),
            role: CatalogRole::Guest,
            primary: false,
            joined_at: rfc3339_now(),
            via_grant_id,
            source: MEMBERSHIP_SOURCE_OVERLAP.into(),
        };
        self.file.memberships.push(row.clone());
        self.flush()?;
        Ok(row)
    }

    /// Drop a guest row. Primary cannot be left this way.
    pub fn leave(&mut self, mesh_id: &str) -> Result<CatalogMembership> {
        let mesh_id = mesh_id.trim();
        if mesh_id == self.file.primary_mesh_id {
            return Err(Error::Conflict(
                "cannot leave primary membership (use mesh leave / kick)".into(),
            ));
        }
        let pos = self
            .file
            .memberships
            .iter()
            .position(|m| m.mesh_id == mesh_id)
            .ok_or_else(|| Error::NotFound(format!("membership {mesh_id}")))?;
        if self.file.memberships[pos].primary {
            return Err(Error::Conflict(
                "cannot leave primary membership (use mesh leave / kick)".into(),
            ));
        }
        let row = self.file.memberships.remove(pos);
        self.flush()?;
        Ok(row)
    }

    /// Point the primary row at `new_primary` (after a legal `adopt_mesh_id`).
    pub fn rebind_primary(&mut self, new_primary: &str) -> Result<()> {
        if new_primary == self.file.primary_mesh_id {
            return Ok(());
        }
        self.file.primary_mesh_id = new_primary.to_string();
        if let Some(row) = self.file.memberships.iter_mut().find(|m| m.primary) {
            row.mesh_id = new_primary.to_string();
        } else {
            self.file.memberships.insert(0, primary_row(new_primary));
        }
        self.flush()
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

fn primary_row(mesh_id: &str) -> CatalogMembership {
    CatalogMembership {
        mesh_id: mesh_id.to_string(),
        role: CatalogRole::Member,
        primary: true,
        joined_at: rfc3339_now(),
        via_grant_id: None,
        source: MEMBERSHIP_SOURCE_INIT.into(),
    }
}

fn rfc3339_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Env escape hatch: permit legacy `adopt_mesh_id` smash with extra catalog rows.
pub fn allow_mesh_smash() -> bool {
    std::env::var_os("MYMESH_ALLOW_MESH_SMASH").is_some_and(|v| v == "1")
}

/// True when `mesh-memberships.json` next to `mesh.json` has extras that block smash.
pub fn catalog_blocks_adopt(mesh_path: impl AsRef<Path>, foreign_mesh_id: &str) -> bool {
    let Some(parent) = mesh_path.as_ref().parent() else {
        return false;
    };
    let path = parent.join("mesh-memberships.json");
    match MembershipStore::open(&path) {
        Ok(store) => store.blocks_adopt(foreign_mesh_id),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-memberships-{}-{}-{}",
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

    #[test]
    fn open_missing_is_empty() {
        let dir = temp_dir("missing");
        let path = dir.join("mesh-memberships.json");
        let store = MembershipStore::open(&path).unwrap();
        assert!(store.list().is_empty());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migrate_writes_primary_0600() {
        let dir = temp_dir("migrate");
        let path = dir.join("mesh-memberships.json");
        let store = MembershipStore::open_or_migrate(&path, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .unwrap();
        assert!(path.exists());
        assert_eq!(store.list().len(), 1);
        assert!(store.list()[0].primary);
        assert_eq!(store.list()[0].role, CatalogRole::Member);
        assert_eq!(store.list()[0].source, MEMBERSHIP_SOURCE_INIT);
        assert!(!store.has_extra_rows());
        let parsed: MeshMembershipsFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.version, MESH_MEMBERSHIPS_FILE_VERSION);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn add_guest_persist_and_leave() {
        let dir = temp_dir("guest");
        let path = dir.join("mesh-memberships.json");
        let mut store =
            MembershipStore::open_or_migrate(&path, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .unwrap();
        let row = store
            .add_guest(
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                Some("01HGRANTTEST0000000000001".into()),
            )
            .unwrap();
        assert_eq!(row.role, CatalogRole::Guest);
        assert!(!row.primary);
        assert_eq!(row.source, MEMBERSHIP_SOURCE_OVERLAP);
        assert_eq!(
            row.via_grant_id.as_deref(),
            Some("01HGRANTTEST0000000000001")
        );
        assert!(store.has_extra_rows());
        assert!(store.blocks_adopt("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        assert!(!store.blocks_adopt("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));

        let store2 = MembershipStore::open(&path).unwrap();
        assert_eq!(store2.list().len(), 2);
        assert_eq!(
            store2
                .get("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
                .unwrap()
                .via_grant_id
                .as_deref(),
            Some("01HGRANTTEST0000000000001")
        );

        let mut store3 = MembershipStore::open(&path).unwrap();
        let left = store3
            .leave("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
            .unwrap();
        assert_eq!(left.role, CatalogRole::Guest);
        assert!(!store3.has_extra_rows());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn extra_member_rejected() {
        let dir = temp_dir("member");
        let path = dir.join("mesh-memberships.json");
        let mut store =
            MembershipStore::open_or_migrate(&path, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .unwrap();
        let err = store
            .add_row(
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                CatalogRole::Member,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented(_)) && err.to_string().contains("F8b"),
            "{err}"
        );
        assert!(!store.has_extra_rows());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cannot_guest_or_leave_primary() {
        let dir = temp_dir("primary");
        let path = dir.join("mesh-memberships.json");
        let primary = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let mut store = MembershipStore::open_or_migrate(&path, primary).unwrap();
        assert!(matches!(
            store.add_guest(primary, None),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(store.leave(primary), Err(Error::Conflict(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_version_fail_closed() {
        let dir = temp_dir("ver");
        let path = dir.join("mesh-memberships.json");
        std::fs::write(
            &path,
            "{\"version\":99,\"primary_mesh_id\":\"x\",\"memberships\":[]}\n",
        )
        .unwrap();
        let err = MembershipStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mesh_memberships_file_path() {
        let paths = crate::Paths {
            config_dir: PathBuf::from("/tmp/cfg"),
            data_dir: PathBuf::from("/tmp/data"),
            cache_dir: PathBuf::from("/tmp/cache"),
        };
        assert_eq!(
            paths.mesh_memberships_file(),
            PathBuf::from("/tmp/data/mesh-memberships.json")
        );
    }
}
