//! This-node membership catalog types (Wave F1 freeze).
//!
//! `PeerMembership` / `DeviceRecord.memberships` are **F8b** and are not goldened here.

use serde::{Deserialize, Serialize};

/// `mesh-memberships.json` schema version.
pub const MESH_MEMBERSHIPS_FILE_VERSION: u32 = 1;

/// Catalog role on this node (guest overlap this wave; member = primary).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRole {
    Member,
    Guest,
}

impl CatalogRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Guest => "guest",
        }
    }
}

/// One row in this node's `mesh-memberships.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogMembership {
    pub mesh_id: String,
    pub role: CatalogRole,
    pub primary: bool,
    pub joined_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_grant_id: Option<String>,
    /// `init` | `overlap` (and future sources).
    pub source: String,
}

/// On-disk catalog (not persisted in F1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshMembershipsFile {
    pub version: u32,
    pub primary_mesh_id: String,
    pub memberships: Vec<CatalogMembership>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_role_snake() {
        assert_eq!(
            serde_json::to_string(&CatalogRole::Guest).unwrap(),
            "\"guest\""
        );
    }

    #[test]
    fn catalog_file_roundtrip() {
        let file = MeshMembershipsFile {
            version: MESH_MEMBERSHIPS_FILE_VERSION,
            primary_mesh_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            memberships: vec![CatalogMembership {
                mesh_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                role: CatalogRole::Member,
                primary: true,
                joined_at: "2026-08-13T12:00:00Z".into(),
                via_grant_id: None,
                source: "init".into(),
            }],
        };
        let j = serde_json::to_string(&file).unwrap();
        assert!(!j.contains("via_grant_id"));
        let back: MeshMembershipsFile = serde_json::from_str(&j).unwrap();
        assert_eq!(back, file);
    }
}
