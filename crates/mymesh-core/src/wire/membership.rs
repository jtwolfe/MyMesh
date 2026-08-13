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

/// On-disk catalog (`Paths::mesh_memberships_file`, mode 0600).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshMembershipsFile {
    pub version: u32,
    pub primary_mesh_id: String,
    pub memberships: Vec<CatalogMembership>,
}

/// `GET /mesh/v1/memberships` — this node's catalog (same shape as the file).
pub type MembershipsListResponse = MeshMembershipsFile;

/// Grant fragment on `POST /mesh/v1/memberships` (existing `GrantObject::Device`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMembershipGrant {
    pub object_device_id_hex: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_days: Option<u64>,
}

/// `POST /mesh/v1/memberships` body (guest overlap this wave).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMembershipBody {
    pub device_id_hex: String,
    pub mesh_id: String,
    pub role: CatalogRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<CreateMembershipGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_grant_id: Option<String>,
}

/// `POST /mesh/v1/memberships` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMembershipResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<CatalogMembership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_grant_id: Option<String>,
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

    #[test]
    fn create_membership_body_guest_roundtrip() {
        let body = CreateMembershipBody {
            device_id_hex: "ab".repeat(32),
            mesh_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
            role: CatalogRole::Guest,
            grant: Some(CreateMembershipGrant {
                object_device_id_hex: "cd".repeat(32),
                capabilities: vec!["terminal".into(), "files".into()],
                not_after_days: Some(7),
            }),
            via_grant_id: None,
        };
        let j = serde_json::to_string(&body).unwrap();
        assert!(j.contains("\"guest\""));
        assert!(!j.contains("via_grant_id"));
        let back: CreateMembershipBody = serde_json::from_str(&j).unwrap();
        assert_eq!(back, body);
    }
}
