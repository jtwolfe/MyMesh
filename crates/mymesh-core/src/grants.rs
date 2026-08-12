//! Grant store (`grants.json` mode 0600) and session `allows()` enforcement.
//!
//! Normative schema: docs/GRANTS.md (S0 freeze). S5 scope: object = one Device,
//! role = guest. Guest session caps require an **active** grant covering this
//! node as object (not merely caps mirrored onto DeviceRecord).
use crate::device::{Capability, DeviceRecord, DeviceStore, MeshRole, TrustState};
use crate::{DeviceId, Error, Result};
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Crockford base32 alphabet (ULID).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a 26-char Crockford ULID grant id (time-sortable).
pub fn new_grant_id() -> String {
    let ms = Utc::now().timestamp_millis().max(0) as u64;
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
    encode_crockford_128(&bytes)
}

fn encode_crockford_128(bytes: &[u8; 16]) -> String {
    let mut chars = String::with_capacity(26);
    let mut acc: u128 = 0;
    for b in bytes {
        acc = (acc << 8) | u128::from(*b);
    }
    acc <<= 2;
    for i in (0..26).rev() {
        let shift = i * 5;
        let idx = ((acc >> shift) & 0x1f) as usize;
        chars.push(CROCKFORD[idx] as char);
    }
    chars
}

/// Device mesh role on a grant (`member` | `guest` — never `owner`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantRole {
    Member,
    Guest,
}

impl GrantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Guest => "guest",
        }
    }
}

/// Grant object (S5: Device only; Mesh | Service later).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantObject {
    Device { device_id: DeviceId },
}

impl GrantObject {
    pub fn device(device_id: DeviceId) -> Self {
        Self::Device { device_id }
    }

    pub fn as_device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::Device { device_id } => Some(device_id),
        }
    }
}

/// Optional identity facet constraint (S7 enforce; stored in S5).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityFacet {
    Personal,
    Work,
}

/// Grant constraints (not_after is enforced in S5; facet/location S7).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_facet: Option<IdentityFacet>,
}

/// Who issued the grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum IssuedBy {
    /// Issuing device id (hex string on the wire / disk).
    DeviceId(String),
    PersonId(String),
    MasterKeyProof(String),
}

impl IssuedBy {
    pub fn device(id: &DeviceId) -> Self {
        Self::DeviceId(id.to_string())
    }
}

/// First-class authorization record (docs/GRANTS.md).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub grant_id: String,
    pub mesh_id: String,
    pub subject_device_id: DeviceId,
    pub object: GrantObject,
    pub role: GrantRole,
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub constraints: GrantConstraints,
    pub issued_by: IssuedBy,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Grant {
    /// Active = not revoked and `not_after` not expired.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(na) = self.constraints.not_after {
            if now >= na {
                return false;
            }
        }
        true
    }

    pub fn covers_object(&self, object_device: &DeviceId) -> bool {
        match &self.object {
            GrantObject::Device { device_id } => device_id == object_device,
        }
    }

    pub fn has_cap(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    grants: HashMap<String, Grant>,
}

/// On-disk grant store under agent Paths (`grants.json`, mode 0600).
#[derive(Debug)]
pub struct GrantStore {
    path: PathBuf,
    grants: HashMap<String, Grant>,
}

impl GrantStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let grants = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: StoreFile = serde_json::from_str(&raw)?;
            file.grants
        } else {
            HashMap::new()
        };
        Ok(Self { path, grants })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list(&self) -> Vec<&Grant> {
        let mut v: Vec<_> = self.grants.values().collect();
        v.sort_by_key(|a| a.issued_at);
        v
    }

    pub fn get(&self, grant_id: &str) -> Option<&Grant> {
        self.grants.get(grant_id)
    }

    /// Create a guest grant (S5 primary shape). Host-local / admin callers.
    #[allow(clippy::too_many_arguments)]
    pub fn create_guest(
        &mut self,
        mesh_id: impl Into<String>,
        subject_device_id: DeviceId,
        object_device_id: DeviceId,
        capabilities: Vec<Capability>,
        not_after: Option<DateTime<Utc>>,
        issued_by: IssuedBy,
    ) -> Result<Grant> {
        if capabilities.is_empty() {
            return Err(Error::Config("grant capabilities must not be empty".into()));
        }
        // Product policy: do not issue Admin to guests by default path.
        if capabilities.contains(&Capability::Admin) {
            return Err(Error::Config(
                "Admin capability is not allowed on guest grants".into(),
            ));
        }
        let grant = Grant {
            grant_id: new_grant_id(),
            mesh_id: mesh_id.into(),
            subject_device_id,
            object: GrantObject::device(object_device_id),
            role: GrantRole::Guest,
            capabilities,
            constraints: GrantConstraints {
                not_after,
                ..Default::default()
            },
            issued_by,
            issued_at: Utc::now(),
            revoked_at: None,
        };
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        self.flush()?;
        Ok(grant)
    }

    /// Insert a pre-built grant (tests / import). Overwrites same grant_id.
    pub fn upsert(&mut self, grant: Grant) -> Result<()> {
        self.grants.insert(grant.grant_id.clone(), grant);
        self.flush()
    }

    /// Set `revoked_at` (idempotent if already revoked). Returns the grant.
    pub fn revoke(&mut self, grant_id: &str) -> Result<Grant> {
        let g = self
            .grants
            .get_mut(grant_id)
            .ok_or_else(|| Error::NotFound(format!("grant {grant_id}")))?;
        if g.revoked_at.is_none() {
            g.revoked_at = Some(Utc::now());
        }
        let out = g.clone();
        self.flush()?;
        Ok(out)
    }

    /// Active grants for subject → object (any cap).
    pub fn active_for_subject_object(
        &self,
        subject: &DeviceId,
        object: &DeviceId,
        now: DateTime<Utc>,
    ) -> Vec<&Grant> {
        self.grants
            .values()
            .filter(|g| {
                g.subject_device_id == *subject && g.covers_object(object) && g.is_active(now)
            })
            .collect()
    }

    /// Whether an active grant covers subject → object with `cap`.
    pub fn grant_allows(
        &self,
        subject: &DeviceId,
        object: &DeviceId,
        cap: &Capability,
        now: DateTime<Utc>,
    ) -> bool {
        self.grants.values().any(|g| {
            g.subject_device_id == *subject
                && g.covers_object(object)
                && g.is_active(now)
                && g.has_cap(cap)
        })
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = StoreFile {
            grants: self.grants.clone(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
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

/// Session capability check (docs/GRANTS.md):
///
/// ```text
/// allows(peer, cap):
///   if peer.trust != Trusted: deny
///   if peer.mesh_role == Guest:
///     require active Grant covering this node as object with cap
///   else:
///     peer.capabilities.contains(cap)
/// ```
pub fn allows(
    devices: &DeviceStore,
    grants: &GrantStore,
    local_device_id: &DeviceId,
    peer: &DeviceId,
    cap: &Capability,
) -> bool {
    allows_at(devices, grants, local_device_id, peer, cap, Utc::now())
}

/// Same as [`allows`] with an explicit clock (tests).
pub fn allows_at(
    devices: &DeviceStore,
    grants: &GrantStore,
    local_device_id: &DeviceId,
    peer: &DeviceId,
    cap: &Capability,
    now: DateTime<Utc>,
) -> bool {
    let Some(rec) = devices.get(peer) else {
        return false;
    };
    if rec.trust != TrustState::Trusted {
        return false;
    }
    match rec.mesh_role {
        MeshRole::Guest => grants.grant_allows(peer, local_device_id, cap, now),
        MeshRole::Member => rec.capabilities.contains(cap),
    }
}

/// Parse a comma-separated capability list (`terminal,files,desktop,tcp`).
/// Rejects empty lists and unknown names. Does **not** allow `admin` for guest CLI.
pub fn parse_capabilities(s: &str) -> Result<Vec<Capability>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        let cap = match p.as_str() {
            "terminal" => Capability::Terminal,
            "files" => Capability::Files,
            "desktop" => Capability::Desktop,
            "tcp" => Capability::Tcp,
            "admin" => Capability::Admin,
            other => {
                return Err(Error::Config(format!(
                    "unknown capability '{other}' (want terminal|files|desktop|tcp)"
                )));
            }
        };
        if !out.contains(&cap) {
            out.push(cap);
        }
    }
    if out.is_empty() {
        return Err(Error::Config("capabilities list is empty".into()));
    }
    Ok(out)
}

/// Helper: `not_after` from optional day count.
pub fn not_after_days(days: Option<u64>) -> Option<DateTime<Utc>> {
    days.map(|d| Utc::now() + Duration::days(d as i64))
}

/// Mark a device record as guest with grant caps (onboarding helper; protocol in C1b).
pub fn apply_guest_device_record(rec: &mut DeviceRecord, grant: &Grant) {
    rec.mesh_role = MeshRole::Guest;
    rec.capabilities = grant.capabilities.clone();
    rec.trust = TrustState::Trusted;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Capability, DeviceRecord, DeviceStore, MeshRole, TrustState};
    use crate::DeviceLabel;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-grants-{}-{}-{}",
            tag,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn trusted_member(id_byte: u8) -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([id_byte; 32]),
            label: DeviceLabel::new(format!("m-{id_byte:02x}")),
            fingerprint: format!("fp-{id_byte:02x}"),
            capabilities: Capability::default_grant(),
            trust: TrustState::Trusted,
            linked_at: Utc::now(),
            last_seen: None,
            endpoint_hint: None,
            mesh_id: Some("mesh-test".into()),
            aliases: vec![],
            groups: vec![],
            mesh_role: MeshRole::Member,
        }
    }

    fn trusted_guest(id_byte: u8, caps: Vec<Capability>) -> DeviceRecord {
        let mut r = trusted_member(id_byte);
        r.mesh_role = MeshRole::Guest;
        r.capabilities = caps;
        r.label = DeviceLabel::new(format!("g-{id_byte:02x}"));
        r
    }

    #[test]
    fn grant_id_is_ulid_shaped() {
        let id = new_grant_id();
        assert_eq!(id.len(), 26);
        assert!(id.chars().all(|c| CROCKFORD.contains(&(c as u8))));
    }

    #[test]
    fn create_list_revoke_roundtrip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("grants.json");
        let mut store = GrantStore::open(&path).unwrap();
        let subject = DeviceId::from_bytes([0x11; 32]);
        let object = DeviceId::from_bytes([0x22; 32]);
        let g = store
            .create_guest(
                "mesh-1",
                subject,
                object,
                vec![Capability::Terminal, Capability::Files],
                Some(Utc::now() + Duration::days(7)),
                IssuedBy::device(&object),
            )
            .unwrap();
        assert_eq!(g.role, GrantRole::Guest);
        assert!(g.is_active(Utc::now()));
        assert_eq!(store.list().len(), 1);

        // reload
        let store2 = GrantStore::open(&path).unwrap();
        let loaded = store2.get(&g.grant_id).unwrap();
        assert_eq!(loaded.subject_device_id, subject);
        assert!(loaded.covers_object(&object));
        assert!(store2.grant_allows(&subject, &object, &Capability::Terminal, Utc::now()));
        assert!(!store2.grant_allows(&subject, &object, &Capability::Desktop, Utc::now()));

        let mut store3 = GrantStore::open(&path).unwrap();
        store3.revoke(&g.grant_id).unwrap();
        assert!(!store3.get(&g.grant_id).unwrap().is_active(Utc::now()));
        assert!(!store3.grant_allows(&subject, &object, &Capability::Terminal, Utc::now()));

        // mode 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn guest_grant_rejects_admin_cap() {
        let dir = temp_dir("no-admin");
        let mut store = GrantStore::open(dir.join("grants.json")).unwrap();
        let err = store
            .create_guest(
                "m",
                DeviceId::from_bytes([1; 32]),
                DeviceId::from_bytes([2; 32]),
                vec![Capability::Terminal, Capability::Admin],
                None,
                IssuedBy::DeviceId("x".into()),
            )
            .unwrap_err();
        assert!(err.to_string().contains("Admin"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn not_after_expiry_denies() {
        let dir = temp_dir("expiry");
        let mut store = GrantStore::open(dir.join("grants.json")).unwrap();
        let subject = DeviceId::from_bytes([0x33; 32]);
        let object = DeviceId::from_bytes([0x44; 32]);
        let past = Utc::now() - Duration::hours(1);
        store
            .create_guest(
                "m",
                subject,
                object,
                vec![Capability::Files],
                Some(past),
                IssuedBy::device(&object),
            )
            .unwrap();
        assert!(!store.grant_allows(&subject, &object, &Capability::Files, Utc::now()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allows_member_path() {
        let dir = temp_dir("member");
        let mut devices = DeviceStore::open(dir.join("devices.json")).unwrap();
        let grants = GrantStore::open(dir.join("grants.json")).unwrap();
        let peer = trusted_member(0xaa);
        let local = DeviceId::from_bytes([0xbb; 32]);
        let id = peer.id;
        devices.upsert(peer).unwrap();
        assert!(allows(
            &devices,
            &grants,
            &local,
            &id,
            &Capability::Terminal
        ));
        assert!(!allows(&devices, &grants, &local, &id, &Capability::Admin));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allows_guest_requires_active_grant_on_object() {
        let dir = temp_dir("guest-allow");
        let mut devices = DeviceStore::open(dir.join("devices.json")).unwrap();
        let mut grants = GrantStore::open(dir.join("grants.json")).unwrap();
        let local = DeviceId::from_bytes([0x01; 32]); // object host
        let guest = trusted_guest(0x02, vec![Capability::Terminal, Capability::Files]);
        let gid = guest.id;
        devices.upsert(guest).unwrap();

        // No grant yet → deny even if device caps list Terminal
        assert!(!allows(
            &devices,
            &grants,
            &local,
            &gid,
            &Capability::Terminal
        ));

        grants
            .create_guest(
                "mesh-g",
                gid,
                local,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&local),
            )
            .unwrap();
        assert!(allows(
            &devices,
            &grants,
            &local,
            &gid,
            &Capability::Terminal
        ));
        // Files not on grant
        assert!(!allows(&devices, &grants, &local, &gid, &Capability::Files));

        // Wrong object host
        let other_host = DeviceId::from_bytes([0x99; 32]);
        assert!(!allows(
            &devices,
            &grants,
            &other_host,
            &gid,
            &Capability::Terminal
        ));

        // Revoke → deny
        let grant_id = grants.list()[0].grant_id.clone();
        grants.revoke(&grant_id).unwrap();
        assert!(!allows(
            &devices,
            &grants,
            &local,
            &gid,
            &Capability::Terminal
        ));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allows_denies_non_trusted() {
        let dir = temp_dir("pending");
        let mut devices = DeviceStore::open(dir.join("devices.json")).unwrap();
        let grants = GrantStore::open(dir.join("grants.json")).unwrap();
        let mut peer = trusted_member(0x55);
        peer.trust = TrustState::Pending;
        let id = peer.id;
        devices.upsert(peer).unwrap();
        assert!(!allows(
            &devices,
            &grants,
            &DeviceId::from_bytes([0; 32]),
            &id,
            &Capability::Terminal
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_capabilities_ok() {
        let c = parse_capabilities("terminal, files ,tcp").unwrap();
        assert_eq!(
            c,
            vec![Capability::Terminal, Capability::Files, Capability::Tcp]
        );
        assert!(parse_capabilities("").is_err());
        assert!(parse_capabilities("shell").is_err());
    }

    #[test]
    fn golden_grant_json_shape() {
        let g = Grant {
            grant_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            mesh_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            subject_device_id: DeviceId::from_bytes([0xab; 32]),
            object: GrantObject::device(DeviceId::from_bytes([0xcd; 32])),
            role: GrantRole::Guest,
            capabilities: vec![Capability::Terminal, Capability::Files],
            constraints: GrantConstraints {
                not_after: None,
                max_sessions: None,
                location_allowlist: None,
                identity_facet: None,
            },
            issued_by: IssuedBy::DeviceId(DeviceId::from_bytes([0xcd; 32]).to_string()),
            issued_at: DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            revoked_at: None,
        };
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["grant_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(v["role"], "guest");
        assert_eq!(v["object"]["kind"], "device");
        assert_eq!(v["issued_by"]["kind"], "device_id");
        assert!(v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "terminal"));
    }
}
