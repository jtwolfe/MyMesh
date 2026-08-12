use crate::{DeviceId, DeviceLabel, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// What a peer is allowed to do on this node after pairing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Terminal,
    Files,
    Desktop,
    /// TCP port tunnels (magic hostname / socks / expose).
    Tcp,
    /// Remote mesh API admin (grant/kick remotely). **Not** in default grant (KD15).
    /// Host-local CLI always administers this node without needing this cap.
    Admin,
}

/// Device mesh role: `member` | `guest` only (never `owner` on a device).
///
/// Missing field in `devices.json` deserializes as [`MeshRole::Member`] (GUEST.md).
/// Person ownership lives only in `mesh-owner.json` (MASTER-KEY.md / KD21).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshRole {
    #[default]
    Member,
    Guest,
}

impl MeshRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Guest => "guest",
        }
    }

    pub fn is_guest(self) -> bool {
        matches!(self, Self::Guest)
    }
}

impl Capability {
    /// Default member grant: terminal / files / desktop / tcp — **no Admin** (KD15).
    pub fn default_grant() -> Vec<Self> {
        vec![Self::Terminal, Self::Files, Self::Desktop, Self::Tcp]
    }

    /// Historical alias for [`Self::default_grant`] (still **without** Admin).
    pub fn all() -> Vec<Self> {
        Self::default_grant()
    }

    /// Default grant plus remote [`Capability::Admin`] (mesh-init creator / `grant-admin`).
    pub fn with_admin() -> Vec<Self> {
        let mut v = Self::default_grant();
        if !v.contains(&Self::Admin) {
            v.push(Self::Admin);
        }
        v
    }
}

/// Who may perform admin-mutating operations (MASTER-KEY / KD15).
///
/// - **Host-local** — process with access to agent `Paths` data dir (filesystem trust).
///   Always sufficient for **this node**; distinct from remote Admin cap.
/// - **MrkProof** — unlocked MRK / `mrk_proof` (mesh-destructive + remote admin API).
/// - **RemoteDeviceAdmin** — Trusted member with [`Capability::Admin`] on device record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAuthority {
    /// CLI or agent process on the machine that owns the data dir.
    HostLocal,
    /// Unlocked mesh root key (MRK) / admin proof.
    MrkProof,
    /// Remote Trusted member whose store record includes Admin.
    RemoteDeviceAdmin { device_id: DeviceId },
}

impl AdminAuthority {
    /// Host-local CLI always may mutate this node's policy store.
    pub fn host_local() -> Self {
        Self::HostLocal
    }

    /// Local store mutations (grants, kick local, grant-admin, etc.).
    pub fn may_mutate_local_store(&self) -> bool {
        matches!(
            self,
            Self::HostLocal | Self::MrkProof | Self::RemoteDeviceAdmin { .. }
        )
    }

    /// Remote / mesh API admin path (not filesystem trust alone).
    pub fn may_remote_admin(&self) -> bool {
        matches!(self, Self::MrkProof | Self::RemoteDeviceAdmin { .. })
    }

    /// Mesh-destructive ops (clear owner, emergency re-init policy) require MRK.
    pub fn may_mesh_destructive(&self) -> bool {
        matches!(self, Self::MrkProof)
    }
}

/// Resolve remote Admin authority from a peer's device record (session / API path).
///
/// Does **not** grant host-local — callers with data-dir access use
/// [`AdminAuthority::host_local`] instead.
pub fn remote_admin_authority(store: &DeviceStore, peer: &DeviceId) -> Option<AdminAuthority> {
    if store.allows(peer, &Capability::Admin) {
        Some(AdminAuthority::RemoteDeviceAdmin { device_id: *peer })
    } else {
        None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// Linked and allowed.
    Trusted,
    /// Pairing completed but waiting for local confirmation.
    Pending,
    /// Explicitly revoked.
    Revoked,
}

/// Persistent record for a linked peer (Signal "linked devices" analogue).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub label: DeviceLabel,
    pub fingerprint: String,
    pub capabilities: Vec<Capability>,
    pub trust: TrustState,
    pub linked_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Optional iroh / transport endpoint tips (relay URLs, etc.) as opaque JSON.
    #[serde(default)]
    pub endpoint_hint: Option<serde_json::Value>,
    /// Mesh this peer belongs to (gossip roster).
    #[serde(default)]
    pub mesh_id: Option<String>,
    /// Extra human names (ssh/dns aliases), lowercase recommended.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Optional tags/groups for filtering (e.g. home, lab).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Member vs guest (default Member when absent — GUEST.md migration).
    #[serde(default)]
    pub mesh_role: MeshRole,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    devices: HashMap<String, DeviceRecord>,
}

/// On-disk store of linked devices under the user's config directory.
#[derive(Debug)]
pub struct DeviceStore {
    path: PathBuf,
    devices: HashMap<DeviceId, DeviceRecord>,
}

impl DeviceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let devices = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let file: StoreFile = serde_json::from_str(&raw)?;
            file.devices.into_values().map(|d| (d.id, d)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, devices })
    }

    pub fn list(&self) -> Vec<&DeviceRecord> {
        let mut v: Vec<_> = self.devices.values().collect();
        v.sort_by(|a, b| a.label.as_str().cmp(b.label.as_str()));
        v
    }

    pub fn get(&self, id: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }

    pub fn upsert(&mut self, record: DeviceRecord) -> Result<()> {
        self.devices.insert(record.id, record);
        self.flush()
    }

    pub fn revoke(&mut self, id: &DeviceId) -> Result<()> {
        if let Some(r) = self.devices.get_mut(id) {
            r.trust = TrustState::Revoked;
            self.flush()
        } else {
            Err(Error::NotFound(id.to_string()))
        }
    }

    pub fn remove(&mut self, id: &DeviceId) -> Result<()> {
        if self.devices.remove(id).is_some() {
            self.flush()
        } else {
            Err(Error::NotFound(id.to_string()))
        }
    }

    pub fn is_trusted(&self, id: &DeviceId) -> bool {
        matches!(
            self.devices.get(id).map(|d| &d.trust),
            Some(TrustState::Trusted)
        )
    }

    /// Member capability check (device-record caps).
    ///
    /// **Guests always return false here** — session paths must use
    /// [`crate::allows`] with [`crate::GrantStore`] so revoke/expiry are enforced.
    pub fn allows(&self, id: &DeviceId, cap: &Capability) -> bool {
        self.devices
            .get(id)
            .filter(|d| d.trust == TrustState::Trusted)
            .map(|d| match d.mesh_role {
                MeshRole::Member => d.capabilities.contains(cap),
                MeshRole::Guest => false,
            })
            .unwrap_or(false)
    }

    /// Whether peer is Trusted **and** has remote [`Capability::Admin`].
    pub fn has_admin(&self, id: &DeviceId) -> bool {
        self.allows(id, &Capability::Admin)
    }

    /// Grant remote Admin on a Trusted member (host-local CLI or MRK; KD15).
    ///
    /// Does **not** require the caller to already hold Admin — host-local
    /// filesystem access is sufficient to mutate this node's device store.
    pub fn grant_admin(&mut self, id: &DeviceId) -> Result<()> {
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if r.trust != TrustState::Trusted {
            return Err(Error::PermissionDenied(format!(
                "device {} is {:?}; Admin only for Trusted members",
                id.short(),
                r.trust
            )));
        }
        if !r.capabilities.contains(&Capability::Admin) {
            r.capabilities.push(Capability::Admin);
        }
        self.flush()
    }

    /// Remove remote Admin from a device record (host-local CLI).
    pub fn revoke_admin(&mut self, id: &DeviceId) -> Result<()> {
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        r.capabilities.retain(|c| *c != Capability::Admin);
        self.flush()
    }

    /// Resolve by full id hex, short prefix, label, or alias (case-insensitive).
    pub fn resolve_query(&self, q: &str) -> Result<DeviceId> {
        let q = q.trim();
        let q_host = q.strip_suffix(".mym").unwrap_or(q);
        let q_host = q_host.strip_suffix('.').unwrap_or(q_host);
        let ql = q_host.to_lowercase();

        // exact label / alias
        let mut hits: Vec<DeviceId> = Vec::new();
        for d in self.devices.values() {
            if d.label.as_str().eq_ignore_ascii_case(q_host)
                || d.aliases.iter().any(|a| a.eq_ignore_ascii_case(q_host))
            {
                hits.push(d.id);
            }
        }
        hits.sort_by_key(|id| id.to_string());
        hits.dedup();
        if hits.len() == 1 {
            return Ok(hits[0]);
        }
        if hits.len() > 1 {
            return Err(Error::Config(format!("ambiguous name '{q_host}'")));
        }

        // prefix match label/alias/short
        for d in self.devices.values() {
            if d.label.as_str().to_lowercase().starts_with(&ql)
                || d.id.short().starts_with(&ql)
                || d.aliases.iter().any(|a| a.to_lowercase().starts_with(&ql))
            {
                hits.push(d.id);
            }
        }
        hits.sort_by_key(|id| id.to_string());
        hits.dedup();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(Error::NotFound(format!("no device matched '{q}'"))),
            _ => Err(Error::Config(format!("ambiguous device '{q}'"))),
        }
    }

    pub fn set_label(&mut self, id: &DeviceId, label: DeviceLabel) -> Result<()> {
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        r.label = label;
        self.flush()
    }

    pub fn add_alias(&mut self, id: &DeviceId, alias: &str) -> Result<()> {
        let alias = alias.trim().to_lowercase();
        if alias.is_empty() {
            return Err(Error::Config("empty alias".into()));
        }
        // uniqueness
        for d in self.devices.values() {
            if d.id != *id
                && (d.label.as_str().eq_ignore_ascii_case(&alias)
                    || d.aliases.iter().any(|a| a == &alias))
            {
                return Err(Error::Config(format!("alias '{alias}' already used")));
            }
        }
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if !r.aliases.iter().any(|a| a == &alias) {
            r.aliases.push(alias);
        }
        self.flush()
    }

    pub fn remove_alias(&mut self, id: &DeviceId, alias: &str) -> Result<()> {
        let alias = alias.trim().to_lowercase();
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        r.aliases.retain(|a| a != &alias);
        self.flush()
    }

    pub fn add_group(&mut self, id: &DeviceId, group: &str) -> Result<()> {
        let g = group.trim().to_lowercase();
        if g.is_empty() {
            return Err(Error::Config("empty group".into()));
        }
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if !r.groups.iter().any(|x| x == &g) {
            r.groups.push(g);
        }
        self.flush()
    }

    pub fn remove_group(&mut self, id: &DeviceId, group: &str) -> Result<()> {
        let g = group.trim().to_lowercase();
        let r = self
            .devices
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        r.groups.retain(|x| x != &g);
        self.flush()
    }

    pub fn in_group(&self, group: &str) -> Vec<&DeviceRecord> {
        let g = group.to_lowercase();
        let mut v: Vec<_> = self
            .devices
            .values()
            .filter(|d| d.groups.iter().any(|x| x == &g))
            .collect();
        v.sort_by(|a, b| a.label.as_str().cmp(b.label.as_str()));
        v
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = StoreFile {
            devices: self
                .devices
                .values()
                .cloned()
                .map(|d| (d.id.to_string(), d))
                .collect(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceLabel;

    fn temp_store() -> (std::path::PathBuf, DeviceStore) {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-devstore-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("devices.json");
        let store = DeviceStore::open(&path).unwrap();
        (dir, store)
    }

    fn trusted_record(id_byte: u8) -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([id_byte; 32]),
            label: DeviceLabel::new(format!("dev-{id_byte:02x}")),
            fingerprint: format!("fp-{id_byte:02x}"),
            capabilities: Capability::default_grant(),
            trust: TrustState::Trusted,
            linked_at: Utc::now(),
            last_seen: None,
            endpoint_hint: None,
            mesh_id: None,
            aliases: vec![],
            groups: vec![],
            mesh_role: MeshRole::Member,
        }
    }

    #[test]
    fn default_grant_excludes_admin() {
        let g = Capability::default_grant();
        assert_eq!(g, Capability::all());
        assert!(!g.contains(&Capability::Admin));
        let with = Capability::with_admin();
        assert!(with.contains(&Capability::Admin));
        assert_eq!(with.len(), g.len() + 1);
    }

    #[test]
    fn grant_admin_host_local_no_prior_admin_required() {
        let (dir, mut store) = temp_store();
        let rec = trusted_record(0xab);
        let id = rec.id;
        store.upsert(rec).unwrap();
        assert!(!store.has_admin(&id));
        store.grant_admin(&id).unwrap();
        assert!(store.has_admin(&id));
        // idempotent
        store.grant_admin(&id).unwrap();
        assert!(store.has_admin(&id));
        // remote authority resolves
        assert!(matches!(
            remote_admin_authority(&store, &id),
            Some(AdminAuthority::RemoteDeviceAdmin { device_id }) if device_id == id
        ));
        store.revoke_admin(&id).unwrap();
        assert!(!store.has_admin(&id));
        assert!(remote_admin_authority(&store, &id).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn grant_admin_rejects_non_trusted() {
        let (dir, mut store) = temp_store();
        let mut rec = trusted_record(0xcd);
        rec.trust = TrustState::Pending;
        let id = rec.id;
        store.upsert(rec).unwrap();
        assert!(store.grant_admin(&id).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn host_local_authority_rules() {
        let local = AdminAuthority::host_local();
        assert!(local.may_mutate_local_store());
        // Host-local is node admin via filesystem, but not "remote admin" path
        assert!(!local.may_remote_admin());
        assert!(!local.may_mesh_destructive());

        let mrk = AdminAuthority::MrkProof;
        assert!(mrk.may_mutate_local_store());
        assert!(mrk.may_remote_admin());
        assert!(mrk.may_mesh_destructive());

        let remote = AdminAuthority::RemoteDeviceAdmin {
            device_id: DeviceId::from_bytes([1; 32]),
        };
        assert!(remote.may_mutate_local_store());
        assert!(remote.may_remote_admin());
        assert!(!remote.may_mesh_destructive());
    }

    #[test]
    fn existing_devices_keep_capabilities_without_admin_auto_grant() {
        // Migration: Trusted peers keep stored caps; no Admin auto-grant.
        let (dir, mut store) = temp_store();
        let rec = trusted_record(0xef);
        let id = rec.id;
        store.upsert(rec).unwrap();
        // simulate "after mesh init" — store unchanged
        assert!(!store.has_admin(&id));
        assert_eq!(
            store.get(&id).unwrap().capabilities,
            Capability::default_grant()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
