//! Mesh membership gossip + kick / grant-revoke application.
use chrono::{TimeZone, Utc};
use mymesh_core::{
    Capability, DeviceId, DeviceLabel, DeviceRecord, DeviceStore, Grant, GrantStore,
    KickNoticeRecord, MeshRole, MeshState, NodeFingerprint, Result, TrustState,
};
use mymesh_crypto::Identity;
use mymesh_protocol::{ControlMessage, MeshMemberWire};
use std::path::Path;
use tracing::info;

pub fn sign_membership(
    identity: &Identity,
    mesh_id: &str,
    from_id: &DeviceId,
    ts: i64,
    members: &[MeshMemberWire],
) -> [u8; 64] {
    identity.sign(&membership_material(mesh_id, from_id, ts, members))
}

pub fn membership_material(
    mesh_id: &str,
    from_id: &DeviceId,
    ts: i64,
    members: &[MeshMemberWire],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"mymesh-membership-v1");
    v.extend_from_slice(mesh_id.as_bytes());
    v.extend_from_slice(from_id.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    let mut ids: Vec<_> = members.iter().map(|m| m.id.to_string()).collect();
    ids.sort();
    for id in ids {
        v.extend_from_slice(id.as_bytes());
    }
    v
}

pub fn verify_membership(
    from_id: &DeviceId,
    mesh_id: &str,
    ts: i64,
    members: &[MeshMemberWire],
    signature: &[u8; 64],
) -> Result<()> {
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: *from_id.as_bytes(),
    };
    pub_id.verify(
        &membership_material(mesh_id, from_id, ts, members),
        signature,
    )?;
    Ok(())
}

pub fn kick_material(mesh_id: &str, target: &DeviceId, by: &DeviceId, ts: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"mymesh-kick-v1");
    v.extend_from_slice(mesh_id.as_bytes());
    v.extend_from_slice(target.as_bytes());
    v.extend_from_slice(by.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v
}

pub fn sign_kick(identity: &Identity, mesh_id: &str, target: &DeviceId, ts: i64) -> [u8; 64] {
    identity.sign(&kick_material(mesh_id, target, &identity.device_id(), ts))
}

pub fn verify_kick(
    mesh_id: &str,
    target: &DeviceId,
    by: &DeviceId,
    ts: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: *by.as_bytes(),
    };
    pub_id.verify(&kick_material(mesh_id, target, by, ts), signature)?;
    Ok(())
}

pub fn members_from_store(
    store: &DeviceStore,
    self_id: DeviceId,
    self_label: &str,
) -> Vec<MeshMemberWire> {
    let mut out = Vec::new();
    out.push(MeshMemberWire {
        id: self_id,
        label: self_label.to_string(),
        fingerprint: NodeFingerprint::from_device_id(&self_id)
            .as_str()
            .to_string(),
        capabilities: Capability::all(),
        linked_at_unix: Utc::now().timestamp(),
    });
    for d in store.list() {
        if d.trust != TrustState::Trusted {
            continue;
        }
        // Guests are bilateral-only — never flood into mesh member snapshots (GUEST.md).
        if d.mesh_role == MeshRole::Guest {
            continue;
        }
        if d.id == self_id {
            continue;
        }
        out.push(MeshMemberWire {
            id: d.id,
            label: d.label.as_str().to_string(),
            fingerprint: d.fingerprint.clone(),
            capabilities: d.capabilities.clone(),
            linked_at_unix: d.linked_at.timestamp(),
        });
    }
    out.sort_by_key(|a| a.id.to_string());
    out
}

pub fn build_snapshot(
    identity: &Identity,
    label: &str,
    store: &DeviceStore,
    mesh: &MeshState,
    nonce: u64,
) -> ControlMessage {
    let from_id = identity.device_id();
    let members = members_from_store(store, from_id, label);
    let ts = Utc::now().timestamp();
    let signature = sign_membership(identity, &mesh.mesh_id, &from_id, ts, &members);
    ControlMessage::MembershipSnapshot {
        nonce,
        mesh_id: mesh.mesh_id.clone(),
        from_id,
        from_label: label.to_string(),
        members,
        ts,
        signature,
    }
}

pub fn build_announce(
    identity: &Identity,
    label: &str,
    store: &DeviceStore,
    mesh: &MeshState,
) -> ControlMessage {
    let from_id = identity.device_id();
    let members = members_from_store(store, from_id, label);
    let ts = Utc::now().timestamp();
    let signature = sign_membership(identity, &mesh.mesh_id, &from_id, ts, &members);
    ControlMessage::MembershipAnnounce {
        mesh_id: mesh.mesh_id.clone(),
        from_id,
        from_label: label.to_string(),
        members,
        ts,
        signature,
    }
}

/// Merge remote members into local store (from a trusted peer only).
pub fn apply_membership(
    store: &mut DeviceStore,
    mesh_path: &Path,
    from_id: &DeviceId,
    mesh_id: &str,
    members: &[MeshMemberWire],
    self_id: DeviceId,
) -> Result<usize> {
    // Caller must ensure from_id is trusted (or join path).
    let mut mesh = MeshState::load(mesh_path)?;
    mesh.adopt_mesh_id(mesh_id);
    mesh.last_sync = Some(Utc::now());
    mesh.save(mesh_path)?;

    let mut added = 0usize;
    for m in members {
        if m.id == self_id {
            continue;
        }
        if store
            .get(&m.id)
            .map(|d| d.trust == TrustState::Trusted)
            .unwrap_or(false)
        {
            // refresh label/caps/mesh_id
            if let Some(existing) = store.get(&m.id).cloned() {
                let mut r = existing;
                r.label = DeviceLabel::new(m.label.clone());
                r.fingerprint = m.fingerprint.clone();
                if !m.capabilities.is_empty() {
                    r.capabilities = m.capabilities.clone();
                }
                r.mesh_id = Some(mesh.mesh_id.clone());
                r.last_seen = Some(Utc::now());
                store.upsert(r)?;
            }
            continue;
        }
        let linked = Utc
            .timestamp_opt(m.linked_at_unix, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let rec = DeviceRecord {
            id: m.id,
            label: DeviceLabel::new(m.label.clone()),
            fingerprint: m.fingerprint.clone(),
            capabilities: if m.capabilities.is_empty() {
                Capability::all()
            } else {
                m.capabilities.clone()
            },
            trust: TrustState::Trusted,
            linked_at: linked,
            last_seen: Some(Utc::now()),
            endpoint_hint: None,
            mesh_id: Some(mesh.mesh_id.clone()),
            aliases: Vec::new(),
            groups: Vec::new(),
            mesh_role: mymesh_core::MeshRole::Member,
        };
        store.upsert(rec)?;
        added += 1;
        info!(peer = %m.id.short(), label = %m.label, "mesh gossip: learned member");
    }
    // tag from_id
    if let Some(mut r) = store.get(from_id).cloned() {
        r.mesh_id = Some(mesh.mesh_id.clone());
        store.upsert(r)?;
    }
    if added > 0 {
        mesh.bump_generation();
        mesh.save(mesh_path)?;
        // dirty file next to mesh.json
        if let Some(parent) = mesh_path.parent() {
            let _ = mymesh_core::mark_mesh_dirty(parent.join("mesh.dirty"));
        }
    }
    Ok(added)
}

/// Apply kick of target from mesh (local remove).
pub fn apply_kick_target(store: &mut DeviceStore, target: &DeviceId) -> Result<()> {
    if store.get(target).is_some() {
        store.remove(target)?;
        info!(peer = %target.short(), "removed kicked mesh member");
    }
    Ok(())
}

/// We were kicked: record notice, clear all trusted mesh members.
pub fn apply_kick_notice_local(
    store: &mut DeviceStore,
    mesh_path: &Path,
    kick_notice_path: &Path,
    by_id: DeviceId,
    by_label: &str,
    message: &str,
) -> Result<()> {
    let mut mesh = MeshState::load(mesh_path)?;
    let notice = KickNoticeRecord {
        by_id,
        by_label: by_label.to_string(),
        message: message.to_string(),
        at: Utc::now(),
    };
    mesh.last_kick_notice = Some(notice);
    mesh.save(mesh_path)?;
    let text = format!(
        "you were kicked from the mesh by {by_label} ({})\n{message}\n",
        by_id
    );
    if let Some(p) = kick_notice_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(kick_notice_path, &text)?;
    // Leave the mesh: drop all trusted peers
    let ids: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| d.trust == TrustState::Trusted)
        .map(|d| d.id)
        .collect();
    for id in ids {
        let _ = store.remove(&id);
    }
    // Rotate mesh id so re-join is a fresh mesh
    let mut mesh = MeshState::new_mesh();
    mesh.last_kick_notice = Some(KickNoticeRecord {
        by_id,
        by_label: by_label.to_string(),
        message: message.to_string(),
        at: Utc::now(),
    });
    mesh.save(mesh_path)?;
    info!(by = %by_id.short(), "local mesh cleared after kick notice");
    Ok(())
}

pub fn leave_ack_material(mesh_id: &str, target: &DeviceId, by: &DeviceId, ts: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"mymesh-kick-leave-v1");
    v.extend_from_slice(mesh_id.as_bytes());
    v.extend_from_slice(target.as_bytes());
    v.extend_from_slice(by.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v
}

pub fn sign_leave_ack(identity: &Identity, mesh_id: &str, by: &DeviceId, ts: i64) -> [u8; 64] {
    identity.sign(&leave_ack_material(mesh_id, &identity.device_id(), by, ts))
}

pub fn verify_leave_ack(
    mesh_id: &str,
    target: &DeviceId,
    by: &DeviceId,
    ts: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: *target.as_bytes(),
    };
    pub_id.verify(&leave_ack_material(mesh_id, target, by, ts), signature)?;
    Ok(())
}

pub fn bump_mesh_dirty(mesh_path: &Path, dirty_path: &Path) -> Result<()> {
    let mut mesh = MeshState::load(mesh_path)?;
    mesh.bump_generation();
    mesh.save(mesh_path)?;
    mymesh_core::mark_mesh_dirty(dirty_path)?;
    Ok(())
}

// --- Grant revoke / announce (GUEST.md / GRANTS.md wire) ---

/// Peer may receive mesh-wide roster / kick gossip (Trusted **member** only).
pub fn peer_receives_mesh_gossip(store: &DeviceStore, peer: &DeviceId) -> bool {
    matches!(
        store.get(peer),
        Some(d) if d.trust == TrustState::Trusted && d.mesh_role == MeshRole::Member
    )
}

/// Peer may sign/apply grant control messages (Trusted and not Guest — fail closed).
pub fn peer_may_mutate_grants(store: &DeviceStore, peer: &DeviceId) -> bool {
    matches!(
        store.get(peer),
        Some(d) if d.trust == TrustState::Trusted && d.mesh_role != MeshRole::Guest
    )
}

pub fn grant_revoke_material(
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    by: &DeviceId,
    ts: i64,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"mymesh-grant-revoke-v1");
    v.extend_from_slice(mesh_id.as_bytes());
    v.extend_from_slice(grant_id.as_bytes());
    v.extend_from_slice(subject.as_bytes());
    v.extend_from_slice(object.as_bytes());
    v.extend_from_slice(by.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v
}

pub fn sign_grant_revoke(
    identity: &Identity,
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    ts: i64,
) -> [u8; 64] {
    identity.sign(&grant_revoke_material(
        mesh_id,
        grant_id,
        subject,
        object,
        &identity.device_id(),
        ts,
    ))
}

pub fn verify_grant_revoke(
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    by: &DeviceId,
    ts: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: *by.as_bytes(),
    };
    pub_id.verify(
        &grant_revoke_material(mesh_id, grant_id, subject, object, by, ts),
        signature,
    )?;
    Ok(())
}

/// Build a signed [`ControlMessage::GrantRevoke`] for gossip to object-host replicas.
pub fn build_grant_revoke(identity: &Identity, mesh_id: &str, grant: &Grant) -> ControlMessage {
    let object = grant
        .object
        .as_device_id()
        .copied()
        .unwrap_or_else(|| identity.device_id());
    let by_id = identity.device_id();
    let ts = Utc::now().timestamp();
    let signature = sign_grant_revoke(
        identity,
        mesh_id,
        &grant.grant_id,
        &grant.subject_device_id,
        &object,
        ts,
    );
    ControlMessage::GrantRevoke {
        grant_id: grant.grant_id.clone(),
        mesh_id: mesh_id.to_string(),
        subject_device_id: grant.subject_device_id,
        object_device_id: object,
        by_id,
        ts,
        signature,
    }
}

/// Apply a verified grant revoke locally (idempotent).
pub fn apply_grant_revoke(grants: &mut GrantStore, grant_id: &str) -> Result<Grant> {
    grants.revoke(grant_id)
}

pub fn grant_announce_material(
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    by: &DeviceId,
    ts: i64,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"mymesh-grant-announce-v1");
    v.extend_from_slice(mesh_id.as_bytes());
    v.extend_from_slice(grant_id.as_bytes());
    v.extend_from_slice(subject.as_bytes());
    v.extend_from_slice(object.as_bytes());
    v.extend_from_slice(by.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v
}

pub fn sign_grant_announce(
    identity: &Identity,
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    ts: i64,
) -> [u8; 64] {
    identity.sign(&grant_announce_material(
        mesh_id,
        grant_id,
        subject,
        object,
        &identity.device_id(),
        ts,
    ))
}

pub fn verify_grant_announce(
    mesh_id: &str,
    grant_id: &str,
    subject: &DeviceId,
    object: &DeviceId,
    by: &DeviceId,
    ts: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let pub_id = mymesh_crypto::IdentityPublic {
        verifying_key: *by.as_bytes(),
    };
    pub_id.verify(
        &grant_announce_material(mesh_id, grant_id, subject, object, by, ts),
        signature,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mymesh_core::{DeviceLabel, IssuedBy, MeshRole};
    use mymesh_protocol::{decode_msg, encode_msg};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mymesh-mesh-sync-{}-{}-{}",
            tag,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn trusted(id_byte: u8, label: &str, role: MeshRole) -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([id_byte; 32]),
            label: DeviceLabel::new(label),
            fingerprint: format!("fp-{id_byte:02x}"),
            capabilities: Capability::default_grant(),
            trust: TrustState::Trusted,
            linked_at: Utc::now(),
            last_seen: None,
            endpoint_hint: None,
            mesh_id: Some("mesh-t".into()),
            aliases: vec![],
            groups: vec![],
            mesh_role: role,
        }
    }

    #[test]
    fn build_snapshot_excludes_guests() {
        let dir = temp_dir("snap-filter");
        let mut store = DeviceStore::open(dir.join("devices.json")).unwrap();
        let host = DeviceId::from_bytes([0xaa; 32]);
        let member = trusted(0xbb, "member-b", MeshRole::Member);
        let guest = trusted(0xcc, "guest-c", MeshRole::Guest);
        let mid = member.id;
        let gid = guest.id;
        store.upsert(member).unwrap();
        store.upsert(guest).unwrap();

        let members = members_from_store(&store, host, "host");
        let ids: Vec<_> = members.iter().map(|m| m.id).collect();
        assert!(ids.contains(&host));
        assert!(ids.contains(&mid));
        assert!(
            !ids.contains(&gid),
            "guest must not appear in membership snapshot"
        );

        let identity = Identity::generate();
        // host id in snapshot is identity's device_id; still filters store guests
        let mut store2 = DeviceStore::open(dir.join("devices2.json")).unwrap();
        store2
            .upsert(trusted(0x11, "m1", MeshRole::Member))
            .unwrap();
        store2.upsert(trusted(0x22, "g1", MeshRole::Guest)).unwrap();
        let mesh = MeshState::new_mesh();
        let snap = build_snapshot(&identity, "lab", &store2, &mesh, 7);
        match snap {
            ControlMessage::MembershipSnapshot { members, .. } => {
                assert!(members.iter().all(|m| {
                    store2
                        .get(&m.id)
                        .map(|d| d.mesh_role != MeshRole::Guest)
                        .unwrap_or(true) // self may not be in store
                }));
                assert!(
                    !members
                        .iter()
                        .any(|m| m.id == DeviceId::from_bytes([0x22; 32])),
                    "guest device filtered from build_snapshot"
                );
                assert!(members
                    .iter()
                    .any(|m| m.id == DeviceId::from_bytes([0x11; 32])));
            }
            other => panic!("expected MembershipSnapshot, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn members_only_snapshot_includes_all_trusted_members() {
        let dir = temp_dir("members-only");
        let mut store = DeviceStore::open(dir.join("devices.json")).unwrap();
        store.upsert(trusted(0x31, "m1", MeshRole::Member)).unwrap();
        store.upsert(trusted(0x32, "m2", MeshRole::Member)).unwrap();
        let self_id = DeviceId::from_bytes([0x30; 32]);
        let members = members_from_store(&store, self_id, "self");
        assert_eq!(members.len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn grant_revoke_encode_decode_and_apply() {
        let dir = temp_dir("grant-revoke");
        let identity = Identity::generate();
        let subject = DeviceId::from_bytes([0x41; 32]);
        let object = identity.device_id();
        let mut grants = GrantStore::open(dir.join("grants.json")).unwrap();
        let grant = grants
            .create_guest(
                "mesh-r",
                subject,
                object,
                vec![Capability::Terminal],
                None,
                IssuedBy::device(&object),
            )
            .unwrap();
        assert!(grant.is_active(Utc::now()));

        let msg = build_grant_revoke(&identity, "mesh-r", &grant);
        let bytes = encode_msg(&msg).unwrap();
        let decoded: ControlMessage = decode_msg(&bytes).unwrap();
        match decoded {
            ControlMessage::GrantRevoke {
                grant_id,
                mesh_id,
                subject_device_id,
                object_device_id,
                by_id,
                ts,
                signature,
            } => {
                assert_eq!(grant_id, grant.grant_id);
                assert_eq!(subject_device_id, subject);
                assert_eq!(object_device_id, object);
                assert_eq!(by_id, identity.device_id());
                verify_grant_revoke(
                    &mesh_id,
                    &grant_id,
                    &subject_device_id,
                    &object_device_id,
                    &by_id,
                    ts,
                    &signature,
                )
                .expect("signature ok");
                let applied = apply_grant_revoke(&mut grants, &grant_id).unwrap();
                assert!(applied.revoked_at.is_some());
                assert!(!grants.get(&grant_id).unwrap().is_active(Utc::now()));
            }
            other => panic!("expected GrantRevoke, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn peer_gossip_and_grant_mutate_gates() {
        let dir = temp_dir("gates");
        let mut store = DeviceStore::open(dir.join("devices.json")).unwrap();
        let member = trusted(0x61, "m", MeshRole::Member);
        let guest = trusted(0x62, "g", MeshRole::Guest);
        let mid = member.id;
        let gid = guest.id;
        store.upsert(member).unwrap();
        store.upsert(guest).unwrap();

        assert!(peer_receives_mesh_gossip(&store, &mid));
        assert!(!peer_receives_mesh_gossip(&store, &gid));
        assert!(!peer_receives_mesh_gossip(
            &store,
            &DeviceId::from_bytes([0x00; 32])
        ));

        assert!(peer_may_mutate_grants(&store, &mid));
        assert!(
            !peer_may_mutate_grants(&store, &gid),
            "Trusted Guest must not mutate grants"
        );
        assert!(!peer_may_mutate_grants(
            &store,
            &DeviceId::from_bytes([0x00; 32])
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn grant_announce_sign_verify_roundtrip() {
        let identity = Identity::generate();
        let subject = DeviceId::from_bytes([0x51; 32]);
        let object = identity.device_id();
        let ts = Utc::now().timestamp();
        let sig = sign_grant_announce(&identity, "m", "G1", &subject, &object, ts);
        verify_grant_announce(
            "m",
            "G1",
            &subject,
            &object,
            &identity.device_id(),
            ts,
            &sig,
        )
        .unwrap();
        let msg = ControlMessage::GrantAnnounce {
            grant_id: "G1".into(),
            mesh_id: "m".into(),
            subject_device_id: subject,
            object_device_id: object,
            capabilities: vec![Capability::Files],
            not_after_unix: None,
            by_id: identity.device_id(),
            ts,
            signature: sig,
        };
        let round: ControlMessage = decode_msg(&encode_msg(&msg).unwrap()).unwrap();
        assert!(matches!(round, ControlMessage::GrantAnnounce { .. }));
    }
}
