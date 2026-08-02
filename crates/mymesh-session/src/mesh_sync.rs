//! Mesh membership gossip + kick application.
use chrono::{TimeZone, Utc};
use mymesh_core::{
    Capability, DeviceId, DeviceLabel, DeviceRecord, DeviceStore, KickNoticeRecord, MeshState,
    NodeFingerprint, Result, TrustState,
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
    pub_id.verify(&membership_material(mesh_id, from_id, ts, members), signature)?;
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

pub fn sign_kick(
    identity: &Identity,
    mesh_id: &str,
    target: &DeviceId,
    ts: i64,
) -> [u8; 64] {
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
        fingerprint: NodeFingerprint::from_device_id(&self_id).as_str().to_string(),
        capabilities: Capability::all(),
        linked_at_unix: Utc::now().timestamp(),
    });
    for d in store.list() {
        if d.trust != TrustState::Trusted {
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
    out.sort_by(|a, b| a.id.to_string().cmp(&b.id.to_string()));
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
        if store.get(&m.id).map(|d| d.trust == TrustState::Trusted).unwrap_or(false) {
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

pub fn sign_leave_ack(
    identity: &Identity,
    mesh_id: &str,
    by: &DeviceId,
    ts: i64,
) -> [u8; 64] {
    identity.sign(&leave_ack_material(
        mesh_id,
        &identity.device_id(),
        by,
        ts,
    ))
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
