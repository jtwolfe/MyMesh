use chrono::Utc;
use mymesh_core::{
    Capability, DeviceLabel, DeviceRecord, DeviceStore, NodeFingerprint, Result, TrustState,
};
use mymesh_crypto::{
    code_from_entropy, parse_code, Identity, PairingCode, PairingRole, PairingSession,
};
use mymesh_net::Rendezvous;
use mymesh_protocol::PairingMessage;
use sha2::{Digest, Sha256};
use tracing::info;

#[derive(Debug)]
pub struct PairOutcome {
    pub code: Option<PairingCode>,
    pub peer: DeviceRecord,
    pub shared_confirm: [u8; 32],
}

fn binder(secret: &mymesh_crypto::SharedSecret, material: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update(material);
    h.finalize().into()
}

/// Host: generate code, wait for guest, complete SPAKE2 + identity exchange.
pub async fn run_host_pair(
    identity: &Identity,
    label: &str,
    capabilities: Vec<Capability>,
    store: &mut DeviceStore,
    rendezvous: &impl Rendezvous,
    nameplate: u16,
) -> Result<PairOutcome> {
    let code = code_from_entropy(nameplate);
    let code_str = code.as_string();
    info!(%code_str, "pairing code ready — enter on the other device");

    let spake = PairingSession::start(PairingRole::Host, &code.password_bytes())?;
    let my_spake = spake.outbound_message().to_vec();
    rendezvous
        .send(&code_str, true, PairingMessage::Spake(my_spake))
        .await?;

    let peer_spake = match rendezvous.recv(&code_str, true).await? {
        PairingMessage::Spake(m) => m,
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "expected SPAKE message, got {other:?}"
            )))
        }
    };
    let secret = spake.finish(&peer_spake)?;

    // Offer identity
    let vk = identity.verifying_key_bytes();
    let device_id = identity.device_id();
    let sign_material = [device_id.as_bytes().as_slice(), label.as_bytes(), &vk].concat();
    let signature = identity.sign(&sign_material);
    let offer_binder = binder(&secret, &sign_material);
    rendezvous
        .send(
            &code_str,
            true,
            PairingMessage::IdentityOffer {
                device_id,
                label: label.to_string(),
                verifying_key: vk,
                capabilities: capabilities.clone(),
                signature,
                binder: offer_binder,
            },
        )
        .await?;

    let peer = match rendezvous.recv(&code_str, true).await? {
        PairingMessage::IdentityAccept {
            device_id: peer_id,
            label: peer_label,
            verifying_key,
            accepted_capabilities,
            signature,
            binder: peer_binder,
        } => {
            let material = [
                peer_id.as_bytes().as_slice(),
                peer_label.as_bytes(),
                &verifying_key,
            ]
            .concat();
            let expect = binder(&secret, &material);
            if expect != peer_binder {
                return Err(mymesh_core::Error::Pairing("binder mismatch".into()));
            }
            // Verify signature with offered key
            let pub_id = mymesh_crypto::IdentityPublic { verifying_key };
            pub_id.verify(&material, &signature)?;
            if pub_id.device_id() != peer_id {
                return Err(mymesh_core::Error::Pairing("device id mismatch".into()));
            }
            DeviceRecord {
                id: peer_id,
                label: DeviceLabel::new(peer_label),
                fingerprint: NodeFingerprint::from_device_id(&peer_id)
                    .as_str()
                    .to_string(),
                capabilities: accepted_capabilities,
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: Some(Utc::now()),
                endpoint_hint: None,
            }
        }
        PairingMessage::Reject { reason } => {
            return Err(mymesh_core::Error::Pairing(reason));
        }
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "unexpected message: {other:?}"
            )))
        }
    };

    store.upsert(peer.clone())?;
    Ok(PairOutcome {
        code: Some(code),
        peer,
        shared_confirm: secret.derive(b"mymesh/confirm"),
    })
}

/// Guest: enter code, complete ceremony, store host as trusted.
pub async fn run_guest_pair(
    identity: &Identity,
    label: &str,
    capabilities: Vec<Capability>,
    store: &mut DeviceStore,
    rendezvous: &impl Rendezvous,
    code_raw: &str,
) -> Result<PairOutcome> {
    let code = parse_code(code_raw)?;
    let code_str = code.as_string();

    let spake = PairingSession::start(PairingRole::Guest, &code.password_bytes())?;
    let my_spake = spake.outbound_message().to_vec();

    // Race: either side may send first; exchange SPAKE messages.
    rendezvous
        .send(&code_str, false, PairingMessage::Spake(my_spake))
        .await?;
    let peer_spake = match rendezvous.recv(&code_str, false).await? {
        PairingMessage::Spake(m) => m,
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "expected SPAKE message, got {other:?}"
            )))
        }
    };
    let secret = spake.finish(&peer_spake)?;

    // Expect host identity offer
    let host_rec = match rendezvous.recv(&code_str, false).await? {
        PairingMessage::IdentityOffer {
            device_id,
            label: host_label,
            verifying_key,
            capabilities: host_caps,
            signature,
            binder: host_binder,
        } => {
            let material = [
                device_id.as_bytes().as_slice(),
                host_label.as_bytes(),
                &verifying_key,
            ]
            .concat();
            let expect = binder(&secret, &material);
            if expect != host_binder {
                return Err(mymesh_core::Error::Pairing("host binder mismatch".into()));
            }
            let pub_id = mymesh_crypto::IdentityPublic { verifying_key };
            pub_id.verify(&material, &signature)?;
            DeviceRecord {
                id: device_id,
                label: DeviceLabel::new(host_label),
                fingerprint: NodeFingerprint::from_device_id(&device_id)
                    .as_str()
                    .to_string(),
                capabilities: host_caps,
                trust: TrustState::Trusted,
                linked_at: Utc::now(),
                last_seen: Some(Utc::now()),
                endpoint_hint: None,
            }
        }
        other => {
            return Err(mymesh_core::Error::Pairing(format!(
                "expected identity offer, got {other:?}"
            )))
        }
    };

    // Accept
    let vk = identity.verifying_key_bytes();
    let device_id = identity.device_id();
    let sign_material = [device_id.as_bytes().as_slice(), label.as_bytes(), &vk].concat();
    let signature = identity.sign(&sign_material);
    let accept_binder = binder(&secret, &sign_material);
    rendezvous
        .send(
            &code_str,
            false,
            PairingMessage::IdentityAccept {
                device_id,
                label: label.to_string(),
                verifying_key: vk,
                accepted_capabilities: capabilities,
                signature,
                binder: accept_binder,
            },
        )
        .await?;

    store.upsert(host_rec.clone())?;
    Ok(PairOutcome {
        code: Some(code),
        peer: host_rec,
        shared_confirm: secret.derive(b"mymesh/confirm"),
    })
}
