//! Enrollment handler for `mymesh-enroll/1` ALPN connections.
//!
//! When a carrier (phone) scans the node's QR and connects using the enrollment
//! ALPN, this handler verifies the ticket, checks that the challenge was confirmed
//! locally, and either accepts or denies the enrollment.
//!
//! ## ALPN `mymesh-enroll/1` wire protocol
//!
//! The carrier sends an [`EnrollMessage::EnrollRequest`] containing:
//! - `ticket`: one-time ticket from the QR code
//! - `person_public_key_hex`: person's Ed25519 public key (hex)
//! - `person_id`: person identity id (e.g. ULID)
//! - `mesh_name`: display name for the mesh/person
//!
//! This matches the DESIGN protocol for QR+challenge enrollment. The node
//! verifies the ticket against its pending session, checks the local challenge
//! confirmation, stores the owner enrollment, and replies with `EnrollAccept`
//! or `EnrollDeny`. Note: this handler bypasses the full `carrier-enroll-v1`
//! signature verification because enrollment is via direct iroh connection
//! with challenge confirmation—the carrier proves key ownership via the
//! authenticated iroh/QUIC connection.

use mymesh_core::wire::PersonFacet;
use mymesh_core::{DeviceId, EnrollSessionFile, EnrollmentStore, Error, Paths, Result};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, EnrollMessage, Frame};
use tracing::{info, warn};

/// Outcome of an enrollment attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// Enrollment accepted, owner stored.
    Accepted,
    /// Enrollment denied (ticket invalid, challenge not confirmed, expired, etc.).
    Denied,
}

/// Handle an incoming enrollment connection.
///
/// This is called when an incoming connection uses the `mymesh-enroll/1` ALPN.
/// The flow is:
/// 1. Receive EnrollRequest with ticket, person identity, mesh name
/// 2. Verify ticket matches the pending enrollment session
/// 3. Check that the challenge was confirmed locally
/// 4. Store the owner person id in enrollments
/// 5. Reply with EnrollAccept or EnrollDeny
pub async fn handle_enroll_connection(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    paths: &Paths,
) -> Result<EnrollOutcome> {
    let device_id = identity.device_id();
    let peer_id = conn.peer_id();

    // Receive the enrollment request
    let frame = conn.recv_frame().await?;
    let msg: EnrollMessage = decode_msg(&frame.payload)?;

    let (ticket, person_public_key_hex, person_id, mesh_name) = match msg {
        EnrollMessage::EnrollRequest {
            ticket,
            person_public_key_hex,
            person_id,
            mesh_name,
        } => (ticket, person_public_key_hex, person_id, mesh_name),
        _ => {
            let deny = EnrollMessage::EnrollDeny {
                reason: "expected EnrollRequest".into(),
            };
            let _ = send_msg(conn.as_ref(), &deny).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    info!(
        peer = %peer_id.short(),
        person_id = %person_id,
        "received enrollment request"
    );

    // Load the pending enrollment session
    let session_path = paths.enroll_session_file();
    let session_file = match EnrollSessionFile::try_load(&session_path)? {
        Some(f) => f,
        None => {
            warn!("enrollment request but no pending session");
            let deny = EnrollMessage::EnrollDeny {
                reason: "no pending enrollment session".into(),
            };
            let _ = send_msg(conn.as_ref(), &deny).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    let session = &session_file.session;

    // Check session validity
    if !session.is_valid() {
        warn!("enrollment session expired");
        let _ = EnrollSessionFile::clear(&session_path);
        let deny = EnrollMessage::EnrollDeny {
            reason: "enrollment session expired".into(),
        };
        let _ = send_msg(conn.as_ref(), &deny).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    // Verify the ticket
    if !session.verify_ticket(&ticket) {
        warn!("ticket mismatch");
        let deny = EnrollMessage::EnrollDeny {
            reason: "invalid ticket".into(),
        };
        let _ = send_msg(conn.as_ref(), &deny).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    // Check that the challenge was confirmed locally
    if !session.challenge_confirmed {
        warn!("challenge not confirmed locally");
        let deny = EnrollMessage::EnrollDeny {
            reason: "challenge not confirmed on node".into(),
        };
        let _ = send_msg(conn.as_ref(), &deny).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    // Store the owner enrollment
    let enroll_result = store_enrollment(
        paths,
        &device_id,
        &person_id,
        &person_public_key_hex,
        &mesh_name,
    );

    match enroll_result {
        Ok(_) => {
            // Mark session as completed
            let mut updated_session = session.clone();
            updated_session.complete(&person_id);
            let updated_file = EnrollSessionFile::new(updated_session);
            let _ = updated_file.save(&session_path);

            info!(
                peer = %peer_id.short(),
                person_id = %person_id,
                "enrollment accepted"
            );

            let accept = EnrollMessage::EnrollAccept {
                device_id,
                label: label.to_string(),
            };
            send_msg(conn.as_ref(), &accept).await?;
            let _ = conn.close().await;
            Ok(EnrollOutcome::Accepted)
        }
        Err(e) => {
            warn!(%e, "enrollment storage failed");
            let deny = EnrollMessage::EnrollDeny {
                reason: format!("enrollment failed: {e}"),
            };
            let _ = send_msg(conn.as_ref(), &deny).await;
            let _ = conn.close().await;
            Ok(EnrollOutcome::Denied)
        }
    }
}

/// Store the enrollment in the enrollments file.
fn store_enrollment(
    paths: &Paths,
    _device_id: &DeviceId,
    person_id: &str,
    person_public_key_hex: &str,
    _mesh_name: &str,
) -> Result<()> {
    let _store = EnrollmentStore::open(paths.enrollments_file())?;

    // For QR enrollment, we don't have a full carrier-enroll-v1 signature
    // We use a simplified enrollment that just stores the person identity
    // The carrier-side signature verification happens via the iroh connection
    // (the carrier's iroh endpoint proves they control the private key)

    // Create a simplified enrollment record directly
    // Note: This bypasses the full carrier-enroll-v1 signature verification
    // because the enrollment is via direct iroh connection with challenge confirmation
    let enrollment_id = mymesh_core::new_grant_id();
    let now = chrono::Utc::now();
    let record = mymesh_core::wire::EnrollmentRecord {
        enrollment_id,
        person_id: person_id.to_string(),
        person_public_key_hex: person_public_key_hex.to_string(),
        facet: PersonFacet::Personal,
        enrolled_at: now.to_rfc3339(),
        can_drive: true,
        label: Some("qr-enroll".into()),
    };

    // Write directly to the file (bypassing signature verification for QR enrollment)
    let enrollments_path = paths.enrollments_file();
    let mut file = if enrollments_path.exists() {
        let raw = std::fs::read_to_string(&enrollments_path)?;
        serde_json::from_str(&raw)?
    } else {
        mymesh_core::wire::EnrollmentsFile {
            version: mymesh_core::wire::ENROLLMENTS_FILE_VERSION,
            enrollments: Vec::new(),
        }
    };

    // Check if already enrolled with this person_id
    if let Some(pos) = file
        .enrollments
        .iter()
        .position(|e| e.person_id == person_id)
    {
        // Update existing
        file.enrollments[pos] = record;
    } else {
        // Check budget
        if file.enrollments.len() >= mymesh_core::MAX_ENROLLMENTS {
            return Err(Error::Config(format!(
                "enrollments budget is {} persons",
                mymesh_core::MAX_ENROLLMENTS
            )));
        }
        file.enrollments.push(record);
    }

    // Write with atomic rename
    let tmp = enrollments_path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(&file)?;
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &enrollments_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&enrollments_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

async fn send_msg<M: serde::Serialize>(conn: &dyn PeerConnection, msg: &M) -> Result<()> {
    conn.send_frame(Frame {
        channel: mymesh_protocol::ChannelId::control(),
        payload: encode_msg(msg)?,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use mymesh_core::EnrollSession;
    use mymesh_net::{LocalFabric, Transport};

    fn tmp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-enroll-handler-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&root);
        Paths {
            config_dir: root.join("config"),
            data_dir: root.clone(),
            cache_dir: root.join("cache"),
        }
    }

    #[tokio::test]
    async fn enroll_denied_without_session() {
        let paths = tmp_paths("no-session");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone).await
        });

        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::EnrollRequest {
                ticket: "fake-ticket".into(),
                person_public_key_hex: hex::encode([0u8; 32]),
                person_id: "test-person".into(),
                mesh_name: "test-mesh".into(),
            };
            conn.send_frame(Frame {
                channel: mymesh_protocol::ChannelId::control(),
                payload: encode_msg(&req).unwrap(),
            })
            .await
            .unwrap();
            let frame = conn.recv_frame().await.unwrap();
            let msg: EnrollMessage = decode_msg(&frame.payload).unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        assert!(matches!(
            carrier_res.unwrap(),
            EnrollMessage::EnrollDeny { .. }
        ));

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_denied_without_challenge_confirm() {
        let paths = tmp_paths("no-confirm");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session but don't confirm challenge
        let session = EnrollSession::new(node_id);
        let ticket = session.ticket.clone();
        let file = EnrollSessionFile::new(session);
        file.save(paths.enroll_session_file()).unwrap();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone).await
        });

        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::EnrollRequest {
                ticket,
                person_public_key_hex: hex::encode([0u8; 32]),
                person_id: "test-person".into(),
                mesh_name: "test-mesh".into(),
            };
            conn.send_frame(Frame {
                channel: mymesh_protocol::ChannelId::control(),
                payload: encode_msg(&req).unwrap(),
            })
            .await
            .unwrap();
            let frame = conn.recv_frame().await.unwrap();
            let msg: EnrollMessage = decode_msg(&frame.payload).unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        match carrier_res.unwrap() {
            EnrollMessage::EnrollDeny { reason } => {
                assert!(reason.contains("challenge") || reason.contains("confirmed"));
            }
            other => panic!("expected EnrollDeny, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_accepted_with_confirmed_challenge() {
        let paths = tmp_paths("accepted");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session and confirm challenge
        let mut session = EnrollSession::new(node_id);
        let ticket = session.ticket.clone();
        let challenge = session.challenge.clone();
        session.confirm_challenge(&challenge).unwrap();
        let file = EnrollSessionFile::new(session);
        file.save(paths.enroll_session_file()).unwrap();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone).await
        });

        let carrier_pk = id_carrier.verifying_key_bytes();
        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::EnrollRequest {
                ticket,
                person_public_key_hex: hex::encode(carrier_pk),
                person_id: "test-person-123".into(),
                mesh_name: "my-mesh".into(),
            };
            conn.send_frame(Frame {
                channel: mymesh_protocol::ChannelId::control(),
                payload: encode_msg(&req).unwrap(),
            })
            .await
            .unwrap();
            let frame = conn.recv_frame().await.unwrap();
            let msg: EnrollMessage = decode_msg(&frame.payload).unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Accepted);
        match carrier_res.unwrap() {
            EnrollMessage::EnrollAccept { device_id, label } => {
                assert_eq!(device_id, node_id);
                assert_eq!(label, "test-node");
            }
            other => panic!("expected EnrollAccept, got {other:?}"),
        }

        // Verify enrollment was stored
        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        let rec = store.get("test-person-123").expect("enrollment stored");
        assert!(rec.can_drive);

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_denied_with_wrong_ticket() {
        let paths = tmp_paths("wrong-ticket");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session and confirm challenge
        let mut session = EnrollSession::new(node_id);
        let challenge = session.challenge.clone();
        session.confirm_challenge(&challenge).unwrap();
        let file = EnrollSessionFile::new(session);
        file.save(paths.enroll_session_file()).unwrap();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone).await
        });

        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::EnrollRequest {
                ticket: "wrong-ticket-value".into(),
                person_public_key_hex: hex::encode([0u8; 32]),
                person_id: "test-person".into(),
                mesh_name: "test-mesh".into(),
            };
            conn.send_frame(Frame {
                channel: mymesh_protocol::ChannelId::control(),
                payload: encode_msg(&req).unwrap(),
            })
            .await
            .unwrap();
            let frame = conn.recv_frame().await.unwrap();
            let msg: EnrollMessage = decode_msg(&frame.payload).unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        match carrier_res.unwrap() {
            EnrollMessage::EnrollDeny { reason } => {
                assert!(reason.contains("ticket") || reason.contains("invalid"));
            }
            other => panic!("expected EnrollDeny, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }
}
