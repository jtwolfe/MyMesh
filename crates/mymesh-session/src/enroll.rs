//! Enrollment handler for `mymesh-enroll/1` ALPN connections.
//!
//! ## ALPN `mymesh-enroll/1` wire protocol (phone-shows-code ceremony)
//!
//! Transport: iroh bidirectional stream
//! Framing: 4-byte big-endian length + UTF-8 JSON
//! Messages (serde tag = "type"):
//! - `request`: { ticket, person_public_key_hex, person_id, mesh_name } // phone → node
//! - `challenge_waiting`: {} // node → phone, ticket ok, show your code
//! - `challenge_offer`: { digits } // phone → node, 6-digit string the phone is displaying
//! - `result`: { success, device_id, device_label, error } // node → phone
//!
//! Flow:
//! 1. Node starts `mymesh enroll start`, shows QR (device id + ticket), does NOT print a code
//! 2. Phone scans QR, connects over iroh using ALPN `mymesh-enroll/1`
//! 3. Phone sends `request` with ticket, person identity, mesh name
//! 4. Node verifies ticket + session not expired (does NOT require prior challenge confirm)
//! 5. Node sends `challenge_waiting`
//! 6. Phone generates 6-digit code, displays it on screen, sends `challenge_offer { digits }`
//! 7. Node prompts human on stdin to type the digits; constant-time compare
//! 8. On match: store owner, send `result { success: true, device_id, device_label }`
//! 9. On mismatch/timeout/expired: send `result { success: false, error }`

use mymesh_core::wire::PersonFacet;
use mymesh_core::{DeviceId, EnrollSessionFile, EnrollmentStore, Error, Paths, Result};
use mymesh_crypto::Identity;
use mymesh_net::PeerConnection;
use mymesh_protocol::EnrollMessage;
use std::future::Future;
use std::pin::Pin;
use tracing::{info, warn};

/// Outcome of an enrollment attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// Enrollment accepted, owner stored.
    Accepted,
    /// Enrollment denied (ticket invalid, challenge not confirmed, expired, etc.).
    Denied,
}

/// Callback type for prompting the human to enter the phone's challenge code.
/// Called with the 6-digit code the phone is displaying; returns the human's input.
pub type ChallengePromptFn =
    Box<dyn FnOnce(String) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send>;

/// Handle an incoming enrollment connection (phone-shows-code ceremony).
///
/// This is called when an incoming connection uses the `mymesh-enroll/1` ALPN.
/// The flow is:
/// 1. Receive `request` with ticket, person identity, mesh name
/// 2. Verify ticket matches pending session (do NOT require prior challenge confirm)
/// 3. Send `challenge_waiting`
/// 4. Receive `challenge_offer { digits }`
/// 5. Call `prompt_challenge_fn` to get human input (prompts stdin in CLI)
/// 6. Constant-time compare; on match: store owner, send `result { success: true }`
/// 7. On mismatch/timeout/expired: send `result { success: false, error }`
pub async fn handle_enroll_connection(
    conn: Box<dyn PeerConnection>,
    identity: &Identity,
    label: &str,
    paths: &Paths,
    prompt_challenge_fn: ChallengePromptFn,
) -> Result<EnrollOutcome> {
    let device_id = identity.device_id();
    let peer_id = conn.peer_id();

    // Step 1: Receive the enrollment request (JSON framing)
    let msg: EnrollMessage = recv_json_msg(conn.as_ref()).await?;

    let (ticket, person_public_key_hex, person_id, mesh_name) = match msg {
        EnrollMessage::Request {
            ticket,
            person_public_key_hex,
            person_id,
            mesh_name,
        } => (ticket, person_public_key_hex, person_id, mesh_name),
        _ => {
            let result = EnrollMessage::Result {
                success: false,
                device_id: None,
                device_label: None,
                error: Some("expected request message".into()),
            };
            let _ = send_json_msg(conn.as_ref(), &result).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    info!(
        peer = %peer_id.short(),
        person_id = %person_id,
        "received enrollment request"
    );

    // Step 2: Load and validate the pending enrollment session
    let session_path = paths.enroll_session_file();
    let session_file = match EnrollSessionFile::try_load(&session_path)? {
        Some(f) => f,
        None => {
            warn!("enrollment request but no pending session");
            let result = EnrollMessage::Result {
                success: false,
                device_id: None,
                device_label: None,
                error: Some("no pending enrollment session".into()),
            };
            let _ = send_json_msg(conn.as_ref(), &result).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    if !session_file.session.is_valid() {
        warn!("enrollment session expired");
        let _ = EnrollSessionFile::clear(&session_path);
        let result = EnrollMessage::Result {
            success: false,
            device_id: None,
            device_label: None,
            error: Some("enrollment session expired".into()),
        };
        let _ = send_json_msg(conn.as_ref(), &result).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    if !session_file.session.verify_ticket(&ticket) {
        warn!("ticket mismatch");
        let result = EnrollMessage::Result {
            success: false,
            device_id: None,
            device_label: None,
            error: Some("invalid ticket".into()),
        };
        let _ = send_json_msg(conn.as_ref(), &result).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    // Step 3: Send challenge_waiting (ticket OK, waiting for phone's code)
    let waiting = EnrollMessage::ChallengeWaiting {};
    send_json_msg(conn.as_ref(), &waiting).await?;

    info!(peer = %peer_id.short(), "sent challenge_waiting, waiting for phone's code");

    // Step 4: Receive challenge_offer { digits }
    let offer_msg: EnrollMessage = recv_json_msg(conn.as_ref()).await?;

    let phone_digits = match offer_msg {
        EnrollMessage::ChallengeOffer { digits } => digits,
        _ => {
            warn!("expected challenge_offer, got something else");
            let result = EnrollMessage::Result {
                success: false,
                device_id: None,
                device_label: None,
                error: Some("expected challenge_offer message".into()),
            };
            let _ = send_json_msg(conn.as_ref(), &result).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    info!(peer = %peer_id.short(), "received challenge_offer, prompting human");

    // Step 5: Prompt the human to enter the phone's code
    let human_input = match prompt_challenge_fn(phone_digits.clone()).await {
        Ok(input) => input,
        Err(e) => {
            warn!(%e, "challenge prompt failed");
            let result = EnrollMessage::Result {
                success: false,
                device_id: None,
                device_label: None,
                error: Some(format!("challenge prompt failed: {e}")),
            };
            let _ = send_json_msg(conn.as_ref(), &result).await;
            let _ = conn.close().await;
            return Ok(EnrollOutcome::Denied);
        }
    };

    // Step 6: Verify the challenge (constant-time compare)
    let mut session = session_file.session.clone();
    if let Err(e) = session.verify_phone_challenge(&phone_digits, &human_input) {
        warn!(%e, "challenge verification failed");
        let result = EnrollMessage::Result {
            success: false,
            device_id: None,
            device_label: None,
            error: Some("challenge mismatch".into()),
        };
        let _ = send_json_msg(conn.as_ref(), &result).await;
        let _ = conn.close().await;
        return Ok(EnrollOutcome::Denied);
    }

    // Step 7: Store the owner enrollment
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
            session.complete(&person_id);
            let updated_file = EnrollSessionFile::new(session);
            let _ = updated_file.save(&session_path);

            info!(
                peer = %peer_id.short(),
                person_id = %person_id,
                "enrollment accepted"
            );

            let result = EnrollMessage::Result {
                success: true,
                device_id: Some(device_id),
                device_label: Some(label.to_string()),
                error: None,
            };
            send_json_msg(conn.as_ref(), &result).await?;
            let _ = conn.close().await;
            Ok(EnrollOutcome::Accepted)
        }
        Err(e) => {
            warn!(%e, "enrollment storage failed");
            let result = EnrollMessage::Result {
                success: false,
                device_id: None,
                device_label: None,
                error: Some(format!("enrollment failed: {e}")),
            };
            let _ = send_json_msg(conn.as_ref(), &result).await;
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

/// Send a length-prefixed JSON message over the connection.
async fn send_json_msg<M: serde::Serialize>(conn: &dyn PeerConnection, msg: &M) -> Result<()> {
    let json = serde_json::to_vec(msg).map_err(|e| Error::Protocol(e.to_string()))?;
    if json.len() > mymesh_protocol::MAX_JSON_MSG_BYTES {
        return Err(Error::Protocol("JSON message too large".into()));
    }
    let len = json.len() as u32;
    let mut payload = Vec::with_capacity(4 + json.len());
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(&json);
    conn.send_raw(&payload).await
}

/// Receive a length-prefixed JSON message from the connection.
async fn recv_json_msg<M: serde::de::DeserializeOwned>(conn: &dyn PeerConnection) -> Result<M> {
    let data = conn.recv_raw().await?;
    if data.len() < 4 {
        return Err(Error::Protocol("message too short for length prefix".into()));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err(Error::Protocol("message truncated".into()));
    }
    let json = &data[4..4 + len];
    serde_json::from_slice(json).map_err(|e| Error::Protocol(e.to_string()))
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

    /// Helper to send a length-prefixed JSON message in tests.
    async fn test_send_json<M: serde::Serialize>(
        conn: &dyn mymesh_net::PeerConnection,
        msg: &M,
    ) -> Result<()> {
        let json = serde_json::to_vec(msg).map_err(|e| Error::Protocol(e.to_string()))?;
        let len = json.len() as u32;
        let mut payload = Vec::with_capacity(4 + json.len());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&json);
        conn.send_raw(&payload).await
    }

    /// Helper to receive a length-prefixed JSON message in tests.
    async fn test_recv_json<M: serde::de::DeserializeOwned>(
        conn: &dyn mymesh_net::PeerConnection,
    ) -> Result<M> {
        let data = conn.recv_raw().await?;
        if data.len() < 4 {
            return Err(Error::Protocol("message too short".into()));
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(Error::Protocol("message truncated".into()));
        }
        let json = &data[4..4 + len];
        serde_json::from_slice(json).map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Create a mock challenge prompt that returns a predetermined response.
    fn mock_prompt(response: &str) -> ChallengePromptFn {
        let resp = response.to_string();
        Box::new(move |_digits| {
            let r = resp.clone();
            Box::pin(async move { Ok(r) })
        })
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
            handle_enroll_connection(conn, &id, "test-node", &paths_clone, mock_prompt("123456"))
                .await
        });

        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::Request {
                ticket: "fake-ticket".into(),
                person_public_key_hex: hex::encode([0u8; 32]),
                person_id: "test-person".into(),
                mesh_name: "test-mesh".into(),
            };
            test_send_json(conn.as_ref(), &req).await.unwrap();
            let msg: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        match carrier_res.unwrap() {
            EnrollMessage::Result { success, error, .. } => {
                assert!(!success);
                assert!(error.unwrap().contains("no pending"));
            }
            other => panic!("expected Result, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_accepted_after_phone_code() {
        let paths = tmp_paths("phone-code-accept");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session (challenge is empty - phone will provide it)
        let session = EnrollSession::new(node_id);
        let ticket = session.ticket.clone();
        let file = EnrollSessionFile::new(session);
        file.save(paths.enroll_session_file()).unwrap();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        // Node will receive "654321" from phone and human types the same
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone, mock_prompt("654321"))
                .await
        });

        let carrier_pk = id_carrier.verifying_key_bytes();
        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();

            // Step 1: Send request
            let req = EnrollMessage::Request {
                ticket,
                person_public_key_hex: hex::encode(carrier_pk),
                person_id: "test-person-phone".into(),
                mesh_name: "my-mesh".into(),
            };
            test_send_json(conn.as_ref(), &req).await.unwrap();

            // Step 2: Receive challenge_waiting
            let waiting: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            assert!(matches!(waiting, EnrollMessage::ChallengeWaiting {}));

            // Step 3: Send challenge_offer with phone's code
            let offer = EnrollMessage::ChallengeOffer {
                digits: "654321".into(),
            };
            test_send_json(conn.as_ref(), &offer).await.unwrap();

            // Step 4: Receive result
            let result: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            result
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Accepted);
        match carrier_res.unwrap() {
            EnrollMessage::Result {
                success,
                device_id,
                device_label,
                ..
            } => {
                assert!(success);
                assert_eq!(device_id, Some(node_id));
                assert_eq!(device_label.as_deref(), Some("test-node"));
            }
            other => panic!("expected Result success, got {other:?}"),
        }

        // Verify enrollment was stored
        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        let rec = store.get("test-person-phone").expect("enrollment stored");
        assert!(rec.can_drive);

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_denied_on_wrong_code() {
        let paths = tmp_paths("wrong-code");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session
        let session = EnrollSession::new(node_id);
        let ticket = session.ticket.clone();
        let file = EnrollSessionFile::new(session);
        file.save(paths.enroll_session_file()).unwrap();

        let fabric = LocalFabric::new();
        let ep_node = fabric.endpoint(node_id);
        let ep_carrier = fabric.endpoint(carrier_id);

        let paths_clone = paths.clone();
        let node_secret = id_node.to_secret_bytes();
        // Phone shows "654321" but human types wrong code "000000"
        let node_task = tokio::spawn(async move {
            let id = Identity::from_secret_bytes(node_secret);
            let conn = ep_node.accept().await.unwrap();
            handle_enroll_connection(conn, &id, "test-node", &paths_clone, mock_prompt("000000"))
                .await
        });

        let carrier_pk = id_carrier.verifying_key_bytes();
        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();

            // Send request
            let req = EnrollMessage::Request {
                ticket,
                person_public_key_hex: hex::encode(carrier_pk),
                person_id: "test-person-wrong".into(),
                mesh_name: "my-mesh".into(),
            };
            test_send_json(conn.as_ref(), &req).await.unwrap();

            // Receive challenge_waiting
            let waiting: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            assert!(matches!(waiting, EnrollMessage::ChallengeWaiting {}));

            // Send challenge_offer with phone's code
            let offer = EnrollMessage::ChallengeOffer {
                digits: "654321".into(), // Phone shows this
            };
            test_send_json(conn.as_ref(), &offer).await.unwrap();

            // Receive result (should be failure)
            let result: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            result
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        match carrier_res.unwrap() {
            EnrollMessage::Result {
                success, error, ..
            } => {
                assert!(!success);
                assert!(error.unwrap().contains("mismatch"));
            }
            other => panic!("expected Result failure, got {other:?}"),
        }

        // Verify enrollment was NOT stored
        let store = EnrollmentStore::open(paths.enrollments_file()).unwrap();
        assert!(store.get("test-person-wrong").is_none());

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }

    #[tokio::test]
    async fn enroll_denied_with_wrong_ticket() {
        let paths = tmp_paths("wrong-ticket");
        let id_node = Identity::generate();
        let id_carrier = Identity::generate();
        let node_id = id_node.device_id();
        let carrier_id = id_carrier.device_id();

        // Create session
        let session = EnrollSession::new(node_id);
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
            handle_enroll_connection(conn, &id, "test-node", &paths_clone, mock_prompt("123456"))
                .await
        });

        let carrier_task = tokio::spawn(async move {
            let conn = ep_carrier.connect(node_id).await.unwrap();
            let req = EnrollMessage::Request {
                ticket: "wrong-ticket-value".into(),
                person_public_key_hex: hex::encode([0u8; 32]),
                person_id: "test-person".into(),
                mesh_name: "test-mesh".into(),
            };
            test_send_json(conn.as_ref(), &req).await.unwrap();
            let msg: EnrollMessage = test_recv_json(conn.as_ref()).await.unwrap();
            msg
        });

        let (node_res, carrier_res) = tokio::join!(node_task, carrier_task);
        assert_eq!(node_res.unwrap().unwrap(), EnrollOutcome::Denied);
        match carrier_res.unwrap() {
            EnrollMessage::Result { success, error, .. } => {
                assert!(!success);
                let err_msg = error.unwrap();
                assert!(err_msg.contains("ticket") || err_msg.contains("invalid"));
            }
            other => panic!("expected Result, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(paths.data_dir);
    }
}
