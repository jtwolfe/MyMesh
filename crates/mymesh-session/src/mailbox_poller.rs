//! Serve-owned admin mailbox poller (F6). Self-host only — not a product.
//!
//! Fetches opaque inbox bytes, requires `carrier-admin-seal-v1`, verifies the
//! person signature via [`execute_admin_envelope`], posts the result to outbox.

use crate::mesh_api::{execute_admin_envelope, MeshApiState};
use axum::body::to_bytes;
use mymesh_core::wire::{
    mailbox_bind_preimage, parse_admin_envelope_json, parse_admin_seal_payload, MailboxBind,
    ADMIN_MAILBOX_POLL_MS,
};
use mymesh_core::{Paths, RateLimitState};
use mymesh_crypto::{open_admin_envelope, Identity};
use mymesh_net::{AdminMailboxClient, AdminMailboxError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Spawn a standing poller. No-op if `mailbox_url` is empty.
pub fn spawn_admin_mailbox_poller(
    paths: Paths,
    secret: [u8; 32],
    label: String,
    mailbox_url: String,
) {
    let url = mailbox_url.trim().trim_end_matches('/');
    if url.is_empty() {
        return;
    }
    let url = url.to_string();
    tokio::spawn(async move {
        let client = AdminMailboxClient::new(&url);
        let identity = Identity::from_secret_bytes(secret);
        let did = identity.device_id().to_string();
        let st = MeshApiState {
            paths,
            rate_limits: Arc::new(RateLimitState::new()),
            secret,
            label,
            auth: Arc::new(Mutex::new(Default::default())),
        };
        info!(
            did = %identity.device_id().short(),
            "mailbox_poller start (self-host, not a product)"
        );
        loop {
            if let Err(e) = bind_once(&client, &identity).await {
                warn!(error = %e, "mailbox bind failed");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            match poll_once(&client, &identity, &st, &did).await {
                Ok(PollOutcome::Empty) => {
                    info!(did = %identity.device_id().short(), result = "empty", "mailbox_poll");
                }
                Ok(PollOutcome::Full) => {
                    info!(did = %identity.device_id().short(), result = "full", "mailbox_poll");
                }
                Err(e) => {
                    warn!(error = %e, "mailbox_poll");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });
}

enum PollOutcome {
    Empty,
    Full,
}

async fn bind_once(
    client: &AdminMailboxClient,
    identity: &Identity,
) -> Result<(), AdminMailboxError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let did = identity.device_id();
    let pre = mailbox_bind_preimage(did.as_bytes(), ts);
    let body = MailboxBind {
        did: did.to_string(),
        ts,
        sig_hex: hex::encode(identity.sign(&pre)),
    };
    client.bind(&body).await
}

async fn poll_once(
    client: &AdminMailboxClient,
    identity: &Identity,
    st: &MeshApiState,
    did: &str,
) -> Result<PollOutcome, AdminMailboxError> {
    let blob = match client.get_inbox(did, ADMIN_MAILBOX_POLL_MS).await {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(PollOutcome::Empty),
        Err(AdminMailboxError::Unbound) => {
            bind_once(client, identity).await?;
            return Ok(PollOutcome::Empty);
        }
        Err(e) => return Err(e),
    };

    let out = match handle_inbox_blob(st, &identity.to_secret_bytes(), &blob).await {
        Ok(bytes) => bytes,
        Err(bytes) => bytes,
    };
    if let Err(e) = client.put_outbox(did, &out).await {
        warn!(error = %e, "mailbox outbox put");
    }
    Ok(PollOutcome::Full)
}

/// Decrypt + execute. Always returns an outbox JSON body (ok or error).
async fn handle_inbox_blob(
    st: &MeshApiState,
    device_seed: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    let seal = parse_admin_seal_payload(blob).map_err(|e| {
        serde_json::to_vec(&serde_json::json!({
            "code": e.code,
            "error": e.message,
        }))
        .unwrap_or_else(|_| b"{\"code\":\"bad_request\",\"error\":\"seal required\"}".to_vec())
    })?;
    let plain = open_admin_envelope(device_seed, &seal).map_err(|e| {
        serde_json::to_vec(&serde_json::json!({
            "code": "bad_request",
            "error": e.to_string(),
        }))
        .unwrap_or_else(|_| b"{\"code\":\"bad_request\",\"error\":\"unseal failed\"}".to_vec())
    })?;
    let text = String::from_utf8(plain).map_err(|_| {
        b"{\"code\":\"bad_request\",\"error\":\"seal plaintext not utf8\"}".to_vec()
    })?;
    let env = parse_admin_envelope_json(&text).map_err(|e| {
        serde_json::to_vec(&serde_json::json!({
            "code": e.code,
            "error": e.message,
        }))
        .unwrap_or_else(|_| b"{\"code\":\"bad_request\",\"error\":\"envelope\"}".to_vec())
    })?;
    let resp = execute_admin_envelope(st, env, "mailbox");
    let bytes = to_bytes(resp.into_body(), 64 * 1024)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_else(|_| b"{\"code\":\"internal\",\"error\":\"mailbox exec body\"}".to_vec());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_api::MeshApiState;
    use chrono::{SecondsFormat, Utc};
    use mymesh_core::wire::{
        admin_envelope_preimage, AdminEnvelope, AdminOp, IntroducePayload, PersonFacet,
    };
    use mymesh_core::{EnrollmentStore, MeshState, Paths};
    use mymesh_crypto::seal_admin_envelope;
    use rand::RngCore;

    fn tmp_paths() -> Paths {
        let root = std::env::temp_dir().join(format!(
            "mymesh-mbox-poll-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let paths = Paths {
            config_dir: root.join("cfg"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        };
        paths.ensure().unwrap();
        paths
    }

    fn test_state(paths: Paths, secret: [u8; 32]) -> MeshApiState {
        MeshApiState {
            paths,
            rate_limits: Arc::new(RateLimitState::new()),
            secret,
            label: "joiner".into(),
            auth: Arc::new(Mutex::new(Default::default())),
        }
    }

    #[tokio::test]
    async fn seal_required_rejects_raw_envelope() {
        let secret = [0xB6u8; 32];
        let st = test_state(tmp_paths(), secret);
        let raw = br#"{"v":1,"op":"introduce","target_device_id_hex":"bb","ts":"2026-08-13T12:00:00Z","nonce":"MzMzMzMzMzMzMzMzMzMzMw","person_id":"p","facet":"personal","payload_json":"{}","sig_hex":"00"}"#;
        let out = match handle_inbox_blob(&st, &secret, raw).await {
            Ok(b) | Err(b) => b,
        };
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["code"], "bad_request");
        assert!(v["error"].as_str().unwrap().contains("seal required"));
    }

    #[tokio::test]
    async fn sealed_introduce_executes_on_enrolled_joiner() {
        let secret = [0xB7u8; 32];
        let joiner = Identity::from_secret_bytes(secret);
        let resident = Identity::from_secret_bytes([0xA7u8; 32]);
        let person = Identity::from_secret_bytes([0x42u8; 32]);
        let paths = tmp_paths();
        MeshState::new_mesh().save(paths.mesh_file()).unwrap();
        let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let ts_unix = mymesh_core::wire::parse_rfc3339_unix(&ts).unwrap();
        let pid = "01HZXPERSON0000000000000";
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let enroll = mymesh_core::wire::EnrollWriteBody {
            person_id: pid.into(),
            facet: PersonFacet::Personal,
            target_device_id_hex: joiner.device_id().to_string(),
            ts: ts.clone(),
            nonce: mymesh_core::wire::encode_base64url(&nonce),
            person_public_key_hex: hex::encode(person.verifying_key_bytes()),
            sig_hex: {
                let pre = mymesh_core::wire::carrier_enroll_v1_preimage(
                    pid,
                    PersonFacet::Personal,
                    joiner.device_id().as_bytes(),
                    ts_unix,
                    &nonce,
                    &person.verifying_key_bytes(),
                )
                .unwrap();
                hex::encode(person.sign(&pre))
            },
            label: None,
        };
        let mut store = EnrollmentStore::open_or_create(paths.enrollments_file()).unwrap();
        store.add(&joiner.device_id(), &enroll).unwrap();

        let payload = IntroducePayload {
            resident_did: resident.device_id().to_string(),
            joiner_did: joiner.device_id().to_string(),
            resident_fp: None,
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let env_nonce = [0x23u8; 16];
        let pre = admin_envelope_preimage(
            AdminOp::Introduce,
            joiner.device_id().as_bytes(),
            "",
            ts_unix,
            &env_nonce,
            &person.verifying_key_bytes(),
            payload_json.as_bytes(),
        )
        .unwrap();
        let env = AdminEnvelope {
            v: 1,
            op: AdminOp::Introduce,
            target_device_id_hex: joiner.device_id().to_string(),
            mesh_id: None,
            ts,
            nonce: mymesh_core::wire::encode_base64url(&env_nonce),
            person_id: pid.into(),
            facet: PersonFacet::Personal,
            payload_json,
            sig_hex: hex::encode(person.sign(&pre)),
        };
        let json = serde_json::to_vec(&env).unwrap();
        let sealed = seal_admin_envelope(&joiner.verifying_key_bytes(), &json).unwrap();
        let blob = serde_json::to_vec(&sealed).unwrap();
        let st = test_state(paths, secret);
        let out = match handle_inbox_blob(&st, &secret, &blob).await {
            Ok(b) | Err(b) => b,
        };
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "dialing");
        assert_eq!(v["joiner_did"], joiner.device_id().to_string());
    }
}
