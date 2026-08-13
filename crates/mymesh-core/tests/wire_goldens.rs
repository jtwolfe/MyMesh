//! Independent F1 goldens (must match Carrier `carrier-core` testdata/wire).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mymesh_core::wire::{
    admin_envelope_preimage, admin_seal_preimage, carrier_enroll_v1_preimage, decode_base64url,
    decode_nonce16, encode_base64url, encode_hex, mailbox_bind_preimage, parse_admin_envelope_json,
    parse_id32_hex, parse_rfc3339_unix, person_enrolled_auth_preimage, unwrap_hint_blob,
    wrap_hint_blob, AdminEnvelope, AdminOp, EnrollWriteBody, HintBlob, PersonFacet,
    SessionDecision, ADMIN_ENVELOPE_DOMAIN, ADMIN_SEAL_DOMAIN, ENROLL_DOMAIN, MAILBOX_BIND_DOMAIN,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/wire")
        .join(name)
}

fn read_str(name: &str) -> String {
    std::fs::read_to_string(testdata(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn assert_json_roundtrip<T>(name: &str, value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let file_val: serde_json::Value = serde_json::from_str(&read_str(name)).unwrap();
    let ser_val = serde_json::to_value(value).unwrap();
    assert_eq!(ser_val, file_val, "serialize({name}) must match golden");
    let decoded: T = serde_json::from_value(file_val.clone()).unwrap();
    assert_eq!(&decoded, value);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), file_val);
}

fn golden_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

const GOLDEN_PUBKEY_HEX: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const PERSON_ID: &str = "01HZXPERSON0000000000000";
const MESH_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const SID: &str = "01HZXPAIRSESSION0000000000";
const CHALLENGE_ID: &str = "01HZXCHALLENGE00000000000";
const HINT_URL: &str = "http://192.168.1.10:17878";
const TS_DECIDE: &str = "2026-08-12T12:00:00Z";
const TS_ENROLL: &str = "2026-08-13T12:00:00Z";
const TS_ENROLL_UNIX: i64 = 1_786_622_400;
const TS_DECIDE_UNIX: i64 = 1_786_536_000;

fn target_did() -> [u8; 32] {
    [0xa1u8; 32]
}

fn person_pk() -> [u8; 32] {
    parse_id32_hex(GOLDEN_PUBKEY_HEX).unwrap()
}

fn sign_hex(pre: &[u8]) -> String {
    encode_hex(&golden_signing_key().sign(pre).to_bytes())
}

#[test]
fn generate_f1_goldens_when_env_set() {
    if std::env::var("GENERATE_F1_GOLDENS").ok().as_deref() != Some("1") {
        return;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/wire");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, s: &str| {
        std::fs::write(dir.join(name), s).unwrap();
    };

    let wave_a = serde_json::json!({
        "sid": SID,
        "decision": "accept",
        "joiner_device_id_hex": "b2".repeat(32),
        "resident_device_id_hex": "a1".repeat(32),
        "ts": TS_DECIDE,
        "nonce": "IiIiIiIiIiIiIiIiIiIiIg"
    });
    write(
        "session_decision.json",
        &format!("{}\n", serde_json::to_string_pretty(&wave_a).unwrap()),
    );

    let nonce_pair = [0x22u8; 16];
    let decide_pre = carrier_enroll_v1_preimage(
        PERSON_ID,
        PersonFacet::Personal,
        &target_did(),
        TS_DECIDE_UNIX,
        &nonce_pair,
        &person_pk(),
    )
    .unwrap();
    let decide_sig = sign_hex(&decide_pre);
    let enroll_decide = SessionDecision {
        sid: SID.into(),
        decision: mymesh_core::wire::SessionPairDecision::Accept,
        joiner_device_id_hex: "b2".repeat(32),
        resident_device_id_hex: "a1".repeat(32),
        ts: TS_DECIDE.into(),
        nonce: encode_base64url(&nonce_pair),
        person_id: Some(PERSON_ID.into()),
        sig_hex: Some(decide_sig),
        facet: Some(PersonFacet::Personal),
        person_public_key_hex: Some(GOLDEN_PUBKEY_HEX.into()),
    };
    write(
        "session-decision-enroll.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&enroll_decide).unwrap()
        ),
    );

    let nonce_enroll = [0x33u8; 16];
    let enroll_pre = carrier_enroll_v1_preimage(
        PERSON_ID,
        PersonFacet::Personal,
        &target_did(),
        TS_ENROLL_UNIX,
        &nonce_enroll,
        &person_pk(),
    )
    .unwrap();
    write(
        "carrier-enroll-v1.hex",
        &format!("{}\n", encode_hex(&enroll_pre)),
    );
    let enroll_body = EnrollWriteBody {
        person_id: PERSON_ID.into(),
        facet: PersonFacet::Personal,
        target_device_id_hex: "a1".repeat(32),
        ts: TS_ENROLL.into(),
        nonce: encode_base64url(&nonce_enroll),
        person_public_key_hex: GOLDEN_PUBKEY_HEX.into(),
        sig_hex: sign_hex(&enroll_pre),
        label: Some("kitchen-phone".into()),
    };
    write(
        "carrier-enroll-v1.json",
        &format!("{}\n", serde_json::to_string_pretty(&enroll_body).unwrap()),
    );

    let ack = mymesh_core::wire::EnrollAckPayload {
        person_id: PERSON_ID.into(),
        facet: PersonFacet::Personal,
        target_device_id_hex: "a1".repeat(32),
        ts: TS_ENROLL.into(),
        nonce: encode_base64url(&nonce_enroll),
        person_public_key_hex: GOLDEN_PUBKEY_HEX.into(),
        enroll_sig_hex: enroll_body.sig_hex.clone(),
        label: Some("kitchen-phone".into()),
    };
    let payload = serde_json::to_string(&ack).unwrap();
    write("admin_envelope_payload.json", &format!("{payload}\n"));

    let env_pre = admin_envelope_preimage(
        AdminOp::EnrollAck,
        &target_did(),
        MESH_ID,
        TS_ENROLL_UNIX,
        &nonce_enroll,
        &person_pk(),
        payload.as_bytes(),
    )
    .unwrap();
    write(
        "admin_envelope_preimage.hex",
        &format!("{}\n", encode_hex(&env_pre)),
    );
    let env = AdminEnvelope {
        v: 1,
        op: AdminOp::EnrollAck,
        target_device_id_hex: "a1".repeat(32),
        mesh_id: Some(MESH_ID.into()),
        ts: TS_ENROLL.into(),
        nonce: encode_base64url(&nonce_enroll),
        person_id: PERSON_ID.into(),
        facet: PersonFacet::Personal,
        payload_json: payload,
        sig_hex: sign_hex(&env_pre),
    };
    write(
        "admin_envelope.json",
        &format!("{}\n", serde_json::to_string_pretty(&env).unwrap()),
    );

    let blob = wrap_hint_blob(&[0x42u8; 32], &target_did(), HINT_URL, &[0x55u8; 24]).unwrap();
    write(
        "hint_blob.json",
        &format!("{}\n", serde_json::to_string_pretty(&blob).unwrap()),
    );

    write(
        "mailbox_bind_preimage.hex",
        &format!(
            "{}\n",
            encode_hex(&mailbox_bind_preimage(&target_did(), TS_ENROLL_UNIX))
        ),
    );
    write(
        "admin_seal_preimage.hex",
        &format!(
            "{}\n",
            encode_hex(&admin_seal_preimage(&nonce_enroll, &env_pre))
        ),
    );
    write(
        "person_enrolled_preimage.hex",
        &format!(
            "{}\n",
            encode_hex(&person_enrolled_auth_preimage(
                CHALLENGE_ID,
                &[0x44u8; 32],
                &target_did()
            ))
        ),
    );
}

fn verify_sig(pre: &[u8], sig_hex: &str) {
    let vk = VerifyingKey::from_bytes(&person_pk()).unwrap();
    let raw = hex::decode(sig_hex).unwrap();
    let sig = Signature::from_bytes(&<[u8; 64]>::try_from(raw.as_slice()).unwrap());
    vk.verify(pre, &sig).expect("golden signature must verify");
}

#[test]
fn golden_session_decision_wave_a_roundtrip() {
    let d = SessionDecision {
        sid: SID.into(),
        decision: mymesh_core::wire::SessionPairDecision::Accept,
        joiner_device_id_hex: "b2".repeat(32),
        resident_device_id_hex: "a1".repeat(32),
        ts: TS_DECIDE.into(),
        nonce: "IiIiIiIiIiIiIiIiIiIiIg".into(),
        person_id: None,
        sig_hex: None,
        facet: None,
        person_public_key_hex: None,
    };
    assert_json_roundtrip("session_decision.json", &d);
    assert!(!d.enroll_fields_present());
}

#[test]
fn golden_session_decision_enroll() {
    let nonce = [0x22u8; 16];
    let pre = carrier_enroll_v1_preimage(
        PERSON_ID,
        PersonFacet::Personal,
        &target_did(),
        TS_DECIDE_UNIX,
        &nonce,
        &person_pk(),
    )
    .unwrap();
    let sig = sign_hex(&pre);
    let d = SessionDecision {
        sid: SID.into(),
        decision: mymesh_core::wire::SessionPairDecision::Accept,
        joiner_device_id_hex: "b2".repeat(32),
        resident_device_id_hex: "a1".repeat(32),
        ts: TS_DECIDE.into(),
        nonce: encode_base64url(&nonce),
        person_id: Some(PERSON_ID.into()),
        sig_hex: Some(sig.clone()),
        facet: Some(PersonFacet::Personal),
        person_public_key_hex: Some(GOLDEN_PUBKEY_HEX.into()),
    };
    assert_json_roundtrip("session-decision-enroll.json", &d);
    assert!(d.enroll_fields_present());
    let built = d.enroll_preimage().unwrap().unwrap();
    assert_eq!(built, pre);
    verify_sig(&pre, &sig);
}

#[test]
fn golden_carrier_enroll_v1() {
    let nonce = [0x33u8; 16];
    let pre = carrier_enroll_v1_preimage(
        PERSON_ID,
        PersonFacet::Personal,
        &target_did(),
        TS_ENROLL_UNIX,
        &nonce,
        &person_pk(),
    )
    .unwrap();
    assert!(pre.starts_with(ENROLL_DOMAIN));
    assert_eq!(encode_hex(&pre), read_str("carrier-enroll-v1.hex").trim());
    let sig = sign_hex(&pre);
    let body = EnrollWriteBody {
        person_id: PERSON_ID.into(),
        facet: PersonFacet::Personal,
        target_device_id_hex: "a1".repeat(32),
        ts: TS_ENROLL.into(),
        nonce: encode_base64url(&nonce),
        person_public_key_hex: GOLDEN_PUBKEY_HEX.into(),
        sig_hex: sig,
        label: Some("kitchen-phone".into()),
    };
    assert_json_roundtrip("carrier-enroll-v1.json", &body);
    assert_eq!(
        mymesh_core::wire::enroll_write_preimage(&body).unwrap(),
        pre
    );
    verify_sig(&pre, &body.sig_hex);
}

#[test]
fn golden_admin_envelope_preimage() {
    let nonce = [0x33u8; 16];
    let payload = read_str("admin_envelope_payload.json");
    let payload = payload.trim();
    let pre = admin_envelope_preimage(
        AdminOp::EnrollAck,
        &target_did(),
        MESH_ID,
        TS_ENROLL_UNIX,
        &nonce,
        &person_pk(),
        payload.as_bytes(),
    )
    .unwrap();
    assert!(pre.starts_with(ADMIN_ENVELOPE_DOMAIN));
    assert_eq!(
        encode_hex(&pre),
        read_str("admin_envelope_preimage.hex").trim()
    );
    let sig = sign_hex(&pre);
    let env = AdminEnvelope {
        v: 1,
        op: AdminOp::EnrollAck,
        target_device_id_hex: "a1".repeat(32),
        mesh_id: Some(MESH_ID.into()),
        ts: TS_ENROLL.into(),
        nonce: encode_base64url(&nonce),
        person_id: PERSON_ID.into(),
        facet: PersonFacet::Personal,
        payload_json: payload.to_string(),
        sig_hex: sig,
    };
    assert_json_roundtrip("admin_envelope.json", &env);
    assert_eq!(env.preimage(&person_pk()).unwrap(), pre);
    verify_sig(&pre, &env.sig_hex);

    let parsed = parse_admin_envelope_json(&read_str("admin_envelope.json")).unwrap();
    assert_eq!(parsed, env);
}

#[test]
fn golden_unknown_admin_op_fail_closed() {
    let mut v: serde_json::Value = serde_json::from_str(&read_str("admin_envelope.json")).unwrap();
    v["op"] = serde_json::Value::String("topology".into());
    let err = parse_admin_envelope_json(&v.to_string()).unwrap_err();
    assert_eq!(err.code, "bad_request");
}

#[test]
fn golden_hint_blob() {
    let seed = [0x42u8; 32];
    let nonce = [0x55u8; 24];
    let blob = wrap_hint_blob(&seed, &target_did(), HINT_URL, &nonce).unwrap();
    assert_json_roundtrip("hint_blob.json", &blob);
    assert_eq!(
        unwrap_hint_blob(&seed, &target_did(), &blob).unwrap(),
        HINT_URL
    );
    let file: HintBlob = serde_json::from_str(&read_str("hint_blob.json")).unwrap();
    assert_eq!(file, blob);
}

#[test]
fn golden_mailbox_bind_preimage() {
    let pre = mailbox_bind_preimage(&target_did(), TS_ENROLL_UNIX);
    assert!(pre.starts_with(MAILBOX_BIND_DOMAIN));
    assert_eq!(
        encode_hex(&pre),
        read_str("mailbox_bind_preimage.hex").trim()
    );
}

#[test]
fn golden_admin_seal_preimage() {
    let env_pre = hex::decode(read_str("admin_envelope_preimage.hex").trim()).unwrap();
    let pre = admin_seal_preimage(&[0x33u8; 16], &env_pre);
    assert!(pre.starts_with(ADMIN_SEAL_DOMAIN));
    assert_eq!(encode_hex(&pre), read_str("admin_seal_preimage.hex").trim());
}

#[test]
fn golden_person_enrolled_auth_preimage() {
    let nonce = [0x44u8; 32];
    let pre = person_enrolled_auth_preimage(CHALLENGE_ID, &nonce, &target_did());
    assert_eq!(
        encode_hex(&pre),
        read_str("person_enrolled_preimage.hex").trim()
    );
    // Bound to raw device id, not a mesh UUID string.
    assert!(!String::from_utf8_lossy(&pre).contains(MESH_ID));
}

#[test]
fn golden_constants_and_nonce_decode() {
    assert_eq!(parse_rfc3339_unix(TS_ENROLL).unwrap(), TS_ENROLL_UNIX);
    assert_eq!(
        decode_nonce16("IiIiIiIiIiIiIiIiIiIiIg").unwrap(),
        [0x22u8; 16]
    );
    assert_eq!(
        decode_base64url("MzMzMzMzMzMzMzMzMzMzMw").unwrap(),
        [0x33u8; 16]
    );
}
