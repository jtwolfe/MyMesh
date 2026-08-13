//! Enrollment wire types and `carrier-enroll-v1` preimage (Wave F1).

use super::{
    decode_nonce16, parse_id32_hex, parse_rfc3339_unix, write_u16le_bytes, AdminWireError,
};
use serde::{Deserialize, Serialize};

/// Domain separator for every enroll write.
pub const ENROLL_DOMAIN: &[u8] = b"carrier-enroll-v1";
/// Facet byte: personal.
pub const ENROLL_FACET_PERSONAL: u8 = 0x01;
/// Facet byte: work.
pub const ENROLL_FACET_WORK: u8 = 0x02;
/// `enrollments.json` schema version.
pub const ENROLLMENTS_FILE_VERSION: u32 = 1;

/// Person signing context on the enroll / admin wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonFacet {
    Personal,
    Work,
}

impl PersonFacet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Work => "work",
        }
    }

    pub fn as_enroll_byte(self) -> u8 {
        match self {
            Self::Personal => ENROLL_FACET_PERSONAL,
            Self::Work => ENROLL_FACET_WORK,
        }
    }

    pub fn from_enroll_byte(b: u8) -> Option<Self> {
        match b {
            ENROLL_FACET_PERSONAL => Some(Self::Personal),
            ENROLL_FACET_WORK => Some(Self::Work),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(Self::Personal),
            "work" => Some(Self::Work),
            _ => None,
        }
    }
}

/// Accept or deny a pending join (`SessionDecision.decision`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPairDecision {
    Accept,
    Deny,
}

/// `POST /pair/v2/decide` body. Additive enroll fields are `serde(default)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDecision {
    pub sid: String,
    pub decision: SessionPairDecision,
    pub joiner_device_id_hex: String,
    pub resident_device_id_hex: String,
    /// RFC3339.
    pub ts: String,
    /// Session nonce (base64url 16B).
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_id: Option<String>,
    /// Wave A: optional audit sig. Enroll path: `carrier-enroll-v1` sig when
    /// `person_id`, `facet`, and `person_public_key_hex` are also present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet: Option<PersonFacet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_public_key_hex: Option<String>,
}

impl SessionDecision {
    /// True when all four enroll fields are present (verify `carrier-enroll-v1` next).
    pub fn enroll_fields_present(&self) -> bool {
        self.person_id.is_some()
            && self.facet.is_some()
            && self.person_public_key_hex.is_some()
            && self.sig_hex.is_some()
    }
}

/// `POST /mesh/v1/enrollments` body (and enroll preimage inputs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollWriteBody {
    pub person_id: String,
    pub facet: PersonFacet,
    pub target_device_id_hex: String,
    pub ts: String,
    /// base64url of 16 raw bytes.
    pub nonce: String,
    pub person_public_key_hex: String,
    pub sig_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// `AdminEnvelope` `op=enroll_ack` payload: same as [`EnrollWriteBody`] with
/// `sig_hex` renamed `enroll_sig_hex`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollAckPayload {
    pub person_id: String,
    pub facet: PersonFacet,
    pub target_device_id_hex: String,
    pub ts: String,
    pub nonce: String,
    pub person_public_key_hex: String,
    pub enroll_sig_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One verified drive binding (`enrollments.json` row).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub enrollment_id: String,
    pub person_id: String,
    pub person_public_key_hex: String,
    pub facet: PersonFacet,
    pub enrolled_at: String,
    pub can_drive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Node enrollments file shape (`Paths::enrollments_file`, mode 0600).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentsFile {
    pub version: u32,
    pub enrollments: Vec<EnrollmentRecord>,
}

/// Canonical enroll preimage:
///
/// ```text
/// carrier-enroll-v1
///   || u16le(len) || person_id_utf8
///   || u8 facet                 // 0x01 personal, 0x02 work
///   || target_did_32
///   || i64le(ts_unix)
///   || nonce_16
///   || person_pk_32
/// ```
pub fn carrier_enroll_v1_preimage(
    person_id: &str,
    facet: PersonFacet,
    target_did: &[u8; 32],
    ts_unix: i64,
    nonce: &[u8; 16],
    person_pk: &[u8; 32],
) -> Result<Vec<u8>, AdminWireError> {
    let mut out =
        Vec::with_capacity(ENROLL_DOMAIN.len() + 2 + person_id.len() + 1 + 32 + 8 + 16 + 32);
    out.extend_from_slice(ENROLL_DOMAIN);
    write_u16le_bytes(&mut out, person_id.as_bytes())?;
    out.push(facet.as_enroll_byte());
    out.extend_from_slice(target_did);
    out.extend_from_slice(&ts_unix.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(person_pk);
    Ok(out)
}

/// Build [`carrier_enroll_v1_preimage`] from an enroll-write body.
pub fn enroll_write_preimage(body: &EnrollWriteBody) -> Result<Vec<u8>, AdminWireError> {
    let target = parse_id32_hex(&body.target_device_id_hex)?;
    let pk = parse_id32_hex(&body.person_public_key_hex)?;
    let nonce = decode_nonce16(&body.nonce)?;
    let ts = parse_rfc3339_unix(&body.ts)?;
    carrier_enroll_v1_preimage(&body.person_id, body.facet, &target, ts, &nonce, &pk)
}

impl SessionDecision {
    /// Build `carrier-enroll-v1` when all four enroll fields are present.
    pub fn enroll_preimage(&self) -> Result<Option<Vec<u8>>, AdminWireError> {
        let (Some(person_id), Some(facet), Some(pk_hex), Some(_)) = (
            self.person_id.as_deref(),
            self.facet,
            self.person_public_key_hex.as_deref(),
            self.sig_hex.as_deref(),
        ) else {
            return Ok(None);
        };
        let target = parse_id32_hex(&self.resident_device_id_hex)?;
        let pk = parse_id32_hex(pk_hex)?;
        let nonce = decode_nonce16(&self.nonce)?;
        let ts = parse_rfc3339_unix(&self.ts)?;
        Ok(Some(carrier_enroll_v1_preimage(
            person_id, facet, &target, ts, &nonce, &pk,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::encode_base64url;

    #[test]
    fn facet_wire_and_byte() {
        assert_eq!(
            serde_json::to_string(&PersonFacet::Personal).unwrap(),
            "\"personal\""
        );
        assert_eq!(PersonFacet::Work.as_enroll_byte(), 0x02);
        assert!(PersonFacet::from_enroll_byte(0x00).is_none());
    }

    #[test]
    fn session_decision_wave_a_omits_enroll_fields() {
        let d = SessionDecision {
            sid: "01HZXPAIRSESSION0000000000".into(),
            decision: SessionPairDecision::Accept,
            joiner_device_id_hex: "b2".repeat(32),
            resident_device_id_hex: "a1".repeat(32),
            ts: "2026-08-12T12:00:00Z".into(),
            nonce: encode_base64url(&[0x22; 16]),
            person_id: None,
            sig_hex: None,
            facet: None,
            person_public_key_hex: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("facet"));
        assert!(!obj.contains_key("person_public_key_hex"));
        assert!(!obj.contains_key("person_id"));
        assert!(!obj.contains_key("sig_hex"));
        assert!(!d.enroll_fields_present());
        assert!(d.enroll_preimage().unwrap().is_none());
    }

    #[test]
    fn enroll_preimage_layout() {
        let pk = [9u8; 32];
        let did = [0xa1u8; 32];
        let nonce = [0x33u8; 16];
        let pre = carrier_enroll_v1_preimage(
            "pid",
            PersonFacet::Personal,
            &did,
            1_786_622_400,
            &nonce,
            &pk,
        )
        .unwrap();
        assert!(pre.starts_with(ENROLL_DOMAIN));
        let off = ENROLL_DOMAIN.len();
        assert_eq!(u16::from_le_bytes([pre[off], pre[off + 1]]), 3);
        assert_eq!(pre[off + 2 + 3], ENROLL_FACET_PERSONAL);
        let work =
            carrier_enroll_v1_preimage("pid", PersonFacet::Work, &did, 1_786_622_400, &nonce, &pk)
                .unwrap();
        assert_ne!(pre, work);
    }
}
