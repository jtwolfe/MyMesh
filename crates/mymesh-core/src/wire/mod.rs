//! Wave F1 wire freeze: AdminEnvelope, enroll, hint/seal, person_enrolled.
//!
//! Goldens under `testdata/wire/` match Carrier `carrier-core` (independently checked).
//! No HTTP handlers and no enroll persistence in this module.

pub mod admin;
pub mod enroll;
pub mod membership;

pub use admin::{
    admin_envelope_preimage, admin_seal_preimage, mailbox_bind_preimage, mailbox_id_from_url,
    parse_admin_envelope_json, parse_admin_seal_payload, person_enrolled_auth_preimage,
    unwrap_hint_blob, wrap_hint_blob, AdminEnvelope, AdminOp, AdminSealPayload, AdminWireError,
    HintBlob, IntroducePayload, MailboxBind, ADMIN_BIND_SKEW_SECS, ADMIN_ENVELOPE_DOMAIN,
    ADMIN_ENVELOPE_MAX_BYTES, ADMIN_ENVELOPE_VERSION, ADMIN_HINT_INFO, ADMIN_MAILBOX_MAX_BYTES,
    ADMIN_MAILBOX_POLL_MS, ADMIN_MAILBOX_TTL_SECS, ADMIN_SEAL_DOMAIN, HINT_BLOB_VERSION,
    MAILBOX_BIND_DOMAIN, PERSON_ENROLLED_METHOD,
};
pub use enroll::{
    carrier_enroll_v1_preimage, enroll_write_preimage, EnrollAckPayload, EnrollWriteBody,
    EnrollmentRecord, EnrollmentsFile, PersonFacet, SessionDecision, SessionPairDecision,
    ENROLLMENTS_FILE_VERSION, ENROLL_DOMAIN, ENROLL_FACET_PERSONAL, ENROLL_FACET_WORK,
};
pub use membership::{
    CatalogMembership, CatalogRole, MeshMembershipsFile, MESH_MEMBERSHIPS_FILE_VERSION,
};

use base64::Engine;

/// Encode bytes as base64url without padding.
pub fn encode_base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url (padding optional) into raw bytes.
pub fn decode_base64url(s: &str) -> Result<Vec<u8>, AdminWireError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AdminWireError::bad_request("empty base64url"));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|e| AdminWireError::bad_request(format!("invalid base64url: {e}")))
}

/// Decode 16-byte nonce from base64url.
pub fn decode_nonce16(s: &str) -> Result<[u8; 16], AdminWireError> {
    let raw = decode_base64url(s)?;
    <[u8; 16]>::try_from(raw.as_slice())
        .map_err(|_| AdminWireError::bad_request("nonce must decode to 16 bytes"))
}

/// Parse 32-byte id / key from 64 hex chars.
pub fn parse_id32_hex(hex_str: &str) -> Result<[u8; 32], AdminWireError> {
    let t = hex_str.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AdminWireError::bad_request(
            "expected 64 hex chars (32 bytes)",
        ));
    }
    let bytes = hex::decode(t).map_err(|_| AdminWireError::bad_request("invalid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode bytes as lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` → unix seconds (UTC).
pub fn parse_rfc3339_unix(ts: &str) -> Result<i64, AdminWireError> {
    let t = ts.trim();
    if t.len() != 20 || !t.ends_with('Z') {
        return Err(AdminWireError::bad_request(
            "timestamp must be YYYY-MM-DDTHH:MM:SSZ",
        ));
    }
    let b = t.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return Err(AdminWireError::bad_request(
            "timestamp must be YYYY-MM-DDTHH:MM:SSZ",
        ));
    }
    let year = parse_digits(&t[0..4])? as i32;
    let month = parse_digits(&t[5..7])?;
    let day = parse_digits(&t[8..10])?;
    let hour = parse_digits(&t[11..13])?;
    let min = parse_digits(&t[14..16])?;
    let sec = parse_digits(&t[17..19])?;
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || min > 59 || sec > 60 {
        return Err(AdminWireError::bad_request("timestamp out of range"));
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
}

fn parse_digits(s: &str) -> Result<u32, AdminWireError> {
    s.parse()
        .map_err(|_| AdminWireError::bad_request("timestamp digits"))
}

/// Howard Hinnant civil-to-days (days since Unix epoch).
fn days_from_civil(mut y: i32, m: u32, d: u32) -> i64 {
    if m <= 2 {
        y -= 1;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era) * 146_097 + i64::from(doe) - 719_468
}

pub(crate) fn write_u16le_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), AdminWireError> {
    let len =
        u16::try_from(data.len()).map_err(|_| AdminWireError::bad_request("length exceeds u16"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_wave_a() {
        assert_eq!(
            parse_rfc3339_unix("2026-08-12T12:00:00Z").unwrap(),
            1_786_536_000
        );
        assert_eq!(
            parse_rfc3339_unix("2026-08-13T12:00:00Z").unwrap(),
            1_786_622_400
        );
        assert_eq!(parse_rfc3339_unix("1970-01-01T00:00:00Z").unwrap(), 0);
    }
}
