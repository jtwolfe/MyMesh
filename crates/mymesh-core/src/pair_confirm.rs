//! Pair v2 confirm-code algorithm (PAIR-V2.md / carrier-core goldens).
//!
//! ```text
//! pepper = bootstrap_token_raw (32B)
//! material = "mymesh-pair-confirm-v1" || flag || sid || joiner_did || resident_did || nonce_raw
//! flag = 0x01 accept | 0x00 deny
//! code = Crockford-base32(truncate(HMAC-SHA256(pepper, material), 5 bytes))  // 8 chars → 4-4
//! ```
//!
//! `joiner_did` / `resident_did` are lowercase hex strings (DeviceId Display).
//! `nonce` is the raw 16 bytes (not base64url ASCII).

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Domain separation for confirm HMAC material.
pub const CONFIRM_DOMAIN: &[u8] = b"mymesh-pair-confirm-v1";
pub const CONFIRM_FLAG_ACCEPT: u8 = 0x01;
pub const CONFIRM_FLAG_DENY: u8 = 0x00;
pub const CONFIRM_HMAC_TRUNCATE: usize = 5;
pub const PAIR_NONCE_LEN: usize = 16;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Accept + deny confirm codes in display form (`XXXX-XXXX`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmCodes {
    /// Display form for accept (Crockford 4-4).
    pub accept: String,
    /// Display form for deny (Crockford 4-4).
    pub deny: String,
}

/// Build HMAC material for confirm codes.
pub fn confirm_code_material(
    accept: bool,
    sid: &str,
    joiner_did: &str,
    resident_did: &str,
    nonce: &[u8; PAIR_NONCE_LEN],
) -> Vec<u8> {
    let flag = if accept {
        CONFIRM_FLAG_ACCEPT
    } else {
        CONFIRM_FLAG_DENY
    };
    let mut m = Vec::with_capacity(
        CONFIRM_DOMAIN.len()
            + 1
            + sid.len()
            + joiner_did.len()
            + resident_did.len()
            + PAIR_NONCE_LEN,
    );
    m.extend_from_slice(CONFIRM_DOMAIN);
    m.push(flag);
    m.extend_from_slice(sid.as_bytes());
    m.extend_from_slice(joiner_did.as_bytes());
    m.extend_from_slice(resident_did.as_bytes());
    m.extend_from_slice(nonce);
    m
}

/// Compute a single confirm code (display `4-4` form).
///
/// `pepper` is the **raw** bootstrap token (32B). `nonce` is raw 16B.
pub fn compute_confirm_code(
    pepper: &[u8],
    accept: bool,
    sid: &str,
    joiner_did: &str,
    resident_did: &str,
    nonce: &[u8; PAIR_NONCE_LEN],
) -> String {
    let material = confirm_code_material(accept, sid, joiner_did, resident_did, nonce);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC-SHA256 accepts any key length");
    mac.update(&material);
    let digest = mac.finalize().into_bytes();
    let trunc = &digest[..CONFIRM_HMAC_TRUNCATE];
    let encoded = crockford_base32_encode(trunc);
    format_confirm_code_display(&encoded)
}

/// Compute accept + deny confirm codes for a bound pair session.
pub fn compute_confirm_codes(
    pepper: &[u8],
    sid: &str,
    joiner_did: &str,
    resident_did: &str,
    nonce: &[u8; PAIR_NONCE_LEN],
) -> ConfirmCodes {
    ConfirmCodes {
        accept: compute_confirm_code(pepper, true, sid, joiner_did, resident_did, nonce),
        deny: compute_confirm_code(pepper, false, sid, joiner_did, resident_did, nonce),
    }
}

/// Format Crockford base32 as **4-4** groups (e.g. `ABCD-EFGH`).
pub fn format_confirm_code_display(raw: &str) -> String {
    let compact: String = raw
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() <= 4 {
        return compact;
    }
    let (a, b) = compact.split_at(4.min(compact.len()));
    if b.is_empty() {
        a.to_string()
    } else {
        let b8 = if b.len() > 4 { &b[..4] } else { b };
        format!("{a}-{b8}")
    }
}

/// Normalize operator input: strip hyphens/spaces, uppercase, map Crockford
/// confusable characters (`I`→`1`, `L`→`1`, `O`→`0`, `U`→`V`).
pub fn normalize_confirm_code_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| {
            let u = c.to_ascii_uppercase();
            match u {
                'I' | 'L' => '1',
                'O' => '0',
                'U' => 'V',
                other => other,
            }
        })
        .collect()
}

/// Constant-time-ish compare of two confirm codes after normalization.
pub fn confirm_codes_equal(a: &str, b: &str) -> bool {
    let na = normalize_confirm_code_input(a);
    let nb = normalize_confirm_code_input(b);
    if na.len() != nb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in na.bytes().zip(nb.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode bytes as Crockford base32 (no padding). Uppercase alphabet.
pub fn crockford_base32_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crockford_encode_5_bytes_is_8_chars() {
        let enc = crockford_base32_encode(&[0xfb, 0x30, 0xe0, 0xe0, 0x24]);
        assert_eq!(enc.len(), 8);
        assert_eq!(enc, "ZCRE1R14");
    }

    #[test]
    fn confirm_display_is_4_4_hyphens_ignored_on_input() {
        assert_eq!(format_confirm_code_display("ZCRE1R14"), "ZCRE-1R14");
        assert_eq!(format_confirm_code_display("zcre-1r14"), "ZCRE-1R14");
        assert_eq!(normalize_confirm_code_input("ZCRE-1R14"), "ZCRE1R14");
        assert_eq!(normalize_confirm_code_input(" zcre 1r14 "), "ZCRE1R14");
        assert_eq!(normalize_confirm_code_input("OIUL"), "01V1");
        assert!(confirm_codes_equal("ZCRE-1R14", "zcre1r14"));
        assert!(!confirm_codes_equal("ZCRE-1R14", "2ESK-ET35"));
    }

    /// Frozen golden vector matching carrier-core `confirm_codes_vector.json`.
    ///
    /// pepper = 32×0x11, nonce = 16×0x22 → accept `ZCRE-1R14`, deny `2ESK-ET35`.
    #[test]
    fn confirm_codes_golden_hmac_vector() {
        let pepper = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let sid = "01HZXPAIRSESSION0000000000";
        let joiner = "b2".repeat(32);
        let resident = "a1".repeat(32);

        let material_accept = confirm_code_material(true, sid, &joiner, &resident, &nonce);
        assert_eq!(material_accept.len(), 193);
        assert!(material_accept.starts_with(CONFIRM_DOMAIN));
        assert_eq!(material_accept[CONFIRM_DOMAIN.len()], CONFIRM_FLAG_ACCEPT);
        assert_eq!(&material_accept[material_accept.len() - 16..], &nonce);

        let material_deny = confirm_code_material(false, sid, &joiner, &resident, &nonce);
        assert_eq!(material_deny[CONFIRM_DOMAIN.len()], CONFIRM_FLAG_DENY);
        assert_ne!(material_accept, material_deny);

        let codes = compute_confirm_codes(&pepper, sid, &joiner, &resident, &nonce);
        assert_eq!(codes.accept, "ZCRE-1R14");
        assert_eq!(codes.deny, "2ESK-ET35");

        assert!(confirm_codes_equal(&codes.accept, "ZCRE1R14"));
        assert!(confirm_codes_equal(&codes.deny, "2esket35"));

        let other = "c3".repeat(32);
        let other_codes = compute_confirm_codes(&pepper, sid, &other, &resident, &nonce);
        assert_ne!(other_codes.accept, codes.accept);
        assert_ne!(other_codes.deny, codes.deny);
    }
}
