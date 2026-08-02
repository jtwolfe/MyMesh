//! BIP39-style 24-word encoding of a DeviceId (32-byte public key).
use bip39::{Language, Mnemonic};
use mymesh_core::{DeviceId, Error, Result};

/// Encode a DeviceId as a 24-word BIP39 mnemonic (space-separated).
pub fn device_id_to_words(id: &DeviceId) -> Result<String> {
    let m = Mnemonic::from_entropy_in(Language::English, id.as_bytes())
        .map_err(|e| Error::Identity(format!("word encode: {e}")))?;
    Ok(m.to_string())
}

/// Normalize messy human paste into a candidate phrase or hex string.
///
/// Accepts:
/// - hex (with optional 0x, whitespace)
/// - words separated by space, newline, comma, slash, pipe, or numbered lists (`1. word`)
/// - quoted blobs
fn normalize_device_id_input(input: &str) -> String {
    let mut s = input.trim().to_string();
    // Strip surrounding quotes
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s = s[1..s.len() - 1].trim().to_string();
    }
    // Strip URI prefix
    if let Some(rest) = s.strip_prefix("mymesh:v1:join:") {
        s = rest.to_string();
    }
    // Collapse common separators for hex check first
    let hex_candidate: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex_candidate.len() == 64 {
        return hex_candidate;
    }
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let h: String = rest.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if h.len() == 64 {
            return h;
        }
    }

    // Word path: drop list markers like "1." "2)" "01:"
    let mut words = Vec::new();
    for tok in s.split(|c: char| {
        c.is_whitespace() || matches!(c, ',' | ';' | '|' | '/' | '\\' | '+' | '=')
    }) {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        // skip pure numbers / list indices
        if t.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ')') {
            continue;
        }
        // "12.word" or "12)word"
        let t = t
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .trim_start_matches(['.', ')', ':', '-'])
            .trim();
        if t.is_empty() {
            continue;
        }
        // only alphabetic words for BIP39
        if t.chars().all(|c| c.is_ascii_alphabetic()) {
            words.push(t.to_lowercase());
        }
    }
    words.join(" ")
}

/// Parse a DeviceId from hex **or** a 12/15/18/21/24-word BIP39 phrase (tolerant paste).
pub fn parse_device_id(input: &str) -> Result<DeviceId> {
    let s = normalize_device_id_input(input);
    if s.is_empty() {
        return Err(Error::Identity("empty device id".into()));
    }
    // Hex
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return s.parse();
    }
    let words = s.split_whitespace().count();
    if words >= 12 {
        let m = Mnemonic::parse_in_normalized(Language::English, &s).map_err(|e| {
            Error::Identity(format!(
                "invalid word id ({words} tokens): {e} — need a valid 24-word BIP39 phrase"
            ))
        })?;
        let ent = m.to_entropy();
        if ent.len() != 32 {
            return Err(Error::Identity(format!(
                "word id must encode 32 bytes (24 words), got {} bytes from {words} words",
                ent.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&ent);
        return Ok(DeviceId::from_bytes(bytes));
    }
    if s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Identity(
            "partial hex is ambiguous — use full 64-char hex or 24-word id".into(),
        ));
    }
    Err(Error::Identity(format!(
        "could not parse device id (need 64-char hex or 24-word phrase); got {} tokens",
        words
    )))
}

/// URI for QR codes / deep links.
pub fn device_join_uri(id: &DeviceId) -> Result<String> {
    Ok(format!("mymesh:v1:join:{}", id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_words() {
        let id = DeviceId::from_bytes([0x42; 32]);
        let words = device_id_to_words(&id).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let back = parse_device_id(&words).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn messy_paste_words() {
        let id = DeviceId::from_bytes([0x42; 32]);
        let words = device_id_to_words(&id).unwrap();
        let numbered = words
            .split_whitespace()
            .enumerate()
            .map(|(i, w)| format!("{}. {w}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let back = parse_device_id(&numbered).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn hex_with_uri() {
        let id = DeviceId::from_bytes([9u8; 32]);
        let uri = device_join_uri(&id).unwrap();
        assert_eq!(parse_device_id(&uri).unwrap(), id);
    }

    #[test]
    fn hex_still_works() {
        let id = DeviceId::from_bytes([9u8; 32]);
        let back = parse_device_id(&id.to_string()).unwrap();
        assert_eq!(id, back);
    }
}
