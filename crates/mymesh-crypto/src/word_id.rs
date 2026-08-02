//! BIP39-style 24-word encoding of a DeviceId (32-byte public key).
//!
//! Display form matches crypto-wallet mnemonics: 24 English words encoding the
//! full 256-bit device id plus BIP39 checksum. Canonical wire form remains hex.
use bip39::{Language, Mnemonic};
use mymesh_core::{DeviceId, Error, Result};

/// Encode a DeviceId as a 24-word BIP39 mnemonic (space-separated).
pub fn device_id_to_words(id: &DeviceId) -> Result<String> {
    let m = Mnemonic::from_entropy_in(Language::English, id.as_bytes())
        .map_err(|e| Error::Identity(format!("word encode: {e}")))?;
    Ok(m.to_string())
}

/// Parse a DeviceId from hex **or** a 12/15/18/21/24-word BIP39 phrase.
pub fn parse_device_id(input: &str) -> Result<DeviceId> {
    let s = input.trim();
    // Hex (64 chars) first
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return s.parse();
    }
    // Compact hex with 0x
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.len() == 64 {
            return rest.parse();
        }
    }
    // Short prefix alone is not enough for full id
    // Word phrase: spaces or dashes
    let phrase = s
        .split(|c: char| c.is_whitespace() || c == '-' || c == ',')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let words = phrase.split_whitespace().count();
    if words >= 12 {
        let m = Mnemonic::parse_in_normalized(Language::English, &phrase)
            .map_err(|e| Error::Identity(format!("invalid word id: {e}")))?;
        let ent = m.to_entropy();
        if ent.len() != 32 {
            return Err(Error::Identity(format!(
                "word id must encode 32 bytes (24 words), got {} bytes",
                ent.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&ent);
        return Ok(DeviceId::from_bytes(bytes));
    }
    // Try hex of other lengths for short prefixes? Reject.
    if s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Identity(
            "partial hex is ambiguous — use full 64-char hex or 24-word id".into(),
        ));
    }
    Err(Error::Identity(format!(
        "could not parse device id (need 64-char hex or 24-word phrase): {s}"
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
    fn hex_still_works() {
        let id = DeviceId::from_bytes([9u8; 32]);
        let back = parse_device_id(&id.to_string()).unwrap();
        assert_eq!(id, back);
    }
}
