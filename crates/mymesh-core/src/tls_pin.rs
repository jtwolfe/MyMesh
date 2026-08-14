//! Optional TLS certificate pin for pair bootstrap (`tlspin=`).
//!
//! Normative format (PAIR-V2.md / S9 D2):
//!
//! ```text
//! tlspin=sha256/<base64>
//! ```
//!
//! where `<base64>` is the Base64 encoding (standard or base64url; padding optional)
//! of `SHA-256(SPKI_DER)` — the SubjectPublicKeyInfo of the leaf (or pinned)
//! certificate presented by the **HTTPS** pair host.
//!
//! Policy:
//! - Pin is **optional**. When absent, client behaviour is unchanged.
//! - When pin is present, the direct `host` **must** be `https://` (fail closed).
//! - When pin is present and HTTPS is used, clients **must** verify the pin
//!   against the peer SPKI before sending bootstrap tokens (fail closed on mismatch).
//! - Release cleartext policy is unchanged: Carrier release already denies cleartext;
//!   MyMesh LAN lab may still emit `http://` host **without** a pin.
//!
//! Full TLS handshake integration lives in the pair HTTP client (Carrier D3).
//! This module provides the wire format, parse/validate, and the fail-closed
//! verify hook that clients call with SPKI bytes extracted from their TLS stack.

use crate::pair_session::ct_eq;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fmt;

/// Wire prefix for SHA-256 SPKI pins (`sha256/<digest>`).
pub const TLS_PIN_SHA256_PREFIX: &str = "sha256/";

/// Expected digest length (SHA-256).
pub const TLS_PIN_SHA256_LEN: usize = 32;

/// Parsed and validated TLS pin (SHA-256 of SPKI).
#[derive(Clone, PartialEq, Eq)]
pub struct TlsPin {
    /// Raw SHA-256 digest of SPKI DER (32 bytes).
    digest: [u8; TLS_PIN_SHA256_LEN],
}

impl std::fmt::Debug for TlsPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPin")
            .field("digest", &self.to_wire())
            .finish()
    }
}

impl TlsPin {
    /// Construct from a raw SHA-256 digest.
    pub fn from_digest(digest: [u8; TLS_PIN_SHA256_LEN]) -> Self {
        Self { digest }
    }

    /// SHA-256 of SPKI DER → pin.
    pub fn from_spki_der(spki_der: &[u8]) -> Self {
        let dig = Sha256::digest(spki_der);
        let mut out = [0u8; TLS_PIN_SHA256_LEN];
        out.copy_from_slice(&dig);
        Self { digest: out }
    }

    /// Raw 32-byte digest.
    pub fn digest(&self) -> &[u8; TLS_PIN_SHA256_LEN] {
        &self.digest
    }

    /// Canonical wire form: `sha256/<base64url-no-pad>`.
    ///
    /// Preferred for QR emission (URL-safe, no padding).
    pub fn to_wire(&self) -> String {
        format!(
            "{}{}",
            TLS_PIN_SHA256_PREFIX,
            URL_SAFE_NO_PAD.encode(self.digest)
        )
    }

    /// Android Network Security Config style: `sha256/<standard-base64-with-pad>`.
    pub fn to_android_wire(&self) -> String {
        format!("{}{}", TLS_PIN_SHA256_PREFIX, STANDARD.encode(self.digest))
    }
}

/// Errors for pin parse / policy / verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsPinError {
    /// Empty or missing pin string when one was required.
    Empty,
    /// Unrecognised algorithm / prefix.
    BadFormat(String),
    /// Digest decode failed or wrong length.
    BadDigest(String),
    /// Pin present but host is not HTTPS (or host missing).
    HttpsRequired,
    /// Peer SPKI hash does not match pin (fail closed).
    Mismatch,
}

impl TlsPinError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "tls_pin_empty",
            Self::BadFormat(_) => "tls_pin_bad_format",
            Self::BadDigest(_) => "tls_pin_bad_digest",
            Self::HttpsRequired => "tls_pin_https_required",
            Self::Mismatch => "tls_pin_mismatch",
        }
    }
}

impl fmt::Display for TlsPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "tls pin is empty"),
            Self::BadFormat(s) => write!(f, "tls pin bad format: {s}"),
            Self::BadDigest(s) => write!(f, "tls pin bad digest: {s}"),
            Self::HttpsRequired => write!(
                f,
                "tlspin requires https:// host (cleartext host + pin rejected)"
            ),
            Self::Mismatch => write!(f, "tls pin mismatch (peer certificate SPKI does not match)"),
        }
    }
}

impl std::error::Error for TlsPinError {}

/// Parse `sha256/<base64|base64url>` pin string (optional surrounding whitespace).
///
/// Accepts standard Base64 (padded or not) and base64url (padded or not).
pub fn parse_tls_pin(s: &str) -> Result<TlsPin, TlsPinError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(TlsPinError::Empty);
    }
    let rest = s
        .strip_prefix(TLS_PIN_SHA256_PREFIX)
        .or_else(|| s.strip_prefix("SHA256/"))
        .ok_or_else(|| {
            TlsPinError::BadFormat(format!(
                "expected '{TLS_PIN_SHA256_PREFIX}<base64>', got {s:?}"
            ))
        })?;
    if rest.is_empty() {
        return Err(TlsPinError::BadDigest("empty digest".into()));
    }
    // Reject hex-only forms that look like digests without the algo prefix confusion —
    // we only accept base64-family encodings here.
    let raw = decode_pin_digest(rest).map_err(TlsPinError::BadDigest)?;
    if raw.len() != TLS_PIN_SHA256_LEN {
        return Err(TlsPinError::BadDigest(format!(
            "digest must be {TLS_PIN_SHA256_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let mut digest = [0u8; TLS_PIN_SHA256_LEN];
    digest.copy_from_slice(&raw);
    Ok(TlsPin { digest })
}

fn decode_pin_digest(s: &str) -> Result<Vec<u8>, String> {
    // Try base64url no-pad, base64url padded, standard no-pad, standard padded.
    if let Ok(v) = URL_SAFE_NO_PAD.decode(s.as_bytes()) {
        return Ok(v);
    }
    if let Ok(v) = URL_SAFE.decode(s.as_bytes()) {
        return Ok(v);
    }
    // STANDARD_NO_PAD is not a const in older base64; strip pad and use STANDARD on padded form.
    if let Ok(v) = STANDARD.decode(s.as_bytes()) {
        return Ok(v);
    }
    // Unpadded standard base64: add padding.
    let mut padded = s.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))
}

/// True when `host` is an `https://` URL (case-insensitive scheme).
pub fn host_is_https(host: &str) -> bool {
    let h = host.trim();
    h.len() >= 8 && h[..8].eq_ignore_ascii_case("https://")
}

/// True when `host` is an `http://` URL (cleartext).
pub fn host_is_http_cleartext(host: &str) -> bool {
    let h = host.trim();
    h.len() >= 7 && h[..7].eq_ignore_ascii_case("http://")
}

/// Policy gate: if a pin is present, host must be HTTPS.
///
/// - `pin == None` → always Ok (no pin policy).
/// - `pin == Some` and host is `https://` → Ok.
/// - otherwise → `HttpsRequired` (fail closed).
pub fn require_https_when_pinned(
    pin: Option<&TlsPin>,
    host: Option<&str>,
) -> Result<(), TlsPinError> {
    if pin.is_none() {
        return Ok(());
    }
    match host {
        Some(h) if host_is_https(h) => Ok(()),
        _ => Err(TlsPinError::HttpsRequired),
    }
}

/// Fail-closed verify: peer SPKI DER must hash to the expected pin.
///
/// Callers extract SPKI from the TLS leaf (or pinned intermediate) certificate
/// via their TLS stack, then pass the DER-encoded SPKI here.
pub fn verify_tls_pin(expected: &TlsPin, peer_spki_der: &[u8]) -> Result<(), TlsPinError> {
    let got = TlsPin::from_spki_der(peer_spki_der);
    if ct_eq(expected.digest(), got.digest()) {
        Ok(())
    } else {
        Err(TlsPinError::Mismatch)
    }
}

/// Convenience: verify pin wire string against peer SPKI (parse + verify).
pub fn verify_tls_pin_str(pin_wire: &str, peer_spki_der: &[u8]) -> Result<(), TlsPinError> {
    let pin = parse_tls_pin(pin_wire)?;
    verify_tls_pin(&pin, peer_spki_der)
}

/// Client hook for direct-ep HTTPS: when `tlspin` is present, verify SPKI.
///
/// | pin | host scheme | peer SPKI | Result |
/// |-----|-------------|-----------|--------|
/// | None | any | — | Ok (no pin check) |
/// | Some | not https | — | Err `HttpsRequired` |
/// | Some | https | missing / empty | Err `Mismatch` (fail closed) |
/// | Some | https | matches | Ok |
/// | Some | https | mismatch | Err `Mismatch` |
///
/// `peer_spki_der` is required when pin is present: pass `None` only when the
/// TLS stack could not produce SPKI (treated as mismatch — fail closed).
pub fn check_direct_host_tls_pin(
    pin: Option<&TlsPin>,
    host: Option<&str>,
    peer_spki_der: Option<&[u8]>,
) -> Result<(), TlsPinError> {
    require_https_when_pinned(pin, host)?;
    let Some(pin) = pin else {
        return Ok(());
    };
    let spki = peer_spki_der
        .filter(|s| !s.is_empty())
        .ok_or(TlsPinError::Mismatch)?;
    verify_tls_pin(pin, spki)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spki(seed: u8) -> Vec<u8> {
        // Synthetic DER-ish bytes (not a real SPKI); pin is over opaque SPKI DER.
        let mut v = vec![0x30, 0x82, 0x01, 0x22]; // SEQUENCE header-ish
        v.extend(std::iter::repeat_n(seed, 64));
        v
    }

    #[test]
    fn roundtrip_wire_canonical() {
        let spki = sample_spki(0xab);
        let pin = TlsPin::from_spki_der(&spki);
        let wire = pin.to_wire();
        assert!(wire.starts_with("sha256/"));
        assert!(!wire.contains('='));
        let parsed = parse_tls_pin(&wire).unwrap();
        assert_eq!(parsed.digest(), pin.digest());
        assert_eq!(parsed.to_wire(), wire);
    }

    #[test]
    fn parse_android_standard_base64() {
        let spki = sample_spki(0x11);
        let pin = TlsPin::from_spki_der(&spki);
        let android = pin.to_android_wire();
        assert!(android.contains('=') || android.len() > 7);
        let parsed = parse_tls_pin(&android).unwrap();
        assert_eq!(parsed, pin);
    }

    #[test]
    fn parse_rejects_bad_prefix_and_empty() {
        assert_eq!(parse_tls_pin("").unwrap_err(), TlsPinError::Empty);
        assert!(matches!(
            parse_tls_pin("md5/AAAA"),
            Err(TlsPinError::BadFormat(_))
        ));
        assert!(matches!(
            parse_tls_pin("sha256/"),
            Err(TlsPinError::BadDigest(_))
        ));
        // wrong length after decode
        assert!(matches!(
            parse_tls_pin("sha256/AAAA"),
            Err(TlsPinError::BadDigest(_))
        ));
    }

    #[test]
    fn verify_match_and_mismatch() {
        let spki_ok = sample_spki(0x42);
        let spki_bad = sample_spki(0x43);
        let pin = TlsPin::from_spki_der(&spki_ok);
        assert!(verify_tls_pin(&pin, &spki_ok).is_ok());
        assert_eq!(
            verify_tls_pin(&pin, &spki_bad).unwrap_err(),
            TlsPinError::Mismatch
        );
        assert_eq!(
            verify_tls_pin_str(&pin.to_wire(), &spki_bad).unwrap_err(),
            TlsPinError::Mismatch
        );
        assert!(verify_tls_pin_str(&pin.to_wire(), &spki_ok).is_ok());
    }

    #[test]
    fn https_policy_when_pinned() {
        let pin = TlsPin::from_spki_der(&sample_spki(1));
        assert!(require_https_when_pinned(None, Some("http://lan:1")).is_ok());
        assert!(require_https_when_pinned(None, None).is_ok());
        assert!(require_https_when_pinned(Some(&pin), Some("https://host:443")).is_ok());
        assert!(require_https_when_pinned(Some(&pin), Some("HTTPS://HOST")).is_ok());
        assert_eq!(
            require_https_when_pinned(Some(&pin), Some("http://lan:17878")).unwrap_err(),
            TlsPinError::HttpsRequired
        );
        assert_eq!(
            require_https_when_pinned(Some(&pin), None).unwrap_err(),
            TlsPinError::HttpsRequired
        );
    }

    #[test]
    fn client_hook_fail_closed() {
        let spki = sample_spki(7);
        let pin = TlsPin::from_spki_der(&spki);
        // no pin → ok
        assert!(check_direct_host_tls_pin(None, Some("http://x"), None).is_ok());
        // pin + https + match
        assert!(
            check_direct_host_tls_pin(Some(&pin), Some("https://example:8443"), Some(&spki))
                .is_ok()
        );
        // pin + http → https required
        assert_eq!(
            check_direct_host_tls_pin(Some(&pin), Some("http://x"), Some(&spki)).unwrap_err(),
            TlsPinError::HttpsRequired
        );
        // pin + https + no spki → mismatch (fail closed)
        assert_eq!(
            check_direct_host_tls_pin(Some(&pin), Some("https://x"), None).unwrap_err(),
            TlsPinError::Mismatch
        );
        // pin + https + empty SPKI slice → mismatch (fail closed; no skip)
        assert_eq!(
            check_direct_host_tls_pin(Some(&pin), Some("https://x"), Some(&[])).unwrap_err(),
            TlsPinError::Mismatch
        );
        // pin + https + wrong spki
        assert_eq!(
            check_direct_host_tls_pin(Some(&pin), Some("https://x"), Some(&sample_spki(9)))
                .unwrap_err(),
            TlsPinError::Mismatch
        );
        // pin + empty host string → https required
        assert_eq!(
            check_direct_host_tls_pin(Some(&pin), Some(""), Some(&spki)).unwrap_err(),
            TlsPinError::HttpsRequired
        );
    }

    #[test]
    fn parse_uppercase_prefix_and_unpadded_standard_base64() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;

        let spki = sample_spki(0x55);
        let pin = TlsPin::from_spki_der(&spki);
        // Documented accept: SHA256/ prefix
        let upper = format!("SHA256/{}", URL_SAFE_NO_PAD.encode(pin.digest()));
        assert_eq!(parse_tls_pin(&upper).unwrap(), pin);

        // Unpadded standard base64 (not base64url): strip '=' from STANDARD encoding
        let std_padded = STANDARD.encode(pin.digest());
        let std_unpadded = std_padded.trim_end_matches('=');
        // 32-byte digests always need padding under STANDARD
        assert!(std_padded.ends_with('='));
        let wire_unpadded = format!("sha256/{std_unpadded}");
        assert_eq!(parse_tls_pin(&wire_unpadded).unwrap(), pin);
    }

    #[test]
    fn host_scheme_helpers() {
        assert!(host_is_https("https://a"));
        assert!(host_is_https("HTTPS://A"));
        assert!(!host_is_https("http://a"));
        assert!(!host_is_https(""));
        assert!(host_is_http_cleartext("http://a"));
        assert!(!host_is_http_cleartext("https://a"));
    }
}
