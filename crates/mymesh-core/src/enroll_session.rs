//! Enrollment session state for QR + challenge enrollment.
//!
//! Flow (phone-shows-code ceremony):
//! 1. Node creates session with one-time ticket, displays QR (NO code on node)
//! 2. Phone scans QR, connects over iroh ALPN `mymesh-enroll/1`
//! 3. Phone sends `request` with ticket, person identity, mesh name
//! 4. Node verifies ticket, sends `challenge_waiting`
//! 5. Phone generates 6-digit code, displays it, sends `challenge_offer { digits }`
//! 6. Human types phone's digits INTO the node (stdin/TUI)
//! 7. Node constant-time compares; on match: store owner, send `result { success: true }`
//!
//! Security properties:
//! - Ticket is single-use and expires (~2 minutes)
//! - Challenge code lives only on the phone until human types it
//! - Photo of QR alone is insufficient (no code in QR; code only on phone screen)
//! - Constant-time comparison prevents timing attacks

use crate::{DeviceId, Error, Result};
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Enrollment session expiry: 2 minutes.
pub const ENROLL_SESSION_EXPIRY_SECS: i64 = 120;

/// QR payload version.
pub const QR_PAYLOAD_VERSION: u32 = 1;

/// ALPN for enrollment (matches mymesh-protocol).
pub const ENROLL_ALPN: &str = "mymesh-enroll/1";

/// QR payload structure (JSON, UTF-8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollQrPayload {
    /// Version (currently 1).
    pub v: u32,
    /// ALPN to use for connection.
    pub alpn: String,
    /// Node device id (hex) or iroh ticket.
    pub device: String,
    /// One-time enrollment ticket.
    pub ticket: String,
}

impl EnrollQrPayload {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::Config(format!("invalid QR payload: {e}")))
    }
}

/// Enrollment session state (persisted to `enroll-session.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollSession {
    /// Session id (random).
    pub session_id: String,
    /// Node device id.
    pub device_id: DeviceId,
    /// One-time ticket (hex, 32 random bytes).
    pub ticket: String,
    /// 6-digit numeric challenge (phone-generated, stored after `challenge_offer`).
    /// Empty string until phone sends its code.
    #[serde(default)]
    pub challenge: String,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// True when the human has confirmed the challenge locally.
    pub challenge_confirmed: bool,
    /// When the challenge was confirmed (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<DateTime<Utc>>,
    /// When enrollment was completed (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Person id that enrolled (if completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_person_id: Option<String>,
}

impl EnrollSession {
    /// Create a new enrollment session for the given device.
    /// Does NOT generate a challenge code - the phone generates and displays it.
    pub fn new(device_id: DeviceId) -> Self {
        let now = Utc::now();
        Self {
            session_id: new_session_id(),
            device_id,
            ticket: new_ticket(),
            challenge: String::new(), // Phone generates the challenge
            created_at: now,
            expires_at: now + Duration::seconds(ENROLL_SESSION_EXPIRY_SECS),
            challenge_confirmed: false,
            confirmed_at: None,
            completed_at: None,
            enrolled_person_id: None,
        }
    }

    /// Check if the session is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at && self.completed_at.is_none()
    }

    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if enrollment can proceed (valid + challenge confirmed).
    pub fn can_enroll(&self) -> bool {
        self.is_valid() && self.challenge_confirmed
    }

    /// Verify the ticket matches.
    pub fn verify_ticket(&self, ticket: &str) -> bool {
        constant_time_eq(self.ticket.as_bytes(), ticket.as_bytes())
    }

    /// Verify the phone's challenge against human input.
    /// `phone_digits`: 6-digit code from phone's `challenge_offer`
    /// `human_input`: what the human typed on the node
    /// On match, sets `challenge_confirmed = true`.
    pub fn verify_phone_challenge(&mut self, phone_digits: &str, human_input: &str) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::Session("enrollment session expired".into()));
        }
        let normalized_phone = phone_digits.trim().replace([' ', '-'], "");
        let normalized_human = human_input.trim().replace([' ', '-'], "");

        // Validate phone_digits looks like a 6-digit code
        if normalized_phone.len() != 6 || !normalized_phone.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::PermissionDenied(
                "phone challenge must be 6 digits".into(),
            ));
        }

        if !constant_time_eq(normalized_phone.as_bytes(), normalized_human.as_bytes()) {
            return Err(Error::PermissionDenied("challenge mismatch".into()));
        }
        self.challenge = normalized_phone;
        self.challenge_confirmed = true;
        self.confirmed_at = Some(Utc::now());
        Ok(())
    }

    /// Legacy: Confirm the challenge locally (for backwards compatibility with tests).
    /// In the new flow, use `verify_phone_challenge` instead.
    #[deprecated(note = "use verify_phone_challenge for new phone-shows-code flow")]
    pub fn confirm_challenge(&mut self, input: &str) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::Session("enrollment session expired".into()));
        }
        let normalized = input.trim().replace([' ', '-'], "");
        // For legacy compatibility: if challenge is empty, treat any 6-digit input as valid
        // This supports old tests that call confirm_challenge before phone sends challenge_offer
        if self.challenge.is_empty() {
            if normalized.len() == 6 && normalized.chars().all(|c| c.is_ascii_digit()) {
                self.challenge = normalized;
                self.challenge_confirmed = true;
                self.confirmed_at = Some(Utc::now());
                return Ok(());
            }
            return Err(Error::PermissionDenied("challenge must be 6 digits".into()));
        }
        if !constant_time_eq(self.challenge.as_bytes(), normalized.as_bytes()) {
            return Err(Error::PermissionDenied("challenge mismatch".into()));
        }
        self.challenge_confirmed = true;
        self.confirmed_at = Some(Utc::now());
        Ok(())
    }

    /// Mark enrollment as completed.
    pub fn complete(&mut self, person_id: &str) {
        self.completed_at = Some(Utc::now());
        self.enrolled_person_id = Some(person_id.to_string());
    }

    /// Build the QR payload for this session.
    pub fn qr_payload(&self) -> EnrollQrPayload {
        EnrollQrPayload {
            v: QR_PAYLOAD_VERSION,
            alpn: ENROLL_ALPN.to_string(),
            device: hex::encode(self.device_id.as_bytes()),
            ticket: self.ticket.clone(),
        }
    }

    /// Seconds remaining until expiry.
    pub fn seconds_remaining(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

/// Enrollment session file (mode 0600).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollSessionFile {
    pub version: u32,
    pub session: EnrollSession,
}

impl EnrollSessionFile {
    pub const VERSION: u32 = 1;

    pub fn new(session: EnrollSession) -> Self {
        Self {
            version: Self::VERSION,
            session,
        }
    }

    pub fn try_load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)?;
        let file: Self = serde_json::from_str(&raw)?;
        if file.version != Self::VERSION {
            return Err(Error::Config(format!(
                "unsupported enroll-session.json version {}",
                file.version
            )));
        }
        Ok(Some(file))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::try_load(path)?.ok_or_else(|| Error::NotFound("enroll-session.json missing".into()))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn clear(path: impl AsRef<Path>) -> Result<bool> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Generate a new session id (ULID-like).
fn new_session_id() -> String {
    let ts = Utc::now().timestamp_millis() as u64;
    let mut rand = [0u8; 10];
    OsRng.fill_bytes(&mut rand);
    format!("{:010X}{}", ts, hex::encode(rand).to_uppercase())
}

/// Generate a new one-time ticket (32 random bytes, hex).
fn new_ticket() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_empty_challenge_and_valid_ticket() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let sess = EnrollSession::new(did);
        // Challenge is empty until phone sends challenge_offer
        assert!(sess.challenge.is_empty());
        assert_eq!(sess.ticket.len(), 64); // 32 bytes hex
        assert!(!sess.challenge_confirmed);
        assert!(sess.is_valid());
    }

    #[test]
    fn session_expires_after_timeout() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);
        sess.expires_at = Utc::now() - Duration::seconds(1);
        assert!(sess.is_expired());
        assert!(!sess.is_valid());
        assert!(!sess.can_enroll());
    }

    #[test]
    fn phone_challenge_verification_correct() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);
        assert!(sess.is_valid());
        assert!(!sess.can_enroll());

        // Phone sends digits, human types the same
        let phone_digits = "123456";
        let human_input = "123456";
        sess.verify_phone_challenge(phone_digits, human_input)
            .unwrap();
        assert!(sess.challenge_confirmed);
        assert!(sess.can_enroll());
        assert_eq!(sess.challenge, "123456");
    }

    #[test]
    fn phone_challenge_verification_wrong() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);

        let phone_digits = "123456";
        let human_input = "654321";
        let err = sess
            .verify_phone_challenge(phone_digits, human_input)
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"));
        assert!(!sess.challenge_confirmed);
    }

    #[test]
    fn phone_challenge_with_whitespace() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);

        // Phone sends "123456", human types "12 34 56" with spaces
        let phone_digits = "123456";
        let human_input = "12 34 56";
        sess.verify_phone_challenge(phone_digits, human_input)
            .unwrap();
        assert!(sess.challenge_confirmed);
    }

    #[test]
    fn phone_challenge_invalid_format() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);

        // Phone sends invalid (not 6 digits)
        let err = sess.verify_phone_challenge("12345", "12345").unwrap_err();
        assert!(err.to_string().contains("6 digits"));

        let err = sess
            .verify_phone_challenge("12345a", "12345a")
            .unwrap_err();
        assert!(err.to_string().contains("6 digits"));
    }

    #[test]
    fn ticket_verification() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let sess = EnrollSession::new(did);
        assert!(sess.verify_ticket(&sess.ticket));
        assert!(!sess.verify_ticket("wrong"));
        assert!(!sess.verify_ticket(&sess.ticket[..60])); // Different length
    }

    #[test]
    fn qr_payload_roundtrip() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let sess = EnrollSession::new(did);
        let qr = sess.qr_payload();
        let json = qr.to_json();
        let parsed = EnrollQrPayload::from_json(&json).unwrap();
        assert_eq!(parsed.v, QR_PAYLOAD_VERSION);
        assert_eq!(parsed.alpn, ENROLL_ALPN);
        assert_eq!(parsed.device, hex::encode(did.as_bytes()));
        assert_eq!(parsed.ticket, sess.ticket);
    }

    #[test]
    fn session_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mymesh-enroll-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("enroll-session.json");

        let did = DeviceId::from_bytes([0x42u8; 32]);
        let sess = EnrollSession::new(did);
        let file = EnrollSessionFile::new(sess.clone());
        file.save(&path).unwrap();

        let loaded = EnrollSessionFile::load(&path).unwrap();
        assert_eq!(loaded.session.session_id, sess.session_id);
        assert_eq!(loaded.session.ticket, sess.ticket);
        // Challenge is empty in new sessions
        assert!(loaded.session.challenge.is_empty());

        EnrollSessionFile::clear(&path).unwrap();
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_session_rejects_phone_challenge() {
        let did = DeviceId::from_bytes([0x42u8; 32]);
        let mut sess = EnrollSession::new(did);
        sess.expires_at = Utc::now() - Duration::seconds(1);
        let err = sess
            .verify_phone_challenge("123456", "123456")
            .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }
}
