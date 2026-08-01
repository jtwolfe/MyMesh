use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Stable 32-byte device identifier (public key / endpoint id).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

impl FromStr for DeviceId {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = hex::decode(s.trim()).map_err(|e| crate::Error::Identity(e.to_string()))?;
        if raw.len() != 32 {
            return Err(crate::Error::Identity(format!(
                "expected 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }
}

/// Human-friendly label for a device (hostname or user-set name).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    pub fn new(s: impl Into<String>) -> Self {
        let mut s = s.into();
        s.truncate(64);
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Best-effort default label from environment / OS hostname.
    pub fn default_host() -> Self {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .or_else(|_| {
                std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .map_err(|_| std::env::VarError::NotPresent)
            })
            .unwrap_or_else(|_| "mymesh-node".into());
        Self::new(host)
    }
}

impl fmt::Display for DeviceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Default for DeviceLabel {
    fn default() -> Self {
        Self::default_host()
    }
}

/// Short human-readable fingerprint for manual verification (SSH-style).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFingerprint(String);

impl NodeFingerprint {
    pub fn from_device_id(id: &DeviceId) -> Self {
        let h = hex::encode(id.as_bytes());
        let groups: Vec<&str> = (0..8).map(|i| &h[i * 4..(i + 1) * 4]).collect();
        Self(groups.join("-"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_device_id() {
        let id = DeviceId::from_bytes([7u8; 32]);
        let s = id.to_string();
        let parsed: DeviceId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn fingerprint_format() {
        let id = DeviceId::from_bytes([0xab; 32]);
        let fp = NodeFingerprint::from_device_id(&id);
        assert_eq!(fp.as_str().matches('-').count(), 7);
    }
}
