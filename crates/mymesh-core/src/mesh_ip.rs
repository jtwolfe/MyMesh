//! Stable loopback mesh addresses in 127.64.0.0/16 (no privileges required on Linux).
use crate::DeviceId;
use std::net::Ipv4Addr;

/// Derive a unique 127.64.x.y address from a device id.
/// Avoids .0 and .255 in the last octet.
pub fn mesh_ipv4(id: &DeviceId) -> Ipv4Addr {
    let b = id.as_bytes();
    let mut x = b[0] as u16;
    x ^= (b[1] as u16) << 1;
    x ^= b[2] as u16;
    let mut y = b[3] as u16;
    y ^= (b[4] as u16) << 2;
    y ^= b[5] as u16;
    let hi = (x % 254 + 1) as u8; // 1..=254
    let lo = (y % 254 + 1) as u8;
    Ipv4Addr::new(127, 64, hi, lo)
}

pub fn mesh_ip_string(id: &DeviceId) -> String {
    mesh_ipv4(id).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceId;

    #[test]
    fn in_loopback_range() {
        let id = DeviceId::from_bytes([7u8; 32]);
        let ip = mesh_ipv4(&id);
        assert_eq!(ip.octets()[0], 127);
        assert_eq!(ip.octets()[1], 64);
        assert_ne!(ip.octets()[3], 0);
        assert_ne!(ip.octets()[3], 255);
    }
}
