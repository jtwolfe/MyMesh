//! SPAKE2-based pairing (Signal-style linked devices / magic-wormhole codes).
use hkdf::Hkdf;
use mymesh_core::{Error, Result};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity as SpakeIdentity, Password, Spake2};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRole {
    /// Device that generates and displays the code.
    Host,
    /// Device that enters the code.
    Guest,
}

/// High-entropy shared secret after successful SPAKE2.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive application keys (e.g. channel encryption, confirmation MAC).
    pub fn derive(&self, info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out).expect("hkdf expand 32 bytes");
        out
    }
}

pub struct PairingSession {
    role: PairingRole,
    state: Spake2<Ed25519Group>,
    outbound_msg: Vec<u8>,
}

impl PairingSession {
    pub fn start(role: PairingRole, password: &[u8]) -> Result<Self> {
        let pw = Password::new(password);
        // Symmetric SPAKE2: both sides use same identity string "mymesh-pair-v1".
        let id = SpakeIdentity::new(b"mymesh-pair-v1");
        let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(&pw, &id);
        let _ = role; // role is reserved for asymmetric flows / UI; SPAKE2 is symmetric here
        Ok(Self {
            role,
            state,
            outbound_msg: msg,
        })
    }

    pub fn role(&self) -> PairingRole {
        self.role
    }

    /// First (and only) message to send to the peer over the rendezvous channel.
    pub fn outbound_message(&self) -> &[u8] {
        &self.outbound_msg
    }

    /// Finish after receiving the peer's SPAKE2 message.
    pub fn finish(self, peer_msg: &[u8]) -> Result<SharedSecret> {
        let key = self
            .state
            .finish(peer_msg)
            .map_err(|e| Error::Pairing(format!("SPAKE2 failed: {e}")))?;
        if key.len() < 32 {
            return Err(Error::Pairing("shared key too short".into()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&key[..32]);
        Ok(SharedSecret(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spake2_handshake() {
        let host = PairingSession::start(PairingRole::Host, b"42-maple-orbit").unwrap();
        let guest = PairingSession::start(PairingRole::Guest, b"42-maple-orbit").unwrap();
        let h_msg = host.outbound_message().to_vec();
        let g_msg = guest.outbound_message().to_vec();
        let h_secret = host.finish(&g_msg).unwrap();
        let g_secret = guest.finish(&h_msg).unwrap();
        assert_eq!(h_secret.as_bytes(), g_secret.as_bytes());
    }
}
