use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mymesh_core::{DeviceId, Error, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Long-term node identity. Private key material is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    signing: SigningKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublic {
    pub verifying_key: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            let id = Self::generate();
            id.save(path)?;
            Ok(id)
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(Error::Identity(format!(
                "identity key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();
        Ok(Self { signing })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = self.signing.to_bytes();
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_bytes(self.signing.verifying_key().to_bytes())
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            verifying_key: self.signing.verifying_key().to_bytes(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

impl IdentityPublic {
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_bytes(self.verifying_key)
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|e| Error::Identity(e.to_string()))?;
        let signature = Signature::from_bytes(sig);
        vk.verify(msg, &signature)
            .map_err(|e| Error::Identity(format!("bad signature: {e}")))
    }
}
