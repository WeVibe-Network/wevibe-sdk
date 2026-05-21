use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use k256::SecretKey;
use sha2::Sha512;

use crate::errors::CryptoError;

type HmacSha512 = Hmac<Sha512>;

pub struct PreIdentity {
    secret_key: SecretKey,
}

impl PreIdentity {
    pub fn random() -> Result<Self, CryptoError> {
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        Ok(Self { secret_key: sk })
    }

    pub fn derive(parent_key: &[u8; 32], label: &[u8]) -> Result<Self, CryptoError> {
        let mut ctx = HmacSha512::new_from_slice(b"secp256k1-bip32-derive")
            .map_err(|_| CryptoError::InvalidInput("HMAC init failed".into()))?;
        ctx.update(parent_key);
        ctx.update(label);
        let result = ctx.finalize().into_bytes();
        let child_sk_bytes: [u8; 32] = result[..32].try_into().map_err(|_| {
            CryptoError::InvalidPrivateKey
        })?;
        let child_sk = SecretKey::from_bytes((&child_sk_bytes).into())
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { secret_key: child_sk })
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let sk = SecretKey::from_bytes(bytes.into())
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { secret_key: sk })
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes().into()
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        let pk = self.secret_key.public_key();
        pk.to_sec1_bytes().to_vec()
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from(&self.secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_keypair() {
        let id1 = PreIdentity::random().unwrap();
        let id2 = PreIdentity::random().unwrap();
        assert_ne!(id1.secret_key_bytes(), id2.secret_key_bytes());
    }

    #[test]
    fn test_deterministic_derivation() {
        let parent: [u8; 32] = [0x42u8; 32];
        let label = b"test-derivation";
        let id1 = PreIdentity::derive(&parent, label).unwrap();
        let id2 = PreIdentity::derive(&parent, label).unwrap();
        assert_eq!(id1.secret_key_bytes(), id2.secret_key_bytes());
    }

    #[test]
    fn test_different_labels_different_keys() {
        let parent: [u8; 32] = [0x42u8; 32];
        let id1 = PreIdentity::derive(&parent, b"label-a").unwrap();
        let id2 = PreIdentity::derive(&parent, b"label-b").unwrap();
        assert_ne!(id1.secret_key_bytes(), id2.secret_key_bytes());
    }

    #[test]
    fn test_roundtrip_secret_key() {
        let original = PreIdentity::random().unwrap();
        let bytes = original.secret_key_bytes();
        let restored = PreIdentity::from_secret_bytes(&bytes).unwrap();
        assert_eq!(original.secret_key_bytes(), restored.secret_key_bytes());
    }

    #[test]
    fn test_public_key_format() {
        let id = PreIdentity::random().unwrap();
        let pk_bytes = id.public_key_bytes();
        assert_eq!(pk_bytes.len(), 33);
        assert!(pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03);
    }
}