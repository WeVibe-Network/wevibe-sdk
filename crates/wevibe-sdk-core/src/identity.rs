use crate::errors::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub trait Identity: Send + Sync {
    fn ed25519_pubkey_hex(&self) -> String;
    fn x25519_pubkey_hex(&self) -> String;
    fn sign_hex(&self, message: &[u8]) -> Result<String, CryptoError>;
    fn org_ids(&self) -> Vec<String>;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalIdentity {
    ed25519_priv: [u8; 32],
    ed25519_pub: [u8; 32],
    x25519_priv: [u8; 32],
    x25519_pub: [u8; 32],
    org_ids: Vec<String>,
}

impl LocalIdentity {
    pub fn generate() -> Result<Self, CryptoError> {
        let (ed_priv, ed_pub, x_priv, x_pub) = crate::crypto::generate_identity();
        Ok(Self {
            ed25519_priv: ed_priv,
            ed25519_pub: ed_pub,
            x25519_priv: x_priv,
            x25519_pub: x_pub,
            org_ids: vec![],
        })
    }

    pub fn from_bytes(
        ed25519_priv: [u8; 32],
        ed25519_pub: [u8; 32],
        x25519_priv: [u8; 32],
        x25519_pub: [u8; 32],
    ) -> Self {
        Self {
            ed25519_priv,
            ed25519_pub,
            x25519_priv,
            x25519_pub,
            org_ids: vec![],
        }
    }

    pub fn with_org(mut self, org_id: impl Into<String>) -> Self {
        self.org_ids.push(org_id.into());
        self
    }
}

impl Identity for LocalIdentity {
    fn ed25519_pubkey_hex(&self) -> String {
        hex::encode(self.ed25519_pub)
    }

    fn x25519_pubkey_hex(&self) -> String {
        hex::encode(self.x25519_pub)
    }

    fn sign_hex(&self, message: &[u8]) -> Result<String, CryptoError> {
        let sig = crate::crypto::sign(&self.ed25519_priv, message)?;
        Ok(hex::encode(sig))
    }

    fn org_ids(&self) -> Vec<String> {
        self.org_ids.clone()
    }
}

pub struct SolanaIdentity {
    ed25519_pub: [u8; 32],
    x25519_pub: [u8; 32],
    org_ids: Vec<String>,
}

impl SolanaIdentity {
    pub fn new(ed25519_pub: [u8; 32], x25519_pub: [u8; 32]) -> Self {
        Self {
            ed25519_pub,
            x25519_pub,
            org_ids: vec![],
        }
    }
}

impl Identity for SolanaIdentity {
    fn ed25519_pubkey_hex(&self) -> String {
        hex::encode(self.ed25519_pub)
    }
    fn x25519_pubkey_hex(&self) -> String {
        hex::encode(self.x25519_pub)
    }
    fn sign_hex(&self, _message: &[u8]) -> Result<String, CryptoError> {
        Err(CryptoError::InvalidPrivateKey)
    }
    fn org_ids(&self) -> Vec<String> {
        self.org_ids.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_identity_generates() {
        let id = LocalIdentity::generate().unwrap();
        assert_eq!(id.ed25519_pubkey_hex().len(), 64);
        assert_eq!(id.x25519_pubkey_hex().len(), 64);
    }

    #[test]
    fn test_local_identity_signs() {
        let id = LocalIdentity::generate().unwrap();
        let msg = b"test message";
        let sig_hex = id.sign_hex(msg).unwrap();
        assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn test_local_identity_sign_verify_roundtrip() {
        let id = LocalIdentity::generate().unwrap();
        let msg = b"wevibe network test";
        let sig_hex = id.sign_hex(msg).unwrap();
        let sig_bytes = hex::decode(&sig_hex).unwrap();
        let pub_bytes = hex::decode(id.ed25519_pubkey_hex()).unwrap();

        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        assert!(crate::crypto::verify(&pub_arr, &sig_arr, msg));
    }

    #[test]
    fn test_org_membership() {
        let id = LocalIdentity::generate().unwrap().with_org("acme-corp");
        assert_eq!(id.org_ids(), vec!["acme-corp"]);
    }

    #[test]
    fn test_solana_identity_sign_returns_err() {
        let id = SolanaIdentity::new([0u8; 32], [0u8; 32]);
        assert!(id.sign_hex(b"test").is_err());
    }

    #[test]
    fn test_local_identity_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<LocalIdentity>();
    }
}
