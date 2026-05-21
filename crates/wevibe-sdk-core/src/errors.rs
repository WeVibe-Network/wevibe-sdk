use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("envelope too short: {0} bytes (minimum 60)")]
    EnvelopeTooShort(usize),
    #[error("blob too short: {0} bytes (minimum 28)")]
    BlobTooShort(usize),
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid private key bytes")]
    InvalidPrivateKey,
    #[error("HKDF expansion failed")]
    HkdfError,
    #[error("mnemonic error: {0}")]
    MnemonicError(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
