use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::errors::CryptoError;

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result as u8
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    for b in 1u16..=255 {
        if gf256_mul(a, b as u8) == 1 {
            return b as u8;
        }
    }
    0
}

fn gf256_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    for coeff in coeffs.iter().rev() {
        result = gf256_mul(result, x) ^ coeff;
    }
    result
}

pub fn split_secret(secret: &[u8; 32], threshold: u8, total_shares: u8) -> Vec<Vec<u8>> {
    assert!(threshold >= 2, "threshold must be >= 2");
    assert!(
        total_shares >= threshold,
        "total_shares must be >= threshold"
    );
    assert!(total_shares <= 255, "total_shares must be <= 255");

    let mut shares: Vec<Vec<u8>> = (0..total_shares).map(|i| vec![i + 1]).collect();

    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; threshold as usize];
        coeffs[0] = secret[byte_idx];
        for j in 1..threshold as usize {
            let mut rand_byte = [0u8; 1];
            OsRng.fill_bytes(&mut rand_byte);
            coeffs[j] = rand_byte[0];
        }

        for (i, share) in shares.iter_mut().enumerate() {
            let x = (i + 1) as u8;
            let y = gf256_poly_eval(&coeffs, x);
            share.push(y);
        }
    }

    shares
}

pub fn reconstruct_secret(shares: &[Vec<u8>], _threshold: u8) -> Result<[u8; 32], CryptoError> {
    if shares.len() < 2 {
        return Err(CryptoError::InvalidInput("need at least 2 shares".into()));
    }

    for (i, share) in shares.iter().enumerate() {
        if share.len() != 33 {
            return Err(CryptoError::InvalidInput(format!(
                "share {} has {} bytes, expected 33",
                i,
                share.len()
            )));
        }
    }

    let k = shares.len();
    let xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();

    for i in 0..k {
        for j in (i + 1)..k {
            if xs[i] == xs[j] {
                return Err(CryptoError::InvalidInput("duplicate share indices".into()));
            }
        }
    }

    let mut secret = [0u8; 32];

    for byte_idx in 0..32 {
        let ys: Vec<u8> = shares.iter().map(|s| s[byte_idx + 1]).collect();

        let mut result: u8 = 0;
        for i in 0..k {
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for j in 0..k {
                if i == j {
                    continue;
                }
                num = gf256_mul(num, xs[j]);
                den = gf256_mul(den, xs[i] ^ xs[j]);
            }
            let basis = gf256_mul(num, gf256_inv(den));
            result ^= gf256_mul(ys[i], basis);
        }
        secret[byte_idx] = result;
    }

    Ok(secret)
}

pub fn generate_identity() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let ed_signing = SigningKey::generate(&mut OsRng);
    let ed_privkey: [u8; 32] = ed_signing.to_bytes();
    let ed_pubkey: [u8; 32] = ed_signing.verifying_key().to_bytes();

    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_pubkey = X25519PublicKey::from(&x_secret);
    let x_privkey: [u8; 32] = x_secret.to_bytes();
    let x_pubkey_bytes: [u8; 32] = *x_pubkey.as_bytes();

    (ed_privkey, ed_pubkey, x_privkey, x_pubkey_bytes)
}

pub fn sign(privkey: &[u8; 32], data: &[u8]) -> Result<[u8; 64], CryptoError> {
    let signing_key = SigningKey::from_bytes(privkey);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

pub fn verify(pubkey: &[u8; 32], signature: &[u8; 64], data: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key.verify(data, &sig).is_ok()
}

pub fn seal_to_pubkey(plaintext: &[u8], recipient_x25519_pubkey: &[u8; 32]) -> Vec<u8> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    let recipient_pubkey = X25519PublicKey::from(*recipient_x25519_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"wevibe-envelope-v1", &mut aes_key)
        .expect("HKDF expand failed");

    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-GCM encrypt failed");

    aes_key.zeroize();

    let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
    blob.extend_from_slice(ephemeral_pubkey.as_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

pub fn open_envelope(blob: &[u8], our_x25519_privkey: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 32 + 12 + 16 {
        return Err(CryptoError::EnvelopeTooShort(blob.len()));
    }

    let ephemeral_pubkey_bytes: [u8; 32] = blob[..32].try_into().unwrap();
    let nonce_bytes: [u8; 12] = blob[32..44].try_into().unwrap();
    let ciphertext_with_tag = &blob[44..];

    let our_secret = StaticSecret::from(*our_x25519_privkey);
    let ephemeral_pubkey = X25519PublicKey::from(ephemeral_pubkey_bytes);
    let shared_secret = our_secret.diffie_hellman(&ephemeral_pubkey);

    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"wevibe-envelope-v1", &mut aes_key)
        .map_err(|_| CryptoError::HkdfError)?;

    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    aes_key.zeroize();
    Ok(plaintext)
}

pub fn encrypt_symmetric(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-GCM encrypt failed");
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

pub fn decrypt_symmetric(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 12 + 16 {
        return Err(CryptoError::BlobTooShort(blob.len()));
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let ciphertext_with_tag = &blob[12..];
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut dek);
    dek
}

pub struct EpochKeys {
    pub epoch: u32,
    pub enc_key: [u8; 32],
    pub search_key: [u8; 32],
    pub audit_key: [u8; 32],
}

pub fn derive_epoch_keys(master_key: &[u8; 32], epoch: u32) -> EpochKeys {
    let epoch_bytes = epoch.to_be_bytes();

    let derive = |info_prefix: &[u8]| -> [u8; 32] {
        let mut info = Vec::with_capacity(info_prefix.len() + 4);
        info.extend_from_slice(info_prefix);
        info.extend_from_slice(&epoch_bytes);

        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), master_key);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("HKDF expand failed");
        okm
    };

    EpochKeys {
        epoch,
        enc_key: derive(b"wevibe-enc-"),
        search_key: derive(b"wevibe-search-"),
        audit_key: derive(b"wevibe-audit-"),
    }
}

pub fn compute_blind_token(keyword: &str, search_key: &[u8; 32]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(search_key).expect("HMAC key length always valid");
    mac.update(keyword.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

pub fn master_key_to_mnemonic(master_key: &[u8; 32]) -> Result<String, CryptoError> {
    let mnemonic = bip39::Mnemonic::from_entropy(master_key)
        .map_err(|e| CryptoError::MnemonicError(e.to_string()))?;
    Ok(mnemonic.to_string())
}

pub fn mnemonic_to_master_key(phrase: &str) -> Result<[u8; 32], CryptoError> {
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(|e: bip39::Error| CryptoError::MnemonicError(e.to_string()))?;
    let (entropy_arr, len) = mnemonic.to_entropy_array();
    if len != 32 {
        return Err(CryptoError::MnemonicError(format!(
            "expected 32 bytes of entropy, got {}",
            len
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&entropy_arr[..32]);
    Ok(key)
}

#[cfg(test)]
mod mnemonic_test_vectors {
    use super::*;

    #[test]
    fn print_mnemonic_vectors() {
        let all_zeros = [0u8; 32];
        let all_ones = [0xffu8; 32];
        let sequential: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();

        println!("all_zeros: {}", master_key_to_mnemonic(&all_zeros).unwrap());
        println!("all_ones: {}", master_key_to_mnemonic(&all_ones).unwrap());
        println!(
            "sequential: {}",
            master_key_to_mnemonic(&sequential).unwrap()
        );
    }
}
