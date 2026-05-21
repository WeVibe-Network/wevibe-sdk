use wevibe_sdk_core::crypto::*;
use wevibe_sdk_core::errors::CryptoError;
use wevibe_sdk_core::{reconstruct_secret, split_secret};
use serde_json::Value;
use std::fs;

#[test]
fn test_epoch_key_derivation_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/test_vectors/epoch_key_derivation.json"
    );
    let mut data: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(path)
            .expect("epoch_key_derivation.json not found — run from wevibe-sdk workspace root"),
    )
    .unwrap();

    let regen = std::env::var("REGEN_VECTORS").is_ok();

    for vector in data.iter_mut() {
        let master_hex = vector["master_key_hex"].as_str().unwrap();
        let epoch = vector["epoch"].as_u64().unwrap() as u32;

        let master: [u8; 32] = hex::decode(master_hex).unwrap().try_into().unwrap();
        let keys = derive_epoch_keys(&master, epoch);

        if regen {
            vector["expected_enc_key_hex"] = Value::String(hex::encode(keys.enc_key));
            vector["expected_search_key_hex"] = Value::String(hex::encode(keys.search_key));
            vector["expected_audit_key_hex"] = Value::String(hex::encode(keys.audit_key));
        } else {
            let exp_enc = vector["expected_enc_key_hex"].as_str().unwrap();
            let exp_search = vector["expected_search_key_hex"].as_str().unwrap();
            let exp_audit = vector["expected_audit_key_hex"].as_str().unwrap();

            assert_eq!(
                hex::encode(keys.enc_key),
                exp_enc,
                "enc_key mismatch for epoch {} — set REGEN_VECTORS=1 cargo test test_epoch_key_derivation_vectors -- --exact to bless new output",
                epoch
            );
            assert_eq!(
                hex::encode(keys.search_key),
                exp_search,
                "search_key mismatch for epoch {} — set REGEN_VECTORS=1 cargo test test_epoch_key_derivation_vectors -- --exact to bless new output",
                epoch
            );
            assert_eq!(
                hex::encode(keys.audit_key),
                exp_audit,
                "audit_key mismatch for epoch {} — set REGEN_VECTORS=1 cargo test test_epoch_key_derivation_vectors -- --exact to bless new output",
                epoch
            );
        }
    }

    if regen {
        fs::write(path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
        eprintln!(
            "REGEN_VECTORS=1 cargo test test_epoch_key_derivation_vectors -- --exact: rewrote epoch_key_derivation.json ({} vectors)",
            data.len()
        );
    }
}

#[test]
fn test_fee_model_hash_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/test_vectors/fee_model_hash.json"
    );
    let mut data: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

    let regen = std::env::var("REGEN_VECTORS").is_ok();
    let vectors = data["vectors"].as_array_mut().unwrap();
    let vec_count = vectors.len();

    for vector in vectors.iter_mut() {
        let canonical = vector["canonical"].as_str().unwrap();
        let expected_hash = vector["sha256_hex"].as_str().unwrap().to_string();

        let canonical_bytes = canonical.as_bytes();
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(canonical_bytes);
        let result = hasher.finalize();
        let actual_hash = hex::encode(result);

        if regen {
            vector["sha256_hex"] = Value::String(actual_hash);
        } else {
            assert_eq!(
                actual_hash, expected_hash,
                "fee_model_hash mismatch — set REGEN_VECTORS=1 cargo test test_fee_model_hash_vectors -- --exact to bless new output"
            );
        }
    }

    if regen {
        let out = serde_json::to_string_pretty(&data).unwrap();
        fs::write(path, out).unwrap();
        eprintln!(
            "REGENERATED: {}/../../protocol/test_vectors/fee_model_hash.json ({} vectors)",
            env!("CARGO_MANIFEST_DIR"),
            vec_count
        );
    }
}

#[test]
fn test_mnemonic_roundtrip_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/test_vectors/mnemonic_roundtrip.json"
    );
    let mut data: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

    let regen = std::env::var("REGEN_VECTORS").is_ok();
    let vectors = data["vectors"].as_array_mut().unwrap();
    let vec_count = vectors.len();

    for vector in vectors.iter_mut() {
        let master_hex = vector["master_key_hex"].as_str().unwrap();
        let expected_phrase = vector["expected_phrase"].as_str().unwrap().to_string();

        let master: [u8; 32] = hex::decode(master_hex).unwrap().try_into().unwrap();
        let actual_phrase = master_key_to_mnemonic(&master).unwrap();

        if regen {
            vector["expected_phrase"] = Value::String(actual_phrase);
        } else {
            assert_eq!(
                actual_phrase, expected_phrase,
                "mnemonic mismatch — set REGEN_VECTORS=1 cargo test test_mnemonic_roundtrip_vectors -- --exact to bless new output"
            );
        }
    }

    if regen {
        let out = serde_json::to_string_pretty(&data).unwrap();
        fs::write(path, out).unwrap();
        eprintln!(
            "REGENERATED: {}/../../protocol/test_vectors/mnemonic_roundtrip.json ({} vectors)",
            env!("CARGO_MANIFEST_DIR"),
            vec_count
        );
    }
}

#[test]
fn test_shamir_roundtrip_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/test_vectors/shamir_roundtrip.json"
    );
    let mut data: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

    let regen = std::env::var("REGEN_VECTORS").is_ok();
    let vectors = data["vectors"].as_array_mut().unwrap();
    let vec_count = vectors.len();

    for vector in vectors.iter_mut() {
        let secret_hex = vector["secret_hex"].as_str().unwrap();
        let threshold = vector["threshold"].as_u64().unwrap() as u8;
        let total_shares = vector["total_shares"].as_u64().unwrap() as u8;

        let secret: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
        let shares = split_secret(&secret, threshold, total_shares);
        let recovered = reconstruct_secret(&shares[0..2].to_vec(), threshold).unwrap();
        assert_eq!(recovered, secret, "shamir roundtrip failed for {}", secret_hex);
    }

    if regen {
        let out = serde_json::to_string_pretty(&data).unwrap();
        fs::write(path, out).unwrap();
        eprintln!(
            "REGENERATED: {}/../../protocol/test_vectors/shamir_roundtrip.json ({} vectors)",
            env!("CARGO_MANIFEST_DIR"),
            vec_count
        );
    }
}

#[test]
fn test_seal_open_envelope_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/test_vectors/seal_open_envelope.json"
    );
    let mut data: Vec<Value> = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

    let regen = std::env::var("REGEN_VECTORS").is_ok();

    for vector in data.iter_mut() {
        let priv_hex = vector["recipient_x25519_privkey_hex"].as_str().unwrap();
        let plaintext_hex = vector["plaintext_hex"].as_str().unwrap();

        let privkey: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let pubkey: [u8; 32] = {
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(privkey);
            *PublicKey::from(&secret).as_bytes()
        };
        let plaintext = hex::decode(plaintext_hex).unwrap();

        let blob = seal_to_pubkey(&plaintext, &pubkey);
        let recovered = open_envelope(&blob, &privkey).unwrap();
        assert_eq!(
            recovered, plaintext,
            "seal/open roundtrip failed for vector"
        );

        if let Some(expected_pub_hex) = vector
            .get("recipient_x25519_pubkey_hex")
            .and_then(|v| v.as_str())
        {
            let actual_pub_hex = hex::encode(pubkey);
            if regen {
                vector["recipient_x25519_pubkey_hex"] = Value::String(actual_pub_hex.clone());
            } else {
                assert_eq!(
                    actual_pub_hex, expected_pub_hex,
                    "stored pubkey does not match derived pubkey — set REGEN_VECTORS=1 cargo test test_seal_open_envelope_vectors -- --exact to bless new output"
                );
            }
        }
    }

    if regen {
        let out = serde_json::to_string_pretty(&data).unwrap();
        fs::write(path, out).unwrap();
        eprintln!(
            "REGENERATED: {}/../../protocol/test_vectors/seal_open_envelope.json ({} vectors)",
            env!("CARGO_MANIFEST_DIR"),
            data.len()
        );
    }
}

#[test]
fn test_identity_ed25519_privkey_32_bytes() {
    let (ed_priv, _, _, _) = generate_identity();
    assert_eq!(ed_priv.len(), 32);
}
#[test]
fn test_identity_ed25519_pubkey_32_bytes() {
    let (_, ed_pub, _, _) = generate_identity();
    assert_eq!(ed_pub.len(), 32);
}
#[test]
fn test_identity_x25519_privkey_32_bytes() {
    let (_, _, xpriv, _) = generate_identity();
    assert_eq!(xpriv.len(), 32);
}
#[test]
fn test_identity_x25519_pubkey_32_bytes() {
    let (_, _, _, xpub) = generate_identity();
    assert_eq!(xpub.len(), 32);
}
#[test]
fn test_identities_unique() {
    let a = generate_identity();
    let b = generate_identity();
    assert_ne!(a.0, b.0);
    assert_ne!(a.2, b.2);
}

#[test]
fn test_sign_returns_64_bytes() {
    let (ed_priv, _, _, _) = generate_identity();
    let sig = sign(&ed_priv, b"test").unwrap();
    assert_eq!(sig.len(), 64);
}
#[test]
fn test_verify_valid() {
    let (ed_priv, ed_pub, _, _) = generate_identity();
    let sig = sign(&ed_priv, b"data").unwrap();
    assert!(verify(&ed_pub, &sig, b"data"));
}
#[test]
fn test_verify_tampered_data() {
    let (ed_priv, ed_pub, _, _) = generate_identity();
    let sig = sign(&ed_priv, b"original").unwrap();
    assert!(!verify(&ed_pub, &sig, b"tampered"));
}
#[test]
fn test_verify_wrong_key() {
    let (pa, _, _, _) = generate_identity();
    let (_, pb, _, _) = generate_identity();
    let sig = sign(&pa, b"data").unwrap();
    assert!(!verify(&pb, &sig, b"data"));
}
#[test]
fn test_ed25519_deterministic() {
    let (ed_priv, _, _, _) = generate_identity();
    assert_eq!(sign(&ed_priv, b"x").unwrap(), sign(&ed_priv, b"x").unwrap());
}

#[test]
fn test_seal_open_roundtrip() {
    let (_, _, xpriv, xpub) = generate_identity();
    let pt = b"secret memory content";
    let blob = seal_to_pubkey(pt, &xpub);
    assert_eq!(open_envelope(&blob, &xpriv).unwrap(), pt);
}
#[test]
fn test_seal_open_empty() {
    let (_, _, xpriv, xpub) = generate_identity();
    let blob = seal_to_pubkey(&[], &xpub);
    let result = open_envelope(&blob, &xpriv).unwrap();
    assert!(result.is_empty());
}
#[test]
fn test_seal_open_large() {
    let (_, _, xpriv, xpub) = generate_identity();
    let pt = vec![0xABu8; 65536];
    let blob = seal_to_pubkey(&pt, &xpub);
    assert_eq!(open_envelope(&blob, &xpriv).unwrap(), pt);
}
#[test]
fn test_seal_nondeterministic() {
    let (_, _, _, xpub) = generate_identity();
    assert_ne!(
        seal_to_pubkey(b"same", &xpub),
        seal_to_pubkey(b"same", &xpub)
    );
}
#[test]
fn test_open_wrong_key_fails() {
    let (_, _, _, xpub) = generate_identity();
    let (_, _, xpriv2, _) = generate_identity();
    let blob = seal_to_pubkey(b"secret", &xpub);
    assert!(open_envelope(&blob, &xpriv2).is_err());
}
#[test]
fn test_open_tampered_fails() {
    let (_, _, xpriv, xpub) = generate_identity();
    let mut blob = seal_to_pubkey(b"secret", &xpub);
    *blob.last_mut().unwrap() ^= 0xFF;
    assert!(open_envelope(&blob, &xpriv).is_err());
}
#[test]
fn test_open_too_short() {
    let (_, _, xpriv, _) = generate_identity();
    assert!(matches!(
        open_envelope(b"short", &xpriv),
        Err(CryptoError::EnvelopeTooShort(_))
    ));
}

#[test]
fn test_sym_roundtrip() {
    let key = generate_dek();
    let blob = encrypt_symmetric(b"hello", &key);
    assert_eq!(decrypt_symmetric(&blob, &key).unwrap(), b"hello");
}
#[test]
fn test_sym_empty() {
    let key = generate_dek();
    let blob = encrypt_symmetric(&[], &key);
    let result = decrypt_symmetric(&blob, &key).unwrap();
    assert!(result.is_empty());
}
#[test]
fn test_sym_nondeterministic() {
    let key = generate_dek();
    assert_ne!(encrypt_symmetric(b"x", &key), encrypt_symmetric(b"x", &key));
}
#[test]
fn test_sym_blob_length() {
    let key = generate_dek();
    let blob = encrypt_symmetric(b"hello", &key);
    assert_eq!(blob.len(), 12 + 5 + 16);
}
#[test]
fn test_sym_wrong_key_fails() {
    let k1 = generate_dek();
    let k2 = generate_dek();
    let blob = encrypt_symmetric(b"data", &k1);
    assert!(decrypt_symmetric(&blob, &k2).is_err());
}
#[test]
fn test_sym_tampered_fails() {
    let key = generate_dek();
    let mut blob = encrypt_symmetric(b"data", &key);
    *blob.last_mut().unwrap() ^= 0xFF;
    assert!(decrypt_symmetric(&blob, &key).is_err());
}
#[test]
fn test_sym_too_short() {
    let key = generate_dek();
    assert!(matches!(
        decrypt_symmetric(b"short", &key),
        Err(CryptoError::BlobTooShort(_))
    ));
}

#[test]
fn test_dek_32_bytes() {
    assert_eq!(generate_dek().len(), 32);
}
#[test]
fn test_dek_unique() {
    assert_ne!(generate_dek(), generate_dek());
}

#[test]
fn test_epoch_keys_deterministic() {
    let m = generate_dek();
    let a = derive_epoch_keys(&m, 0);
    let b = derive_epoch_keys(&m, 0);
    assert_eq!(a.enc_key, b.enc_key);
    assert_eq!(a.search_key, b.search_key);
    assert_eq!(a.audit_key, b.audit_key);
}
#[test]
fn test_epoch_keys_differ_across_epochs() {
    let m = generate_dek();
    let e0 = derive_epoch_keys(&m, 0);
    let e1 = derive_epoch_keys(&m, 1);
    assert_ne!(e0.enc_key, e1.enc_key);
    assert_ne!(e0.search_key, e1.search_key);
}
#[test]
fn test_epoch_keys_three_distinct() {
    let m = generate_dek();
    let k = derive_epoch_keys(&m, 0);
    assert_ne!(k.enc_key, k.search_key);
    assert_ne!(k.enc_key, k.audit_key);
    assert_ne!(k.search_key, k.audit_key);
}
#[test]
fn test_epoch_keys_different_masters() {
    let a = derive_epoch_keys(&generate_dek(), 0);
    let b = derive_epoch_keys(&generate_dek(), 0);
    assert_ne!(a.enc_key, b.enc_key);
}
#[test]
fn test_epoch_large() {
    let m = generate_dek();
    let k = derive_epoch_keys(&m, 65535);
    assert_eq!(k.epoch, 65535);
    assert_eq!(k.enc_key.len(), 32);
}

#[test]
fn test_blind_token_len() {
    let k = generate_dek();
    assert_eq!(compute_blind_token("redis", &k).len(), 64);
}
#[test]
fn test_blind_token_hex() {
    let k = generate_dek();
    assert!(compute_blind_token("redis", &k)
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
}
#[test]
fn test_blind_token_deterministic() {
    let k = generate_dek();
    assert_eq!(
        compute_blind_token("redis", &k),
        compute_blind_token("redis", &k)
    );
}
#[test]
fn test_blind_token_keyword_domain_separation() {
    let k = generate_dek();
    assert_ne!(
        compute_blind_token("redis", &k),
        compute_blind_token("postgres", &k)
    );
}
#[test]
fn test_blind_token_key_domain_separation() {
    assert_ne!(
        compute_blind_token("redis", &generate_dek()),
        compute_blind_token("redis", &generate_dek())
    );
}
#[test]
fn test_blind_token_opaque() {
    let k = generate_dek();
    let t = compute_blind_token("supersecretkeyword", &k);
    assert!(!t.contains("supersecretkeyword"));
}

#[test]
fn test_shamir_split_produces_correct_number_of_shares() {
    let secret = [0x42u8; 32];
    let shares = split_secret(&secret, 2, 3);
    assert_eq!(shares.len(), 3);
    for share in &shares {
        assert!(!share.is_empty());
    }
}

#[test]
fn test_shamir_reconstruct_with_2_of_3() {
    let secret = [0xAAu8; 32];
    let shares = split_secret(&secret, 2, 3);
    let recovered = reconstruct_secret(&shares[0..2].to_vec(), 2).unwrap();
    assert_eq!(recovered, secret);
    let recovered = reconstruct_secret(&shares[1..3].to_vec(), 2).unwrap();
    assert_eq!(recovered, secret);
    let recovered = reconstruct_secret(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_shamir_reconstruct_with_all_3() {
    let secret = [0xBBu8; 32];
    let shares = split_secret(&secret, 2, 3);
    let recovered = reconstruct_secret(&shares, 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_shamir_single_share_insufficient() {
    let secret = [0xCCu8; 32];
    let shares = split_secret(&secret, 2, 3);
    let result = reconstruct_secret(&shares[0..1].to_vec(), 2);
    assert!(result.is_err());
}

#[test]
fn test_shamir_invalid_share_data() {
    let result = reconstruct_secret(&[vec![0, 1, 2]], 2);
    assert!(result.is_err());
}

#[test]
fn test_shamir_roundtrip_random_key() {
    let secret = generate_dek();
    let shares = split_secret(&secret, 2, 3);
    let recovered = reconstruct_secret(&shares[0..2].to_vec(), 2).unwrap();
    assert_eq!(recovered, secret);
}
