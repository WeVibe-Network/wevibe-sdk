use wevibe_sdk_core::crypto;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_identity() -> js_sys::Array {
    let (ed_priv, ed_pub, x_priv, x_pub) = crypto::generate_identity();
    let arr = js_sys::Array::new();
    arr.push(&js_sys::Uint8Array::from(ed_priv.as_ref()));
    arr.push(&js_sys::Uint8Array::from(ed_pub.as_ref()));
    arr.push(&js_sys::Uint8Array::from(x_priv.as_ref()));
    arr.push(&js_sys::Uint8Array::from(x_pub.as_ref()));
    arr
}

#[wasm_bindgen]
pub fn sign(privkey: &[u8], data: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let privkey: [u8; 32] = privkey
        .try_into()
        .map_err(|_| JsError::new("privkey must be 32 bytes"))?;
    let sig = crypto::sign(&privkey, data).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(sig.as_ref()))
}

#[wasm_bindgen]
pub fn verify(pubkey: &[u8], signature: &[u8], data: &[u8]) -> bool {
    let Ok(pubkey) = pubkey.try_into() else {
        return false;
    };
    let Ok(signature) = signature.try_into() else {
        return false;
    };
    crypto::verify(&pubkey, &signature, data)
}

#[wasm_bindgen]
pub fn seal_to_pubkey(
    plaintext: &[u8],
    recipient_pubkey: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let recipient: [u8; 32] = recipient_pubkey
        .try_into()
        .map_err(|_| JsError::new("recipient_pubkey must be 32 bytes"))?;
    let blob = crypto::seal_to_pubkey(plaintext, &recipient);
    Ok(js_sys::Uint8Array::from(blob.as_slice()))
}

#[wasm_bindgen]
pub fn open_envelope(blob: &[u8], privkey: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let privkey: [u8; 32] = privkey
        .try_into()
        .map_err(|_| JsError::new("privkey must be 32 bytes"))?;
    let plaintext =
        crypto::open_envelope(blob, &privkey).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(plaintext.as_slice()))
}

#[wasm_bindgen]
pub fn encrypt_symmetric(plaintext: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("key must be 32 bytes"))?;
    let blob = crypto::encrypt_symmetric(plaintext, &key);
    Ok(js_sys::Uint8Array::from(blob.as_slice()))
}

#[wasm_bindgen]
pub fn decrypt_symmetric(blob: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("key must be 32 bytes"))?;
    let plaintext =
        crypto::decrypt_symmetric(blob, &key).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(plaintext.as_slice()))
}

#[wasm_bindgen]
pub fn compute_blind_token(keyword: &str, search_key: &[u8]) -> Result<String, JsError> {
    let key: [u8; 32] = search_key
        .try_into()
        .map_err(|_| JsError::new("search_key must be 32 bytes"))?;
    Ok(crypto::compute_blind_token(keyword, &key))
}

#[wasm_bindgen]
pub fn derive_epoch_keys(master_key: &[u8], epoch: u32) -> Result<js_sys::Array, JsError> {
    let key: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let keys = crypto::derive_epoch_keys(&key, epoch);
    let arr = js_sys::Array::new();
    arr.push(&js_sys::Uint8Array::from(keys.enc_key.as_ref()));
    arr.push(&js_sys::Uint8Array::from(keys.search_key.as_ref()));
    arr.push(&js_sys::Uint8Array::from(keys.audit_key.as_ref()));
    Ok(arr)
}

#[wasm_bindgen]
pub fn generate_dek() -> js_sys::Uint8Array {
    let dek = crypto::generate_dek();
    js_sys::Uint8Array::from(dek.as_ref())
}

#[wasm_bindgen]
pub fn master_key_to_mnemonic(master_key: &[u8]) -> Result<String, JsError> {
    let key: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    crypto::master_key_to_mnemonic(&key).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn mnemonic_to_master_key(phrase: &str) -> Result<js_sys::Uint8Array, JsError> {
    let key = crypto::mnemonic_to_master_key(phrase).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(key.as_ref()))
}

#[wasm_bindgen(js_name = "splitSecret")]
pub fn split_secret_wasm(
    secret: &[u8],
    threshold: u8,
    total_shares: u8,
) -> Result<JsValue, JsError> {
    if secret.len() != 32 {
        return Err(JsError::new("secret must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(secret);
    let shares = wevibe_sdk_core::split_secret(&key, threshold, total_shares);
    serde_json::to_string(&shares)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("serialization error: {}", e)))
}

#[wasm_bindgen(js_name = "reconstructSecret")]
pub fn reconstruct_secret_wasm(shares_json: &str, threshold: u8) -> Result<Vec<u8>, JsError> {
    let shares: Vec<Vec<u8>> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("invalid shares JSON: {}", e)))?;
    let key = wevibe_sdk_core::reconstruct_secret(&shares, threshold)
        .map_err(|e| JsError::new(&format!("{}", e)))?;
    Ok(key.to_vec())
}
