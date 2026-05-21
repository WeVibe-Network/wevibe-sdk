# wevibe-sdk Topology (Updated: CO-216)

## Integration Diagram

```
            +--------------+
            |  wevibe-mcp  |
            +--------------+
                  |
                  | WASM FFI / native FFI
                  v
            +--------------+
            |  wevibe-sdk    |
            +--------------+
             /     |      \
            /      |       \
    Identity   Crypto   Attestation   secp256k1 (CO-216)
       |         |           |              |
       v         v           v              v
  Anchor CLI  Ciphertext  Serve envelopes  PRE identity (NEW)
               builder
```

## Module Inventory (Updated: CO-216)

### Identity Module

**Location:** `crates/wevibe-sdk-core/src/identity.rs`

Generates org member keypairs, sealed envelopes, recovery phrases. Used by both CLI and dashboard.

### Crypto Module

**Location:** `crates/wevibe-sdk-core/src/crypto.rs`

Encrypts memory payloads; outputs ciphertext + wrapped DEK + commitment.

### Epoch Module

**Location:** (part of identity/crypto)

Derives `K_enc(e)` and `K_audit(e)`; consumed by encryption and attestation modules.

### secp256k1 Module (NEW — CO-216)

**Location:** `crates/wevibe-sdk-core/src/secp256k1.rs`

Provides secp256k1 key operations for PRE (Proxy Re-Encryption) identity management. This module is the Apache-2.0 bridge between WeVibe Network’s ed25519/x25519 identity system and the secp256k1-based Umbral PRE system.

**Key type:** `PreIdentity`
- `random()` — generate random PRE identity keypair
- `derive(parent_key: &[u8; 32], label: &[u8])` — BIP-32-style key derivation
- `from_secret_bytes(bytes: &[u8; 32])` — reconstruct from raw 32-byte BE scalar
- `secret_key_bytes()` — serialize as 32-byte big-endian (Umbral-compatible)
- `public_key_bytes()` — serialize as 33-byte compressed secp256k1 (Umbral-compatible)
- `signing_key()` — get `k256::ecdsa::SigningKey` for ECDSA operations

**Derivation label:** `PRE_DERIVATION_LABEL = b"wevibe-pre-identity/v1"`

**Serialization compatibility:**
- Secret key: 32-byte big-endian scalar — compatible with `umbral_pre::SecretKey::try_from_be_bytes()`
- Public key: 33-byte compressed secp256k1 — compatible with `umbral_pre::PublicKey::try_from_array()`

**License:** MIT/Apache-2.0 (uses `k256`, NOT `umbral-pre`)

### Merkle Module

**Location:** (part of crypto)

Builds incremental trees for chunked payloads; required by wevibe-chain for inclusion proofs.

### Attestation Module

**Location:** (part of identity)

Signs serve events using member key; outputs envelope consumed by x/serve.

## Deployment Targets

- Native Rust library linked by dashboard backend and CLI.
- WASM module embedded inside wevibe-mcp.
- Python wheel for moderation scripts.

## Data Stores

- `~/.wevibe/identity/` — sealed envelopes + recovery metadata.
- `~/.wevibe/cache/merkle/` — cached merkle paths per memory.
- Temporary buffers stored in-memory; no plaintext persisted after encryption step.

## External Interfaces

- Accepts plaintext buffers from CLI or MCP.
- Emits ciphertext packages for wevibe-chain transactions (`MsgSubmitCommitment`).
- Emits attestation envelopes for `MsgSubmitServeBatch`.

## PRE Integration (CO-216)

The `secp256k1` module enables WeVibe Network’s PRE architecture by providing byte-compatible keys for Umbral operations:

```
WeVibe wallet secp256k1 key
        │
        └── BIP-32 derive (PRE_DERIVATION_LABEL)
                │
                v
        PreIdentity (secp256k1)
                │
        ├── secret_key_bytes() → 32-byte BE → umbral_pre::SecretKey::try_from_be_bytes()
        └── public_key_bytes() → 33-byte compressed → umbral_pre::PublicKey::try_from_array()
```

**Why separate from umbral-pre:** The wevibe-sdk is Apache-2.0 licensed. `umbral-pre` is GPL-3.0. The secp256k1 module uses `k256` (MIT/Apache-2.0) to generate compatible key material without introducing the GPL dependency into the SDK.

## Sprint 24 Notes

- SDK surfaces moderation provenance metadata so downstream components know when hub quorum has marked a memory ready.
- Added helper shims used by the OpenCode plugin to align Accept / Deny / Report outcomes with stored ciphertext packages.
- Integration guidance references fee grant-backed moderator approvals relying on SDK attestation helpers.
- **CO-216:** secp256k1 module added for PRE identity. Byte-compatible with Umbral SecretKey/PublicKey format.

## Performance Notes

- Uses streaming encryptor to cap memory usage; chunk size default 64 KiB.
- Merkle tree builder uses poseidon-like (SHA-256) hashed leaves for compatibility with chain.
- Zeroize feature recommended for production to wipe secrets.
