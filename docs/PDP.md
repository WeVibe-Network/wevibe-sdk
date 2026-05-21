# wevibe-sdk PDP

## Crate Layout

- `src/lib.rs` — feature-gated library entry.
- `src/identity.rs` — BIP39, X25519 keypairs, sealed envelopes.
- `src/epoch.rs` — HKDF derivation utilities and rotation helpers.
- `src/crypto.rs` — AES-256-GCM implementation using `ring`.
- `src/merkle.rs` — incremental Merkle tree builder.
- `src/attestation.rs` — payload struct + ed25519 signer.
- `bindings/wasm/` — wasm-bindgen glue.
- `bindings/python/` — PyO3 module when `python` feature enabled.

## Features

| Feature flag | Description |
|--------------|-------------|
| `wasm` | Enable wasm-bindgen exports. |
| `python` | Enable PyO3 bindings. |
| `zeroize` | Zeroize secrets on drop. |
| `serde` | Derive serde traits for structs. |

## Build & Test Commands

- `cargo test` — unit tests and vector validation.
- `cargo fmt && cargo clippy -- -D warnings` — linting.
- `wasm-pack build --target nodejs` — WASM package.
- `maturin develop` (with `python` feature) — build Python wheel locally.

## Inputs/Outputs

- `EncryptionRequest` -> `EncryptionResponse` (ciphertext, nonce, wrapped DEK, merkle commitment).
- `AttestationRequest` -> `AttestationEnvelope` (content hash, epoch, serve key, signature).
- `KeywordRequest` -> `KeywordTokens` (Vec<String> weighted).

## Dependency Matrix

- `ring` — crypto primitives (HKDF, ed25519, AES-GCM).
- `rand_core` — RNG seed.
- `sha2` — SHA-256 HMAC for keyword tokens.
- `hkdf` — HKDF convenience wrapper (optional).
- `serde_json` — serialisation of envelopes.

## CI Pipeline

- `cargo test` + vector verification.
- `wasm-pack` build + size check.
- `cargo audit` for vulnerability scanning.
- Publish to crates.io on tag push using GitHub Actions.

## Documentation

- Rustdoc hosted at `docs.rs/wevibe-sdk`.
- Example notebooks under `examples/` show contribution + retrieval flows.

## Sprint 24 Updates

- Added structures for capturing moderator provenance emitted by the Accept / Deny / Report flow so client apps can align decryption with hub readiness.
- Updated bindings to surface `required_approvals` metadata when available from hub responses.
- Documented helper usage for moderator approvals following fee grant trial allowance issuance.
