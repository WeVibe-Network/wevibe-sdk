# wevibe-sdk Whitepaper

Version: 1.0 · Sprint 24

## Overview

wevibe-sdk provides the cryptographic primitives and state machinery required for WeVibe Network’s end-to-end encrypted memory flow. It is the single source of truth for key derivation, envelope sealing, ciphertext chunking, and attestation signing across all client surfaces.

## Core Responsibilities

1. **Key hierarchy** — derives epoch keys from `K_master` using HKDF-SHA256, matching wevibe-chain semantics.
2. **Envelope sealing** — wraps DEKs to moderation and retrieval keys with X25519 + AES-256-GCM.
3. **Ciphertext streaming** — chunked encryption with Merkle commitments for large payloads.
4. **Keyword hashing** — deterministic HMAC tokens for local retrieval indexes.
5. **Attestation signing** — ed25519 signatures for serve attestation batches.

## API Structure

- `sdk::identity` — BIP39 recovery, moderation keypairs, envelope sealing helpers.
- `sdk::epoch` — HKDF derivation, epoch rotation, contest stake utilities.
- `sdk::crypto` — AES-GCM encryption/decryption, Merkle commitment builder.
- `sdk::keywords` — tokenisation and weighting helpers.
- `sdk::attestation` — serve attestation envelope builder.
- `sdk::wasm` — wasm-bindgen exports for Node/Browser consumers.

## Security Considerations

- All symmetric operations use AEAD with random 96-bit nonces; nonces stored alongside ciphertext.
- HKDF info strings namespaced (`"wevibe-enc-"`, `"wevibe-audit-"` etc.) to avoid cross-protocol reuse.
- Optional zeroization via `zeroize` crate for secret material.
- Deterministic test vectors under `tests/vectors/` to validate compatibility with wevibe-chain keepers.

## Build Targets

- `cargo build --release` → native Rust library.
- `wasm-pack build` → WASM + JS glue for wevibe-mcp.
- `pyo3` feature flag → Python bindings for moderation scripts.

## Future Enhancements

- Hardware-backed key storage adapters (YubiKey, Nitrokey).
- Multi-signer contest resolution helpers.
- Batch-friendly Merkle proof compression for mobile environments.

## Sprint 24 Updates

- Documented metadata emitted when the OpenCode plugin records Accept / Deny / Report decisions so client applications can align decryption flows with hub readiness state.
- Clarified how SDK helpers surface moderator provenance for approvals executed after hub quorum is met or leader override is applied.
- Added references to fee grant-aware signing flows that support moderator approvals backed by `MsgGrantTrialAllowance`.
