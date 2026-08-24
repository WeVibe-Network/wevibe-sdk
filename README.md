<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:02100a,100:2fe07a&height=160&section=header&text=wevibe-sdk&fontColor=54f59a&fontSize=42&fontAlignY=40&desc=Rust%20and%20WASM%20cryptography%20SDK&descAlignY=64&descSize=16" alt="wevibe-sdk" width="100%" />

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
![WebAssembly](https://img.shields.io/badge/WebAssembly-654FF0?style=flat-square&logo=webassembly&logoColor=white)
[![status-alpha](https://img.shields.io/badge/status-alpha-ffc266?style=flat-square)](https://github.com/WeVibe-Network)
[![license-Apache--2.0](https://img.shields.io/badge/license-Apache--2.0-82aaff?style=flat-square)](LICENSE)
[![docs-wevibe-docs](https://img.shields.io/badge/docs-wevibe--docs-54f59a?style=flat-square)](https://github.com/WeVibe-Network/wevibe-docs)
[![%40WeVibe__Network](https://img.shields.io/badge/%40WeVibe__Network-0a0a0a?style=flat-square&logo=x&logoColor=white)](https://x.com/WeVibe_Network)

</div>

---

The shared cryptographic substrate for WeVibe clients: one Rust implementation, compiled natively for local TS/Rust tooling and to WebAssembly for the browser.

## Overview

`wevibe-sdk` is a Rust workspace that provides the single source of truth for key derivation and encryption across the WeVibe client stack — the web dashboard, which consumes the WASM build, and the local TS/Rust clients, which consume the native core. Every client derives identity keys, seals envelopes, and splits secrets through the same auditable code path; no primitive is re-implemented on any consumer side. If a format ever changes, it changes in exactly one place.

**Status: alpha.** The core is implemented and consumed by real clients today, but APIs may still evolve as the network hardens.

### Workspace layout

| Crate | Role |
|---|---|
| `crates/wevibe-sdk-core` | Native Rust core: crypto primitives, identity, secp256k1 pre-identity, types, errors |
| `crates/wevibe-sdk-wasm` | Thin `wasm-bindgen` bindings over the core (`cdylib` + `rlib`) |

## What's inside

Primitives are implemented directly in `wevibe-sdk-core`; the WASM crate exposes a 1:1 subset of them (listed in [WASM surface](#wasm-surface)).

- **Ed25519 signing** — keypair generation, sign, verify (`ed25519-dalek`)
- **X25519 key agreement** — static key generation and one-shot ephemeral–static ECDH sealing (`x25519-dalek`)
- **AES-256-GCM** — symmetric encryption with random 12-byte nonces, and envelope sealing (ephemeral X25519 → HKDF → AES-256-GCM) (`aes-gcm`)
- **HKDF-SHA256 key derivation** (`hkdf`) with versioned info strings:
  - seed → associated X25519 key, info `wevibe-x25519-v1`
  - ECDH shared secret → envelope key, info `wevibe-envelope-v1`
  - master key + epoch → `enc` / `search` / `audit` keys, infos `wevibe-enc-` / `wevibe-search-` / `wevibe-audit-` + big-endian epoch
- **HMAC-SHA256 blind search tokens** (`hmac`)
- **BIP39 mnemonics** — 32-byte master key ⇔ 24-word recovery phrase (`bip39`)
- **Shamir secret sharing** — t-of-n split/reconstruct over 32-byte secrets, hand-rolled GF(256), no external dependency
- **secp256k1 `PreIdentity`** — random or deterministic key material; 32-byte BE scalar secret, 33-byte compressed SEC1 public key (`k256`)
- **DEK generation** — fresh random 32-byte data-encryption keys

`identity.rs` wraps the keypairs in an `Identity` trait: `LocalIdentity` holds the full Ed25519 + X25519 material locally (zeroized on drop); `SolanaIdentity` is a pubkey-only view that refuses to sign locally.

### Identity model

Identity is Ed25519-first: a 32-byte Ed25519 seed is the protocol identity, and the associated X25519 encryption keypair is derived deterministically from the same seed via HKDF (`wevibe-x25519-v1`). `generate_identity_from_seed` yields the full four-key identity (Ed25519 sign/verify pair + X25519 pair) from one seed. No wallet is required to join the network.

### What this SDK is not

Proxy re-encryption (PRE/Umbral) is **not** in this crate and is not a dependency. It lives in the sibling [wevibe-umbral](https://github.com/WeVibe-Network/wevibe-umbral) crate; `wevibe-sdk`'s contribution at that boundary is byte-compatible secp256k1 key material via `PreIdentity`.

## WASM surface

`wevibe-sdk-wasm` (npm package name `wevibe-sdk-wasm`, 0.1.0) exports 15 functions:

`generate_identity` · `generate_identity_from_seed` · `sign` · `verify` · `seal_to_pubkey` · `open_envelope` · `encrypt_symmetric` · `decrypt_symmetric` · `derive_epoch_keys` · `compute_blind_token` · `generate_dek` · `master_key_to_mnemonic` · `mnemonic_to_master_key` · `splitSecret` · `reconstructSecret`

Generated build outputs are committed and consumed directly:

| Directory | Target |
|---|---|
| `pkg/` | browser |
| `pkg-nodejs/` | Node.js |

## Consumers

The crates are unpublished — nothing is pushed to crates.io or npm. All consumption is by local path or vendoring inside the WeVibe workspace:

- **wevibe-dashboard** (under `wevibe-server/`) — depends on `wevibe-sdk-wasm` via `file:./vendor/wevibe-sdk-wasm`, a vendored copy of `pkg/`
- **wevibe-mcp** and **wevibe-mcp-exp** — load `pkg-nodejs/` from a sibling checkout at runtime
- **wevibe-meta/tests** — depends on `wevibe-sdk-wasm` via `file:../../wevibe-sdk/pkg-nodejs`

## Getting started

Build the workspace:

```bash
cargo build
cargo build --release
```

Run the test suite:

```bash
cargo test
```

The suite includes cross-format vector tests checked against committed JSON fixtures under `protocol/test_vectors/` (epoch key derivation, envelope seal/open, Shamir roundtrip, mnemonic roundtrip). If you intentionally change derivation output, bless the fixtures with `REGEN_VECTORS=1 cargo test` and review the diff before committing.

Regenerating the WASM artifacts is done with `wasm-pack` against `crates/wevibe-sdk-wasm`; there is no committed build script.

## Roadmap

Near-term direction is passkey-first onboarding on top of the existing seed-based identity model described above. It is not implemented yet; nothing in this README should be read as a committed API surface beyond what the code does today.

## License

Apache-2.0 — both crates. See [LICENSE](./LICENSE).

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
