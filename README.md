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

Rust and WASM cryptography SDK for WeVibe clients.

## Overview

`wevibe-sdk` is a Rust workspace that provides the shared cryptographic foundation used across WeVibe client applications.

The workspace currently includes:

- `crates/wevibe-sdk-core`: core crypto, identity, types, and error handling.
- `crates/wevibe-sdk-wasm`: WebAssembly bindings for browser and JavaScript clients.

This project is in active alpha. The core cryptographic functionality is implemented and used, but APIs may still evolve as the network hardens and client integration expands.

## Role in the WeVibe Network

This SDK is the common crypto layer for the client stack, including MCP and dashboard integrations.

Current primitives include:

- keypair and identity foundations
- AES-256-GCM symmetric encryption
- x25519 and ed25519 key operations
- HKDF-based key derivation
- BIP39 recovery phrase support
- sealed-envelope key distribution patterns

The dashboard consumes the generated WASM bundle from this repository (`pkg/` and `pkg-nodejs/`).

## Getting started

### Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

### Generate WASM artifacts

This repository already includes generated outputs in `pkg/` and `pkg-nodejs/`.
To regenerate bindings, use `wasm-pack` from the workspace as needed.

## Testing

Run the full workspace test suite:

```bash
cargo test
```

## Configuration

No runtime service configuration is required for the core Rust crates.
For WASM consumers, use the generated package targets in `pkg/` (web) and `pkg-nodejs/` (Node.js).

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for current status and upcoming work.

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
