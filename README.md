# wevibe-sdk

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

The dashboard consumes the generated WASM bundle from this repository (`pkg/` and `pkg-nodejs/`). A Python binding is also present for non-JavaScript client surfaces.

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
