## Status

- Alpha-stage Rust workspace with implemented crypto core (`wevibe-sdk-core`) and WASM bindings (`wevibe-sdk-wasm`).
- Generated WASM outputs are available in `pkg/` and `pkg-nodejs/` for client consumption.
- Python binding support is present for non-JavaScript integration surfaces.

## Near-term

- Implement a passkey-first shared client-key scheme generated at first run:
  - Ed25519 key material for hub authentication.
  - secp256k1 key material for PRE identity use.
- Continue hardening client-facing APIs while preserving one cryptographic foundation across MCP and dashboard clients.

## Future

- Introduce BIP-32-based PRE identity separation.
- Coordinate SDK interfaces with embedding-model evolution so clients can migrate consistently as model assumptions change.

## Design references

- WeVibe docs: https://github.com/WeVibe-Network/wevibe-docs
