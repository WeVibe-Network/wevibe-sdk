"""wevibe-sdk identity — persistent identity management.

Replaces the old wevibe_mcp/wallet.py. Manages Ed25519 + X25519 keypairs,
stored in the OS keychain via key_store. Exposes a simple interface:
load the identity, sign data, get the public key string.
"""

from __future__ import annotations

from pathlib import Path
from wevibe_sdk.crypto import Identity, generate_identity

# TODO: import from key_store once implemented
# from wevibe_sdk.key_store import store_identity, load_identity


IDENTITY_SERVICE = "wevibe-network"
IDENTITY_ACCOUNT = "identity-v1"


def get_or_create_identity() -> Identity:
    """Load identity from keychain, or generate and store a new one.

    TODO: implement
        existing = load_identity(IDENTITY_SERVICE, IDENTITY_ACCOUNT)
        if existing:
            return existing
        identity = generate_identity()
        store_identity(IDENTITY_SERVICE, IDENTITY_ACCOUNT, identity)
        return identity

    Migration path from old wallet.json:
        wallet_path = Path.home() / ".wevibe" / "wallet.json"
        if wallet_path.exists():
            # read old UUID wallet, derive deterministic identity from it
            # (or just generate a fresh identity — old wallet was not cryptographic)
            wallet_path.rename(wallet_path.with_suffix(".json.migrated"))
    """
    raise NotImplementedError("TODO: get_or_create_identity")


def get_pubkey_hex() -> str:
    """Return the hex-encoded Ed25519 public key for this device."""
    return get_or_create_identity().pubkey_hex


def sign_bytes(data: bytes) -> bytes:
    """Sign data with this device's Ed25519 private key."""
    from wevibe_sdk.crypto import sign
    identity = get_or_create_identity()
    return sign(identity.ed25519_privkey_bytes, data)
