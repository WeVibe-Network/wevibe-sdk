"""Persistent device identity management."""

from __future__ import annotations

from wevibe_sdk.crypto import Identity


IDENTITY_SERVICE = "wevibe-network"
IDENTITY_ACCOUNT = "identity-v1"


def get_or_create_identity() -> Identity:
    """Load identity from keychain, or create it if missing."""
    raise NotImplementedError("Identity keychain persistence is not implemented yet")


def get_pubkey_hex() -> str:
    """Return the hex-encoded Ed25519 public key for this device."""
    return get_or_create_identity().pubkey_hex


def sign_bytes(data: bytes) -> bytes:
    """Sign data with this device's Ed25519 private key."""
    from wevibe_sdk.crypto import sign
    identity = get_or_create_identity()
    return sign(identity.ed25519_privkey_bytes, data)
