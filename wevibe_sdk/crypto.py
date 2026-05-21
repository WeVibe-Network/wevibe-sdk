"""wevibe-sdk crypto — all cryptographic primitives for WeVibe Network clients.

All operations are local. Nothing in this module makes network calls.
This module is the only place in wevibe_mcp that touches raw cryptographic
primitives. All other modules call through this interface.

Dependencies:
    pip install cryptography>=42.0
"""

from __future__ import annotations

import os
import hmac
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class Identity:
    """An WeVibe Network participant identity."""

    ed25519_privkey_bytes: bytes
    ed25519_pubkey_bytes: bytes
    x25519_privkey_bytes: bytes
    x25519_pubkey_bytes: bytes

    @property
    def pubkey_hex(self) -> str:
        """Hex-encoded Ed25519 public key — used as the participant identifier."""
        return self.ed25519_pubkey_bytes.hex()


@dataclass
class EpochKeys:
    """Derived symmetric keys for a single epoch."""

    epoch: int
    enc_key: bytes
    search_key: bytes
    audit_key: bytes


def generate_identity() -> Identity:
    """Generate a new WeVibe Network identity (Ed25519 + X25519 keypairs)."""
    ed_key = Ed25519PrivateKey.generate()
    x_key = X25519PrivateKey.generate()
    return Identity(
        ed25519_privkey_bytes=ed_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        ed25519_pubkey_bytes=ed_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        x25519_privkey_bytes=x_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        x25519_pubkey_bytes=x_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
    )


def sign(privkey_bytes: bytes, data: bytes) -> bytes:
    """Sign data with Ed25519 private key."""
    key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    return key.sign(data)


def verify(pubkey_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on failure."""
    key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def seal_to_pubkey(plaintext: bytes, recipient_x25519_pubkey_bytes: bytes) -> bytes:
    """Encrypt plaintext to a recipient's X25519 public key.

    Uses X25519 ECDH to derive a shared secret, then AES-256-GCM.
    Output format: ephemeral_pubkey (32 bytes) || nonce (12 bytes) || ciphertext
    """
    ephemeral_privkey = X25519PrivateKey.generate()
    ephemeral_pubkey_bytes = ephemeral_privkey.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    recipient_pubkey = X25519PublicKey.from_public_bytes(recipient_x25519_pubkey_bytes)
    shared_secret = ephemeral_privkey.exchange(recipient_pubkey)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"wevibe-envelope-v1",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return ephemeral_pubkey_bytes + nonce + ciphertext


def open_envelope(ciphertext_blob: bytes, our_x25519_privkey_bytes: bytes) -> bytes:
    """Decrypt an envelope sealed with seal_to_pubkey."""
    if len(ciphertext_blob) < 32 + 12 + 16:
        raise ValueError(
            f"Envelope too short: {len(ciphertext_blob)} bytes "
            f"(minimum 60: 32 ephemeral pubkey + 12 nonce + 16 GCM tag)"
        )
    ephemeral_pubkey_bytes = ciphertext_blob[:32]
    nonce = ciphertext_blob[32:44]
    ciphertext_with_tag = ciphertext_blob[44:]

    our_privkey = X25519PrivateKey.from_private_bytes(our_x25519_privkey_bytes)
    ephemeral_pubkey = X25519PublicKey.from_public_bytes(ephemeral_pubkey_bytes)
    shared_secret = our_privkey.exchange(ephemeral_pubkey)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"wevibe-envelope-v1",
    ).derive(shared_secret)
    return AESGCM(aes_key).decrypt(nonce, ciphertext_with_tag, None)


def encrypt_symmetric(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt with a random nonce. Output: nonce (12 bytes) || ciphertext || tag (16 bytes)."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_symmetric(blob: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt. Input format matches encrypt_symmetric output."""
    if len(blob) < 12 + 16:
        raise ValueError(f"Blob too short: {len(blob)} bytes (minimum 28: 12 nonce + 16 GCM tag)")
    nonce = blob[:12]
    ciphertext_with_tag = blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, None)


def generate_dek() -> bytes:
    """Generate a random 32-byte data encryption key."""
    return os.urandom(32)


def derive_epoch_keys(master_key: bytes, epoch: int) -> EpochKeys:
    """Derive per-epoch symmetric keys from the org master key using HKDF."""
    epoch_bytes = epoch.to_bytes(4, "big")
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"wevibe-enc-" + epoch_bytes,
    ).derive(master_key)
    search_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"wevibe-search-" + epoch_bytes,
    ).derive(master_key)
    audit_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"wevibe-audit-" + epoch_bytes,
    ).derive(master_key)
    return EpochKeys(
        epoch=epoch,
        enc_key=enc_key,
        search_key=search_key,
        audit_key=audit_key,
    )


def compute_blind_token(keyword: str, search_key: bytes) -> str:
    """Compute HMAC-SHA256 blind token for a keyword.

    The retrieval node stores and matches these — it never sees the plaintext keyword.
    """
    return hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
