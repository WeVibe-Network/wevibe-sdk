"""wevibe-sdk key_store — OS keychain abstraction for local secret storage.

Wraps the `keyring` library to provide a consistent interface across
macOS Keychain, Windows DPAPI / Credential Manager, and Linux Secret Service.

All secrets stored here are local-only. Nothing in this module makes
network calls or writes to disk directly.

Dependencies:
    pip install keyring>=24.0
"""

from __future__ import annotations

import base64
import json
import os

# TODO: import keyring
# import keyring
# from keyring.errors import NoKeyringError

SERVICE_PREFIX = "wevibe-network"


def get_device_key() -> bytes:
    """Return the 32-byte AES device key for local buffer encryption.

    Generated on first call, stored in OS keychain.
    This key encrypts session buffers and the pending vault on disk.

    TODO: implement
        import keyring
        stored = keyring.get_password(SERVICE_PREFIX, "device-key-v1")
        if stored:
            return base64.b64decode(stored)
        key = os.urandom(32)
        keyring.set_password(SERVICE_PREFIX, "device-key-v1", base64.b64encode(key).decode())
        return key
    """
    raise NotImplementedError("TODO: get_device_key")


def store_key_envelope(org_id: str, envelope_type: str, blob: bytes) -> None:
    """Store a sealed key envelope for an org.

    envelope_type: "enc_bundle" | "search_bundle" | "audit_bundle" | "mod_priv"

    TODO: implement using keyring
        account = f"org-{org_id}-{envelope_type}"
        keyring.set_password(SERVICE_PREFIX, account, base64.b64encode(blob).decode())
    """
    raise NotImplementedError("TODO: store_key_envelope")


def load_key_envelope(org_id: str, envelope_type: str) -> bytes | None:
    """Load a sealed key envelope. Returns None if not found.

    TODO: implement
    """
    raise NotImplementedError("TODO: load_key_envelope")


def list_org_ids() -> list[str]:
    """Return all org IDs for which we have stored key envelopes.

    TODO: implement — keyring does not natively list by prefix on all backends.
    Maintain a separate plaintext index file at ~/.wevibe/orgs.json
    that lists joined org IDs. The sensitive material (keys) stays in keychain;
    the index (just org IDs, not keys) can be a plain JSON file.
    """
    index_path = _orgs_index_path()
    if not index_path.exists():
        return []
    try:
        return json.loads(index_path.read_text()).get("org_ids", [])
    except Exception:
        return []


def _orgs_index_path():
    from pathlib import Path
    p = Path.home() / ".wevibe" / "orgs.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
