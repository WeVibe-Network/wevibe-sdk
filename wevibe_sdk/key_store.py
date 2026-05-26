"""wevibe-sdk key_store — OS keychain abstraction for local secret storage.

Wraps the `keyring` library to provide a consistent interface across
macOS Keychain, Windows DPAPI / Credential Manager, and Linux Secret Service.

All secrets stored here are local-only. Nothing in this module makes
network calls or writes to disk directly.

Dependencies:
    pip install keyring>=24.0
"""

from __future__ import annotations

import json

SERVICE_PREFIX = "wevibe-network"


def get_device_key() -> bytes:
    """Return the 32-byte AES device key for local buffer encryption.

    Generated on first call, stored in OS keychain.
    This key encrypts session buffers and the pending vault on disk.
    """
    raise NotImplementedError("Device key persistence is not implemented yet")


def store_key_envelope(org_id: str, envelope_type: str, blob: bytes) -> None:
    """Store a sealed key envelope for an org.

    envelope_type: "enc_bundle" | "search_bundle" | "audit_bundle" | "mod_priv"
    """
    raise NotImplementedError("Key envelope persistence is not implemented yet")


def load_key_envelope(org_id: str, envelope_type: str) -> bytes | None:
    """Load a sealed key envelope. Return None when no envelope exists."""
    raise NotImplementedError("Key envelope loading is not implemented yet")


def list_org_ids() -> list[str]:
    """Return all org IDs for which we have stored key envelopes.

    The keyring API cannot list accounts by prefix consistently across backends,
    so org IDs are tracked in a local index at ~/.wevibe/orgs.json.
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
