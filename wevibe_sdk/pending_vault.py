"""wevibe-sdk pending_vault — local storage for pending submission DEKs.

When a contributor submits a memory, the Hub receives only the
encrypted ciphertext. The contributor keeps a local copy of the DEK
(encrypted under the device key) so they can view their own pending
submissions without a network round-trip.

This module is the sole owner of ~/.wevibe/pending_vault/.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

VAULT_DIR = Path.home() / ".wevibe" / "pending_vault"


@dataclass
class PendingEntry:
    submission_hash: str
    org_id: str
    epoch_id: int
    encrypted_dek: str   # base64 — DEK encrypted under device key
    task_preview: str    # first 100 chars of task_description, plaintext for display
    created_at: str
    status: str          # "pending" | "approved" | "denied"


def store_pending_dek(
    submission_hash: str,
    org_id: str,
    epoch_id: int,
    dek: bytes,
    task_preview: str,
) -> None:
    """Encrypt and store a pending submission DEK.

    TODO: implement
        from wevibe_sdk.crypto import encrypt_symmetric
        from wevibe_sdk.key_store import get_device_key
        import base64

        device_key = get_device_key()
        encrypted_dek = encrypt_symmetric(dek, device_key)
        entry = PendingEntry(
            submission_hash=submission_hash,
            org_id=org_id,
            epoch_id=epoch_id,
            encrypted_dek=base64.b64encode(encrypted_dek).decode(),
            task_preview=task_preview[:100],
            created_at=datetime.now(timezone.utc).isoformat(),
            status="pending",
        )
        _write_entry(entry)
    """
    raise NotImplementedError("TODO: store_pending_dek")


def load_pending_dek(submission_hash: str) -> bytes | None:
    """Decrypt and return a pending submission DEK. Returns None if not found.

    TODO: implement (inverse of store_pending_dek)
    """
    raise NotImplementedError("TODO: load_pending_dek")


def list_pending(org_id: str | None = None) -> list[PendingEntry]:
    """List pending vault entries, optionally filtered by org."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for f in VAULT_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            entry = PendingEntry(**data)
            if org_id is None or entry.org_id == org_id:
                entries.append(entry)
        except Exception:
            continue
    return sorted(entries, key=lambda e: e.created_at, reverse=True)


def update_status(submission_hash: str, status: str) -> None:
    """Update the status of a pending entry (called on moderation outcome)."""
    path = VAULT_DIR / f"{submission_hash}.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text())
        data["status"] = status
        path.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _write_entry(entry: PendingEntry) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    path = VAULT_DIR / f"{entry.submission_hash}.json"
    path.write_text(json.dumps(asdict(entry), indent=2))
