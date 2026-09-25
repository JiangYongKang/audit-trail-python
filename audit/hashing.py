"""Canonical serialization and hash-chain primitives.

Every record hash is::

    sha256(canonical_json({"prev": <prev_hash>, "body": <record body>}))

so the hash both seals the record content and binds it to its predecessor.
The encoding is canonical (sorted keys, fixed separators, no whitespace) so
that the same record always yields the same digest across processes and
restarts.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(data: Any) -> bytes:
    """Deterministic JSON encoding (sorted keys, stable separators)."""
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_digest(prev_hash: str, body: dict[str, Any]) -> str:
    """Hash over the previous record hash and the canonical record body."""
    return sha256_hex(canonical_json({"prev": prev_hash, "body": body}))
