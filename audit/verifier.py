"""Standalone chain verification used by the CLI."""
from __future__ import annotations

from audit.models import VerifyResult
from audit.storage import SegmentStore


def verify_store(store: SegmentStore) -> VerifyResult:
    return store.verify()
