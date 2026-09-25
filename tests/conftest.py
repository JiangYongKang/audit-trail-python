"""Shared fixtures and helpers for the audit-trail test suite."""
from __future__ import annotations

import os
import tempfile

import pytest

from audit.models import AuditEvent, Outcome, Sensitivity
from audit.retention import RetentionPolicy
from audit.service import AuditService
from audit.storage import SegmentStore, Spool

# Tiny retention windows (seconds) so purge boundaries are easy to hit.
TEST_RETENTION = {
    Sensitivity.PUBLIC: 100.0,
    Sensitivity.INTERNAL: 1_000.0,
    Sensitivity.SENSITIVE: 10_000.0,
    Sensitivity.REGULATED: 100_000.0,
}


@pytest.fixture
def tmp_dir() -> str:
    directory = tempfile.mkdtemp(prefix="audit-test-")
    yield directory


def make_service(
    directory: str,
    *,
    rotate_bytes: int = 1 << 20,
    retention: RetentionPolicy | None = None,
    fault_hook=None,
    max_append_retries: int = 3,
) -> AuditService:
    store = SegmentStore(os.path.join(directory, "store"), rotate_bytes=rotate_bytes)
    if fault_hook is not None:
        store.fault_hook = fault_hook
    spool = Spool(os.path.join(directory, "spool.jsonl"))
    return AuditService(
        store,
        spool,
        retention=retention or RetentionPolicy(TEST_RETENTION),
        max_append_retries=max_append_retries,
        retry_backoff=0,
    )


def make_event(
    action: str = "act",
    *,
    operator: str = "alice",
    obj: str = "obj-1",
    outcome: Outcome = Outcome.SUCCESS,
    level: Sensitivity = Sensitivity.INTERNAL,
    key: str | None = None,
    correlation_id: str = "cid-1",
    reason: str | None = None,
    fields=None,
    ts: float | None = None,
    entrypoint: str = "http",
) -> AuditEvent:
    return AuditEvent(
        operator=operator,
        action=action,
        object=obj,
        outcome=outcome,
        sensitivity=level,
        idempotency_key=key,
        correlation_id=correlation_id,
        reason=reason,
        fields=fields or {},
        entrypoint=entrypoint,
        occurred_at=ts,
    )
