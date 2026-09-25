"""Write failure: retry, durable spool, replay, restart-recovery."""
from __future__ import annotations

import os

import pytest

from audit.retention import RetentionPolicy
from audit.service import AuditService
from audit.storage import SegmentStore, Spool, StorageError

from conftest import make_event, make_service


def test_temporary_failure_retried_then_succeeds(tmp_dir):
    calls = {"n": 0}

    def fail_twice():
        calls["n"] += 1
        if calls["n"] <= 2:
            raise OSError("transient io error")

    service = make_service(tmp_dir, fault_hook=fail_twice, max_append_retries=5)
    record = service.record(make_event(action="retry-me"))
    print(f"[input] fault on attempts 1-2 -> succeeded on {calls['n']}, "
          f"seq={record.seq}")
    assert calls["n"] == 3
    assert service.verify().ok


def test_persistent_failure_spools_and_raises(tmp_dir):
    def always_fail():
        raise OSError("disk offline")

    service = make_service(tmp_dir, fault_hook=always_fail, max_append_retries=3)
    with pytest.raises(StorageError) as excinfo:
        service.record(make_event(action="must-not-be-lost"))
    print(f"[input] 3 failing attempts -> raised: {excinfo.value}")
    assert "exhausted retries" in str(excinfo.value)
    assert len(service.spool) == 1, "event must be durably spooled, not dropped"
    # The raw spool content must already be masked.
    spool_text = open(os.path.join(tmp_dir, "spool.jsonl"), "rb").read().decode()
    print(f"[spool] {spool_text.strip()[:160]}...")
    assert "super-secret" not in spool_text


def test_spool_replayed_after_recovery(tmp_dir):
    def always_fail():
        raise OSError("disk offline")

    service = make_service(tmp_dir, fault_hook=always_fail)
    for i in range(3):
        with pytest.raises(StorageError):
            service.record(make_event(action=f"deferred-{i}",
                                      fields={"password": "super-secret"}))
    assert len(service.spool) == 3

    service.store.fault_hook = None
    replayed = service.flush_spool()
    print(f"[input] 3 spooled events after outage -> replayed={replayed}")
    assert replayed == 3
    assert len(service.spool) == 0
    records = service.query()
    assert [r.action for r in records] == ["deferred-0", "deferred-1", "deferred-2"]
    assert all(r.fields["password"] == "***" for r in records)
    assert service.verify().ok


def test_spool_survives_process_restart(tmp_dir):
    def always_fail():
        raise OSError("disk offline")

    service = make_service(tmp_dir, fault_hook=always_fail)
    with pytest.raises(StorageError):
        service.record(make_event(action="survives-restart"))
    assert len(service.spool) == 1

    # Simulate a fresh process reopening the same on-disk state.
    restarted = AuditService(
        SegmentStore(os.path.join(tmp_dir, "store")),
        Spool(os.path.join(tmp_dir, "spool.jsonl")),
        retention=RetentionPolicy({}),
    )
    replayed = restarted.flush_spool()
    print(f"[input] spooled before restart -> replayed after restart="
          f"{replayed}")
    assert replayed == 1
    assert restarted.verify().ok
