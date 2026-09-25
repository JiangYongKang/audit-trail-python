"""Retention boundaries, purge anchors and purge-safe reads."""
from __future__ import annotations

import json
import os
import threading

from audit.models import Outcome, Sensitivity
from audit.service import AuditService
from audit.storage import SegmentStore, Spool

from conftest import make_event, make_service

NOW = 1_000_000.0  # fixed "now" so boundaries are exact


def _populate_mixed_ages(service: AuditService) -> None:
    # 4 public records (retention 100s) at distinct ages, one per segment.
    for i, ts in enumerate((NOW - 200, NOW - 150, NOW - 101, NOW - 100), 1):
        service.record(make_event(action=f"pub-{i}", level=Sensitivity.PUBLIC, ts=ts))
    # 2 internal records (retention 1000s)
    service.record(make_event(action="int-1", level=Sensitivity.INTERNAL, ts=NOW - 500))
    service.record(make_event(action="int-2", level=Sensitivity.INTERNAL, ts=NOW - 50))


def test_boundary_exactly_at_cutoff_is_kept(tmp_dir):
    service = make_service(tmp_dir, rotate_bytes=1)
    _populate_mixed_ages(service)
    report = service.purge_expired(now=NOW)
    # pub-1..pub-3 are strictly older than cutoff (ts < NOW-100);
    # pub-4 at exactly NOW-100 is NOT expired and stops the prefix.
    print(f"[input] boundary ts==cutoff present -> removed_segments="
          f"{report.removed_segments} anchor_seq={report.anchor_seq}")
    assert report.removed_records == 3
    surviving = service.query()
    assert [r.action for r in surviving[:1]][0] == "pub-4"
    result = service.verify()
    print(f"[judgement] verify after purge ok={result.ok} "
          f"head_seq={result.head_seq} last_seq={result.last_seq}")
    assert result.ok


def test_purge_is_noop_when_nothing_expired(tmp_dir):
    service = make_service(tmp_dir, rotate_bytes=1)
    service.record(make_event(level=Sensitivity.REGULATED, ts=NOW))
    report = service.purge_expired(now=NOW)
    print(f"[input] fresh regulated record -> removed={report.removed_records}")
    assert report.removed_segments == 0 and report.anchor_seq is None
    assert service.verify().ok


def test_verification_stays_continuous_across_restart_and_repurge(tmp_dir):
    service = make_service(tmp_dir, rotate_bytes=1)
    _populate_mixed_ages(service)
    service.purge_expired(now=NOW)
    assert service.verify().ok

    restarted = AuditService(
        SegmentStore(os.path.join(tmp_dir, "store"), rotate_bytes=1),
        Spool(os.path.join(tmp_dir, "spool2.jsonl")),
        retention=service.retention,
    )
    result = restarted.verify()
    print(f"[judgement after restart] ok={result.ok} head_seq={result.head_seq}")
    assert result.ok
    # everything internal becomes old -> second purge, chain must stay valid
    report = restarted.purge_expired(now=NOW + 100_000)
    print(f"[input] second purge -> removed={report.removed_records} "
          f"anchor={report.anchor_seq}")
    assert restarted.verify().ok


def test_queries_during_purge_see_no_partial_state(tmp_dir):
    service = make_service(tmp_dir, rotate_bytes=1)
    _populate_mixed_ages(service)
    stop = threading.Event()
    violations: list[str] = []
    seen_counts: list[int] = []

    def reader() -> None:
        while not stop.is_set():
            records = service.query()
            seen_counts.append(len(records))
            result = service.verify()
            # A concurrent reader must observe either the pre-purge or the
            # post-anchor state, never a mid-deletion broken chain.
            if not result.ok:
                violations.append(
                    f"verify failed during purge: {result.reason}@{result.first_bad_seq}"
                )

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()
    for _ in range(20):
        service.purge_expired(now=NOW)
    stop.set()
    for thread in threads:
        thread.join()
    print(f"[input] readers during purge: observations={len(seen_counts)} "
          f"violations={len(violations)}")
    assert not violations, violations
    assert service.verify().ok


def test_masked_values_never_persisted(tmp_dir):
    service = make_service(tmp_dir)
    service.record(make_event(fields={"password": "PLAINTEXT-SECRET",
                                      "email": "root@corp.example"}))
    service.purge_expired(now=NOW)  # ensures no raw values in purge payloads
    for root, _dirs, files in os.walk(tmp_dir):
        for name in files:
            content = open(os.path.join(root, name), "rb").read()
            assert b"PLAINTEXT-SECRET" not in content, name
    print("[judgement] raw secret absent from every persisted byte")
