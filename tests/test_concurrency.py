"""Concurrent writers: true order preserved, no fork, no gap, no dup."""
from __future__ import annotations

import threading

from audit.storage import StorageError

from conftest import make_event, make_service


def test_concurrent_writes_preserve_chain_order(tmp_dir):
    n_threads = 8
    per_thread = 25
    service = make_service(tmp_dir)
    errors: list[Exception] = []
    barrier = threading.Barrier(n_threads)

    def worker(tid: int) -> None:
        try:
            barrier.wait()
            for i in range(per_thread):
                service.record(
                    make_event(
                        action=f"t{tid}-{i}",
                        key=f"t{tid}-{i}",
                        correlation_id=f"c{tid}-{i}",
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(tid,))
               for tid in range(n_threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    total = n_threads * per_thread
    records = service.query()
    seqs = [r.seq for r in records]
    print(f"[input] {n_threads} threads x {per_thread} events, "
          f"errors={len(errors)}")
    assert not errors, errors
    assert seqs == list(range(1, total + 1)), "sequence gap/dup under concurrency"
    # Hash linkage must be unbroken in on-disk physical order.
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.record_hash
    result = service.verify()
    print(f"[judgement] verify ok={result.ok} total={result.total} "
          f"(expected {total})")
    assert result.ok and result.total == total
    # Idempotency under concurrent duplicate submissions collapses to one.
    key = "concurrent-dup"
    barrier2 = threading.Barrier(n_threads)
    def dup_worker() -> None:
        barrier2.wait()
        service.record(make_event(key=key))
    dup_threads = [threading.Thread(target=dup_worker) for _ in range(n_threads)]
    for thread in dup_threads:
        thread.start()
    for thread in dup_threads:
        thread.join()
    after = service.query()
    same_key = [r for r in after if r.idempotency_key == key]
    print(f"[input] {n_threads} concurrent duplicate submissions -> "
          f"{len(same_key)} record(s)")
    assert len(same_key) == 1
    assert service.verify().ok
