"""持续跟读测试：阻塞等待、断线重启按位置续读、顺序一致、游标失效、并发下不重不漏。"""
from __future__ import annotations

import threading
import time

import pytest

from audit.config import AuditConfig
from audit.follow import CursorExpiredError, FollowReader
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.service import AuditService

DAY = 86400.0


def _event(i: int, ts: float = 1000.0, **kw) -> AuditEvent:
    defaults = {"actor": "alice", "action": "read", "target": "doc",
                "outcome": Outcome.SUCCESS, "occurred_at": ts + i,
                "source": "http", "idempotency_key": f"k{i}"}
    defaults.update(kw)
    return AuditEvent(**defaults)


def test_blocks_until_new_record(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    svc.record(AuditEvent(actor="alice", action="read", target="doc",
                          outcome=Outcome.SUCCESS, occurred_at=2000.0,
                          source="http"))
    reader = FollowReader(svc, start_after=1, batch_limit=10)

    def produce() -> None:
        time.sleep(0.05)
        svc.record(AuditEvent(actor="alice", action="read", target="doc",
                              outcome=Outcome.SUCCESS, occurred_at=2001.0,
                              source="http"))

    threading.Thread(target=produce).start()
    t0 = time.monotonic()
    batch = reader.read_batch(timeout=2.0)
    waited = time.monotonic() - t0
    reader.close()
    print(f"[输入] 跟读等待中 50ms 后写入 1 条 | [判定] 等待 {waited:.3f}s 收到 seq={[r.seq for r in batch]}")
    assert [r.seq for r in batch] == [2]
    assert waited >= 0.04


def test_timeout_returns_empty_keeps_position(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    svc.record(_event(0))
    reader = FollowReader(svc)
    assert [r.seq for r in reader.read_batch(timeout=0.05)] == [1]
    pos = reader.position()
    empty = reader.read_batch(timeout=0.05)
    reader.close()
    print(f"[输入] 无新记录等待 50ms | [判定] 返回={empty} 游标保持={reader.position()}")
    assert empty == [] and reader.position() == pos


def test_resume_after_disconnect_no_loss_no_dup(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    for i in range(5):
        svc.record(_event(i))
    # 模拟下游：读到 seq=3 后“断线”
    r1 = FollowReader(svc)
    b1 = r1.read_batch(timeout=0.05)
    r1.close()
    pos_after_three = 3
    assert [r.seq for r in b1[:3]] == [1, 2, 3]
    # 断线期间继续产生记录
    for i in range(5, 8):
        svc.record(_event(i))
    # “重连”：拿旧位置继续
    r2 = FollowReader(svc, start_after=pos_after_three)
    b2 = r2.read_batch(timeout=0.05)
    print(f"[输入] 读到 seq=3 断线，期间写 6..8，游标 3 重连 | "
          f"[判定] 续读 seq={[r.seq for r in b2]}")
    assert [r.seq for r in b2] == [4, 5, 6, 7, 8]  # 不丢不重


def test_resume_across_service_restart(tmp_path):
    cfg = AuditConfig(storage_dir=str(tmp_path))
    svc1 = AuditService(cfg)
    for i in range(4):
        svc1.record(_event(i))
    reader = FollowReader(svc1)
    reader.read_batch(timeout=0.05)
    reader.close()
    pos = 4
    # 服务进程重启，但下游保存的游标不变
    svc2 = AuditService(cfg)
    svc2.record(_event(4))
    reader2 = FollowReader(svc2, start_after=pos)
    batch = reader2.read_batch(timeout=0.05)
    reader2.close()
    print(f"[输入] 服务重启，下游游标=4，重启后写 1 条 | [判定] seq={[r.seq for r in batch]}")
    assert [r.seq for r in batch] == [5]


def test_concurrent_follow_order_and_completeness(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    reader = FollowReader(svc, batch_limit=1)
    received: list[int] = []
    stop = threading.Event()

    def consume() -> None:
        while not stop.is_set():
            for rec in reader.read_batch(timeout=0.1):
                received.append(rec.seq)

    t = threading.Thread(target=consume)
    t.start()

    def worker(wid: int) -> None:
        for i in range(20):
            svc.record(AuditEvent(
                actor=f"u{wid}", action="read", target="doc",
                outcome=Outcome.SUCCESS, occurred_at=1000.0,
                idempotency_key=f"{wid}-{i}"))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    deadline = time.monotonic() + 2.0
    while len(received) < 80 and time.monotonic() < deadline:
        time.sleep(0.02)
    stop.set()
    t.join()
    ordered = received == sorted(received)
    unique = len(set(received)) == len(received)
    print(f"[输入] 4 线程并发写 80 条，单跟读器实时读 | "
          f"[判定] 收到={len(received)} 严格递增={ordered} 无重复={unique}")
    assert len(received) == 80
    assert ordered and unique
    assert received == list(range(1, 81))
    reader.close()


def test_cursor_into_cleaned_range_raises_on_start(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    for i in range(8):
        svc.record(AuditEvent(actor="a", action="read", target="d",
                              outcome=Outcome.SUCCESS, occurred_at=1000.0 + i,
                              idempotency_key=f"k{i}"))
    svc.cleanup(1000.0 + 30 * DAY + 4)  # 清理 seq 1..4
    with pytest.raises(CursorExpiredError) as exc:
        FollowReader(svc, start_after=3)
    print(f"[输入] 清理 seq1..4 后用游标 3 跟读 | [判定] 抛出={exc.value}")


def test_cursor_expires_during_waiting(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    t0 = 5_000.0
    for i in range(8):
        svc.record(AuditEvent(actor="a", action="read", target="d",
                              outcome=Outcome.SUCCESS, occurred_at=t0 + i,
                              idempotency_key=f"k{i}"))
    # 跟读器先把现存记录全部消费到链尾（游标=8），然后阻塞等待
    reader = FollowReader(svc)
    assert [r.seq for r in reader.read_batch(timeout=0.05)] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert reader.position() == 8

    def compact() -> None:
        time.sleep(0.05)
        # 清理把全部 8 条压缩成锚点 seq=8：正在等待的游标 8 落入清理段
        svc.cleanup(t0 + 30 * DAY + 8)

    threading.Thread(target=compact).start()
    with pytest.raises(CursorExpiredError) as exc:
        reader.read_batch(timeout=1.0)
    reader.close()
    print(f"[输入] 游标=8 阻塞等待期间清理推进到锚点 seq=8 | [判定] 抛出={exc.value}")


def test_followed_records_contain_no_raw_secrets(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    reader = FollowReader(svc)
    svc.record(AuditEvent(actor="a", action="login", target="d",
                          outcome=Outcome.SUCCESS, sensitivity=Sensitivity.HIGH,
                          details={"password": "super-secret-123",
                                   "token": "tok-abc", "ip": "9.9.9.9"}))
    batch = reader.read_batch(timeout=0.05)
    reader.close()
    text = str(batch[0].event.details)
    print(f"[输入] 跟读 HIGH 级别事件（含 password/token 原文） | "
          f"[判定] details={batch[0].event.details} 含原文={'super-secret-123' in text}")
    assert "super-secret-123" not in text
    assert "tok-abc" not in text
