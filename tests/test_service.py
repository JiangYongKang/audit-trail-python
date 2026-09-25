"""审计服务测试：并发写入、写失败重试、幂等去重、重启恢复。"""
from __future__ import annotations

import builtins
import threading

import pytest

import audit.store as store_mod
from audit.config import AuditConfig
from audit.models import AuditEvent, Outcome
from audit.service import AuditService


def _event(actor: str = "alice", key: str | None = None, ts: float = 0.0) -> AuditEvent:
    return AuditEvent(actor=actor, action="read", target="doc",
                      outcome=Outcome.SUCCESS, correlation_id="corr-1",
                      idempotency_key=key, occurred_at=ts)


def test_concurrent_writes_keep_order_and_chain(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    n_threads, n_each = 8, 25

    def worker(tid: int) -> None:
        for i in range(n_each):
            svc.record(_event(actor=f"u{tid}", key=f"k{tid}-{i}"))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = svc.records()
    seqs = [r.seq for r in records]
    result = svc.verify()
    print(f"[输入] {n_threads} 线程 × {n_each} 条并发写入 | "
          f"[判定] 总数={len(records)} 序号连续={seqs == list(range(1, n_threads * n_each + 1))} "
          f"链校验={result.ok}")
    assert len(records) == n_threads * n_each
    assert seqs == list(range(1, n_threads * n_each + 1))  # 无分叉、无断链
    assert result.ok


def test_duplicate_submission_deduped(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    r1 = svc.record(_event(key="same-key"))
    r2 = svc.record(_event(key="same-key"))
    total = len(svc.records())
    print(f"[输入] 同一 idempotency_key 提交两次 | "
          f"[判定] 两次返回 seq={r1.seq}/{r2.seq} 落盘总数={total}")
    assert r1.seq == r2.seq
    assert total == 1


def test_write_failure_retried_then_succeeds(tmp_path, monkeypatch):
    """写入调用本身前 2 次失败、第 3 次成功：重试后事件不丢。"""
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path), write_retries=3,
                                   retry_backoff_s=0.001))
    calls = {"n": 0}
    real_open = builtins.open

    def flaky_open(file, mode="r", *args, **kwargs):
        if "a" in mode:
            calls["n"] += 1
            if calls["n"] <= 2:
                raise OSError("模拟磁盘瞬时故障")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(store_mod, "open", flaky_open, raising=False)
    rec = svc.record(_event())
    print(f"[输入] 追加写前 2 次抛 OSError | [判定] 重试后落盘 seq={rec.seq} 写尝试={calls['n']} "
          f"链校验={svc.verify().ok}")
    assert rec.seq == 1
    assert calls["n"] == 3
    assert svc.verify().ok


def test_write_failure_not_silently_swallowed(tmp_path, monkeypatch):
    """写入持续失败：必须抛异常（不静默吞掉），且状态不前进、事件可重试。"""
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path), write_retries=2,
                                   retry_backoff_s=0.001))

    def failing_open(file, mode="r", *args, **kwargs):
        if "a" in mode:
            raise OSError("模拟磁盘持续故障")
        return builtins.open(file, mode, *args, **kwargs)

    monkeypatch.setattr(store_mod, "open", failing_open, raising=False)
    with pytest.raises(OSError) as exc_info:
        svc.record(_event())
    print(f"[输入] 追加写持续故障 | [判定] 向上抛出异常={exc_info.value}")

    monkeypatch.undo()
    # 事件未丢：故障恢复后同一事件可重试，且序号不回溯（仍为 1）
    rec = svc.record(_event())
    print(f"[输入] 故障恢复后重试同一事件 | [判定] seq={rec.seq} 链校验={svc.verify().ok}")
    assert rec.seq == 1
    assert svc.verify().ok


def test_fsync_failure_does_not_duplicate_record(tmp_path, monkeypatch):
    """fsync 阶段失败（内容已写盘）：重试必须幂等，不产生重复行。"""
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path), write_retries=3,
                                   retry_backoff_s=0.001))
    calls = {"n": 0}
    real_fsync = store_mod.os.fsync

    def flaky_fsync(fd: int) -> None:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise OSError("模拟 fsync 瞬时故障")
        real_fsync(fd)

    monkeypatch.setattr(store_mod.os, "fsync", flaky_fsync)
    rec = svc.record(_event())
    total = len(svc.records())
    print(f"[输入] fsync 前 2 次失败（内容已写盘） | "
          f"[判定] seq={rec.seq} 落盘总数={total} 链校验={svc.verify().ok}")
    assert rec.seq == 1
    assert total == 1  # 不得出现重复行
    assert svc.verify().ok


def test_restart_keeps_chain_continuous(tmp_path):
    cfg = AuditConfig(storage_dir=str(tmp_path))
    svc1 = AuditService(cfg)
    for i in range(3):
        svc1.record(_event(key=f"k{i}"))

    svc2 = AuditService(cfg)  # 模拟进程重启
    rec = svc2.record(_event(key="k3"))
    dup = svc2.record(_event(key="k0"))  # 重启前已提交的键
    result = svc2.verify()
    print(f"[输入] 写 3 条后重启再写 1 条 + 重复提交旧键 | "
          f"[判定] 新记录 seq={rec.seq} 重复键返回 seq={dup.seq} 链校验={result.ok}")
    assert rec.seq == 4
    assert dup.seq == 1
    assert result.ok
    assert len(svc2.records()) == 4
