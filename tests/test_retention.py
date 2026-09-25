"""保留期清理测试：分级保留、过期边界、清理后校验连续、清理期间查询一致。"""
from __future__ import annotations

import threading

from audit.config import AuditConfig
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.service import AuditService

DAY = 86400.0


def _svc(tmp_path, **kw) -> AuditService:
    return AuditService(AuditConfig(storage_dir=str(tmp_path), **kw))


def _event(ts: float, sensitivity: Sensitivity = Sensitivity.LOW,
           key: str | None = None) -> AuditEvent:
    return AuditEvent(actor="alice", action="read", target="doc",
                      outcome=Outcome.SUCCESS, correlation_id="c",
                      idempotency_key=key, sensitivity=sensitivity,
                      occurred_at=ts)


def test_per_sensitivity_retention(tmp_path):
    svc = _svc(tmp_path)
    t0 = 1_000_000.0
    svc.record(_event(ts=t0, sensitivity=Sensitivity.LOW, key="low"))       # 30 天
    svc.record(_event(ts=t0, sensitivity=Sensitivity.MEDIUM, key="med"))    # 90 天
    svc.record(_event(ts=t0, sensitivity=Sensitivity.HIGH, key="high"))     # 365 天

    # 40 天后：仅 LOW(seq=1) 过期，压缩到 seq=2 前停止（MEDIUM 未过期）
    removed = svc.cleanup(t0 + 40 * DAY)
    records = svc.records()
    print(f"[输入] 三级敏感记录 + 40 天后清理 | [判定] 移除={removed} "
          f"剩余 seq={[r.seq for r in records]} 链校验={svc.verify().ok}")
    assert removed == 1
    assert records[0].anchor and records[0].seq == 1
    assert svc.verify().ok

    # 100 天后：MEDIUM(seq=2) 也过期，HIGH(seq=3) 保留
    removed = svc.cleanup(t0 + 100 * DAY)
    records = svc.records()
    result = svc.verify()
    print(f"[输入] 100 天后清理 | [判定] 移除={removed} 剩余 seq={[r.seq for r in records]} "
          f"锚点={records[0].anchor} 链校验={result.ok}")
    assert removed == 1
    assert records[0].anchor and records[0].seq == 2
    assert [r.seq for r in records] == [2, 3]
    assert result.ok  # 清理不破坏校验结论


def test_expiry_boundary_exact_cutoff_kept(tmp_path):
    svc = _svc(tmp_path)
    t0 = 2_000_000.0
    svc.record(_event(ts=t0, key="a"))
    svc.record(_event(ts=t0 + 1, key="b"))
    # now - 30 天 == t0：恰好等于 cutoff 的记录保留，严格更早的才过期
    removed = svc.cleanup(t0 + 30 * DAY)
    seqs = [r.seq for r in svc.records()]
    print(f"[输入] occurred_at == cutoff（边界）| [判定] 移除={removed} 剩余 seq={seqs}")
    assert removed == 0  # t0 恰好等于 cutoff，不过期

    removed = svc.cleanup(t0 + 30 * DAY + 0.5)  # t0 过期、t0+1 不过期
    seqs = [r.seq for r in svc.records()]
    print(f"[输入] cutoff 越过 t0 0.5s | [判定] 移除={removed} 剩余 seq={seqs} "
          f"链校验={svc.verify().ok}")
    assert removed == 1
    assert seqs == [1, 2]  # 锚(seq=1) + seq2
    assert svc.verify().ok


def test_cleanup_preserves_chain_across_restart(tmp_path):
    cfg = AuditConfig(storage_dir=str(tmp_path))
    svc = AuditService(cfg)
    t0 = 3_000_000.0
    for i in range(5):
        svc.record(_event(ts=t0 + i, key=f"k{i}"))
    svc.cleanup(t0 + 30 * DAY + 3)  # 前 3 条过期

    svc2 = AuditService(cfg)  # 重启
    rec = svc2.record(_event(ts=t0 + 30 * DAY + 4, key="k5"))
    result = svc2.verify()
    print(f"[输入] 清理后重启再写 | [判定] 新 seq={rec.seq} 链校验={result.ok}")
    assert rec.seq == 6  # 链尾状态延续，序号不回退
    assert result.ok


def test_queries_during_cleanup_see_consistent_data(tmp_path):
    svc = _svc(tmp_path)
    t0 = 4_000_000.0
    for i in range(50):
        svc.record(_event(ts=t0 + i, key=f"k{i}"))

    violations: list[str] = []
    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            records = svc.records()
            seqs = [r.seq for r in records]
            if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
                violations.append(f"查询看到重排/重复数据: {seqs[:5]}…")
            if not svc.verify().ok:
                violations.append("查询看到校验失败的中间态")

    def cleaner() -> None:
        for step in range(10):
            svc.cleanup(t0 + 30 * DAY + step * 5)

    readers = [threading.Thread(target=reader) for _ in range(4)]
    for r in readers:
        r.start()
    cleaner()
    stop.set()
    for r in readers:
        r.join()

    print(f"[输入] 4 个并发查询线程 + 10 轮清理 | [判定] 违规次数={len(violations)} "
          f"最终链校验={svc.verify().ok}")
    assert not violations, violations
    assert svc.verify().ok
