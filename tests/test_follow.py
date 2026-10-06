"""持续跟读测试：按位置续读不重不漏、长轮询等新记录、断线重启续读、
并发写入顺序一致、位置落到已清理区段时报错、内容不含脱敏原文。"""
from __future__ import annotations

import threading
import time

from audit.config import AuditConfig
from audit.follow import (
    POSITION_START,
    FollowReader,
    PositionCompacted,
    PositionInvalid,
)
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.service import AuditService

DAY = 86400.0


def _svc(tmp_path, **kw) -> AuditService:
    return AuditService(AuditConfig(storage_dir=str(tmp_path), **kw))


def _event(ts: float, key: str | None = None, sensitivity: Sensitivity = Sensitivity.LOW,
           details: dict | None = None) -> AuditEvent:
    return AuditEvent(actor="alice", action="read", target="doc",
                      outcome=Outcome.SUCCESS, correlation_id="c",
                      idempotency_key=key, sensitivity=sensitivity,
                      occurred_at=ts, source="http", details=details or {})


def test_poll_from_start_then_resume_no_dup_no_gap(tmp_path):
    svc = _svc(tmp_path)
    for i in range(5):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    fr = FollowReader(svc)

    b1 = fr.poll(POSITION_START, max_records=2)
    b2 = fr.poll(b1.next_position, max_records=2)
    b3 = fr.poll(b2.next_position, max_records=2)
    b4 = fr.poll(b3.next_position, max_records=2)  # 已到尾部：空批
    got = [r.seq for r in b1.records + b2.records + b3.records]
    print(f"[输入] 5 条记录，按 2 条/批续读（模拟断线后用位置续上）| "
          f"[判定] 汇总 seq={got} 末批空={b4.records == []} "
          f"末位置={b4.next_position} waited={b4.waited}")
    assert got == [1, 2, 3, 4, 5]  # 不重不漏
    assert b4.records == []
    assert b4.next_position == "5"
    assert b4.waited is False  # 未给等待超时，不空等


def test_long_poll_waits_for_new_record(tmp_path):
    svc = _svc(tmp_path)
    for i in range(2):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    fr = FollowReader(svc, poll_interval_s=0.01)

    def add_later() -> None:
        time.sleep(0.08)
        svc.record(_event(ts=99.0, key="late"))

    threading.Thread(target=add_later).start()
    t0 = time.monotonic()
    batch = fr.poll("2", max_records=10, wait_timeout_s=1.0)
    elapsed = time.monotonic() - t0
    print(f"[输入] 尾部位置=2，80ms 后写入 seq3，长轮询 1s | "
          f"[判定] 拿到 seq={[r.seq for r in batch.records]} 等待={elapsed:.2f}s "
          f"waited={batch.waited} 下一位置={batch.next_position}")
    assert [r.seq for r in batch.records] == [3]
    assert batch.waited is True
    assert 0.05 < elapsed < 0.8


def test_restart_resume_from_persisted_position(tmp_path):
    cfg = AuditConfig(storage_dir=str(tmp_path))
    svc1 = AuditService(cfg)
    for i in range(4):
        svc1.record(_event(ts=float(i), key=f"k{i}"))
    fr = FollowReader(svc1)
    batch = fr.poll(POSITION_START, max_records=2)
    saved_position = batch.next_position  # 下游持久化的位置

    svc2 = AuditService(cfg)  # 下游+服务一起重启
    svc2.record(_event(ts=4.0, key="k4"))
    fr2 = FollowReader(svc2)
    resumed = fr2.poll(saved_position, max_records=10)
    print(f"[输入] 重启前读到位置 {saved_position}，重启期间又写 1 条 | "
          f"[判定] 续读 seq={[r.seq for r in resumed.records]} 下一位置={resumed.next_position}")
    assert [r.seq for r in resumed.records] == [3, 4, 5]  # 从位置后继续，不重不漏


def test_concurrent_writes_follow_order_matches_commit_order(tmp_path):
    svc = _svc(tmp_path)
    n_threads, n_each = 6, 20
    stop = threading.Event()
    seen: list[int] = []
    read_errors: list[str] = []

    def reader() -> None:
        fr = FollowReader(svc, poll_interval_s=0.002)
        position = POSITION_START
        while not stop.is_set():
            try:
                batch = fr.poll(position, max_records=7, wait_timeout_s=0.05)
            except PositionCompacted as exc:
                read_errors.append(str(exc))
                return
            seen.extend(r.seq for r in batch.records)
            position = batch.next_position

    rt = threading.Thread(target=reader)
    rt.start()

    def writer(tid: int) -> None:
        for i in range(n_each):
            svc.record(_event(ts=float(tid * 100 + i), key=f"w{tid}-{i}"))

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 等 reader 把尾部读完
    deadline = time.monotonic() + 2.0
    while len(seen) < n_threads * n_each and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    rt.join()

    print(f"[输入] {n_threads} 线程×{n_each} 并发写 + 同步跟读 | "
          f"[判定] 读到={len(seen)} 严格递增={seen == sorted(seen)} "
          f"无重复={len(set(seen)) == len(seen)} 完整={sorted(seen) == list(range(1, 121))} "
          f"错误={read_errors}")
    assert len(seen) == n_threads * n_each
    assert seen == sorted(seen) and len(set(seen)) == len(seen)
    assert sorted(seen) == list(range(1, n_threads * n_each + 1))


def test_position_in_compacted_range_raises(tmp_path):
    svc = _svc(tmp_path)
    t0 = 9_000_000.0
    for i in range(10):
        svc.record(_event(ts=t0 + i * DAY, key=f"k{i}"))
    fr = FollowReader(svc)
    batch = fr.poll(POSITION_START, max_records=3)
    saved = batch.next_position  # 位置 = 3
    svc.cleanup(t0 + 40 * DAY)   # 默认 30 天保留：前若干条被压缩为锚点
    try:
        fr.poll(saved, max_records=10)
        raised = None
    except PositionCompacted as exc:
        raised = exc
    print(f"[输入] 位置 seq={saved} 落在保留期清理区段后续读 | "
          f"[判定] PositionCompacted={raised is not None}（{raised}）")
    assert raised is not None
    assert raised.position_seq == 3
    # 从锚点之后重新开始跟读仍然可用
    anchor = svc.records()[0]
    fresh = fr.poll(str(anchor.seq), max_records=10)
    print(f"[输入] 从锚点 seq={anchor.seq} 之后重新跟读 | "
          f"[判定] seq={[r.seq for r in fresh.records]}")
    assert all(r.seq > anchor.seq for r in fresh.records)


def test_invalid_position_raises(tmp_path):
    fr = FollowReader(_svc(tmp_path))
    for bad in ("abc", "-1"):
        try:
            fr.poll(bad)
            raised = None
        except PositionInvalid:
            raised = True
        print(f"[输入] 非法续读位置 {bad!r} | [判定] PositionInvalid={raised is not None}")
        assert raised is not None


def test_followed_content_has_no_raw_secret(tmp_path):
    svc = _svc(tmp_path)
    secret = "p@ss-跟读绝密"
    svc.record(_event(ts=1.0, sensitivity=Sensitivity.HIGH,
                      details={"password": secret, "email": "spy@x.cn"}, key="k1"))
    fr = FollowReader(svc)
    batch = fr.poll(POSITION_START, max_records=10)
    dumped = str(batch.records)
    print(f"[输入] HIGH 含密事件写入后跟读 | [判定] 内容不含原文={secret not in dumped} "
          f"seq={[r.seq for r in batch.records]}")
    assert secret not in dumped
    assert [r.seq for r in batch.records] == [1]


def test_stream_generator_resumes_across_batches(tmp_path):
    svc = _svc(tmp_path)
    for i in range(5):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    fr = FollowReader(svc, poll_interval_s=0.005)
    gen = fr.stream(POSITION_START, max_records=2, wait_timeout_s=0.0)
    b1 = next(gen)
    b2 = next(gen)
    b3 = next(gen)  # seq5
    b4 = next(gen)  # 到尾部，空批
    seqs = [r.seq for r in b1.records + b2.records + b3.records]
    print(f"[输入] stream() 生成器按 2 条/批取数 | [判定] seq={seqs} "
          f"末批空={b4.records == []} 位置={b4.next_position}")
    assert seqs == [1, 2, 3, 4, 5]
    assert b4.records == [] and b4.next_position == "5"
    gen.close()
