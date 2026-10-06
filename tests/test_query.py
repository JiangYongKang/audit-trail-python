"""条件查询测试：过滤条件边界、正/倒序、游标分页不重不漏。"""
from __future__ import annotations

from audit.config import AuditConfig
from audit.models import AuditEvent, Outcome
from audit.query import QueryFilter, QueryReader
from audit.service import AuditService


def _svc(tmp_path, **kw) -> AuditService:
    return AuditService(AuditConfig(storage_dir=str(tmp_path), **kw))


def _event(ts: float, actor: str = "alice", action: str = "read",
           target: str = "doc", outcome: Outcome = Outcome.SUCCESS,
           source: str = "http", key: str | None = None) -> AuditEvent:
    return AuditEvent(actor=actor, action=action, target=target, outcome=outcome,
                      correlation_id="c", idempotency_key=key,
                      occurred_at=ts, source=source)


def test_time_range_is_inclusive_at_both_ends(tmp_path):
    svc = _svc(tmp_path)
    for ts in (10.0, 11.0, 12.0):
        svc.record(_event(ts=ts, key=f"k{ts}"))
    qr = QueryReader(svc)
    page = qr.first_page(QueryFilter(start_time=11.0, end_time=11.0))
    seqs = [r.seq for r in page.records]
    print(f"[输入] 记录时间 10/11/12，查询 [11,11]（两端含边界）| "
          f"[判定] 命中 seq={seqs} cleaned={page.cleaned}")
    assert seqs == [2]
    assert not page.cleaned


def test_all_filter_dimensions(tmp_path):
    svc = _svc(tmp_path)
    svc.record(_event(ts=1.0, actor="alice", action="read", target="doc-a",
                      outcome=Outcome.SUCCESS, source="http", key="1"))
    svc.record(_event(ts=2.0, actor="bob", action="write", target="doc-b",
                      outcome=Outcome.DENIED, source="job", key="2"))
    svc.record(_event(ts=3.0, actor="alice", action="write", target="doc-a",
                      outcome=Outcome.SUCCESS, source="http", key="3"))
    qr = QueryReader(svc)

    cases = [
        (QueryFilter(actor="alice"), [1, 3]),
        (QueryFilter(action="write"), [2, 3]),
        (QueryFilter(target="doc-b"), [2]),
        (QueryFilter(outcome=Outcome.DENIED), [2]),
        (QueryFilter(source="job"), [2]),
        (QueryFilter(actor="alice", action="write", outcome=Outcome.SUCCESS,
                     start_time=0.0, end_time=100.0), [3]),
    ]
    for flt, expected in cases:
        page = qr.first_page(flt)
        got = [r.seq for r in page.records]
        print(f"[输入] 过滤 {flt} | [判定] 命中 seq={got} 期望={expected}")
        assert got == expected


def test_descending_returns_newest_first(tmp_path):
    svc = _svc(tmp_path)
    for i in range(5):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    page = QueryReader(svc).first_page(descending=True)
    seqs = [r.seq for r in page.records]
    print(f"[输入] 5 条记录，倒序查询 | [判定] seq={seqs}")
    assert seqs == [5, 4, 3, 2, 1]


def test_pagination_no_dup_no_gap(tmp_path):
    svc = _svc(tmp_path)
    n = 23
    for i in range(n):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    qr = QueryReader(svc, page_size=10)

    seen: list[int] = []
    page = qr.first_page()
    pages = 0
    while True:
        seen.extend(r.seq for r in page.records)
        pages += 1
        if page.next_cursor is None:
            break
        page = qr.next_page(page.next_cursor)
    print(f"[输入] {n} 条记录，page_size=10 正序翻页 | "
          f"[判定] 页数={pages} 汇总 seq={seen} has_more(末页)={page.has_more}")
    assert seen == list(range(1, n + 1))  # 不重不漏
    assert pages == 3
    assert not page.has_more


def test_descending_pagination_no_dup_no_gap(tmp_path):
    svc = _svc(tmp_path)
    n = 15
    for i in range(n):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    qr = QueryReader(svc, page_size=4)

    seen: list[int] = []
    page = qr.first_page(descending=True)
    while True:
        seen.extend(r.seq for r in page.records)
        if page.next_cursor is None:
            break
        page = qr.next_page(page.next_cursor)
    print(f"[输入] {n} 条记录，page_size=4 倒序翻页 | [判定] 汇总 seq={seen}")
    assert seen == list(range(n, 0, -1))
    assert len(seen) == n


"""—— 已清理区间与游标行为 ——"""

import threading

from audit.query import CursorExpired, CursorInvalid

DAY = 86400.0


def test_cleaned_range_reported_not_silent_shortage(tmp_path):
    """查询时间段命中已清理区段：显式 cleaned=True，而不是悄悄少返回。"""
    from audit.models import Sensitivity
    cfg = AuditConfig(storage_dir=str(tmp_path),
                      retention_days={Sensitivity.LOW: 10.0,
                                      Sensitivity.MEDIUM: 10.0,
                                      Sensitivity.HIGH: 10.0})
    svc = AuditService(cfg)
    t0 = 5_000_000.0
    for i in range(5):
        svc.record(_event(ts=t0 + i * DAY, key=f"k{i}"))
    svc.cleanup(t0 + 10 * DAY + 0.5)  # seq1（t0）过期，留锚点 seq=1

    qr = QueryReader(svc)
    # 查询区间覆盖被移除记录的发生时间 t0（其余记录按天间隔，尚未过期）
    page = qr.first_page(QueryFilter(start_time=t0 - 1, end_time=t0 + 5 * DAY))
    seqs = [r.seq for r in page.records]
    print(f"[输入] 清理 seq=1 后查询覆盖其发生时间 | "
          f"[判定] 返回 seq={seqs} cleaned={page.cleaned} "
          f"锚点seq={page.cleaned_up_to_seq} 移除条数={page.removed_count}")
    assert seqs == [2, 3, 4, 5]
    assert page.cleaned is True
    assert page.cleaned_up_to_seq == 1
    assert page.removed_count == 1

    # 查询区间与已清理时间不相交：不告警
    page2 = qr.first_page(QueryFilter(start_time=t0 + 2 * DAY, end_time=t0 + 5 * DAY))
    print(f"[输入] 查询区间晚于被移除记录时间 | [判定] cleaned={page2.cleaned}")
    assert page2.cleaned is False


def test_cursor_into_compacted_range_raises(tmp_path):
    """翻页过程中位置被清理：显式抛 CursorExpired，禁止装作无事继续。"""
    svc = _svc(tmp_path)
    t0 = 6_000_000.0
    n = 20
    for i in range(n):
        svc.record(_event(ts=t0 + i, key=f"k{i}"))
    qr = QueryReader(svc, page_size=5)
    page = qr.first_page()
    assert [r.seq for r in page.records] == [1, 2, 3, 4, 5]

    # 清理把前 10 条压缩为锚点 seq=10
    svc.cleanup(t0 + 30 * DAY + 11)
    try:
        qr.next_page(page.next_cursor)
        raised = None
    except CursorExpired as exc:
        raised = exc
    print(f"[输入] 首页取 seq1-5 后清理前 10 条，再翻页 | "
          f"[判定] 抛出 CursorExpired={raised is not None} 信息={raised}")
    assert raised is not None


def test_cursor_filter_mismatch_raises(tmp_path):
    svc = _svc(tmp_path)
    for i in range(6):
        svc.record(_event(ts=float(i), actor="alice" if i % 2 else "bob",
                          key=f"k{i}"))
    qr = QueryReader(svc, page_size=2)
    page = qr.first_page(QueryFilter(actor="alice"))
    try:
        qr.next_page(page.next_cursor, QueryFilter(actor="bob"))
        raised = None
    except CursorInvalid as exc:
        raised = exc
    print(f"[输入] 用 alice 的游标翻 bob 的查询 | [判定] CursorInvalid={raised is not None}")
    assert raised is not None


def test_concurrent_writes_dont_duplicate_or_gap_pages(tmp_path):
    """翻页期间持续写入：窗口固定，本次遍历不重不漏（新数据留给下次首页）。"""
    svc = _svc(tmp_path)
    t0 = 7_000_000.0
    for i in range(20):
        svc.record(_event(ts=t0 + i, key=f"init{i}"))
    qr = QueryReader(svc, page_size=7)

    page = qr.first_page()  # 先固定本次遍历窗口（1..20），再让写入开始
    stop = threading.Event()

    def writer() -> None:
        i = 0
        while not stop.is_set():
            svc.record(_event(ts=t0 + 1000 + i, key=f"new{i}"))
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    seen: list[int] = []
    try:
        while True:
            seen.extend(r.seq for r in page.records)
            if page.next_cursor is None:
                break
            page = qr.next_page(page.next_cursor)
    finally:
        stop.set()
        t.join()
    print(f"[输入] 翻页期间持续写入 | [判定] 本次遍历 seq={seen} "
          f"恰好={seen == list(range(1, 21))} 链校验={svc.verify().ok}")
    assert seen == list(range(1, 21))  # 窗口内不重不漏
    assert svc.verify().ok


def test_concurrent_cleanup_keeps_reads_consistent(tmp_path):
    """查询与清理并发：不出现乱序/重复/半截数据；最后一页带 cleaned 告知。"""
    svc = _svc(tmp_path)
    t0 = 8_000_000.0
    for i in range(60):
        svc.record(_event(ts=t0 + i, key=f"k{i}"))
    qr = QueryReader(svc, page_size=8)

    stop = threading.Event()
    violations: list[str] = []

    def reader() -> None:
        while not stop.is_set():
            page = qr.first_page()
            seqs = [r.seq for r in page.records]
            if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
                violations.append(f"页内乱序/重复: {seqs}")
            if any(r.anchor for r in page.records):
                violations.append("锚点被当作业务记录返回")

    def cleaner() -> None:
        for step in range(12):
            svc.cleanup(t0 + 30 * DAY + step * 5)

    rt = threading.Thread(target=reader)
    rt.start()
    cleaner()
    stop.set()
    rt.join()

    page = qr.first_page()
    print(f"[输入] 查询与 12 轮清理并发 | [判定] 违规={len(violations)} "
          f"清理后首页 seq={[r.seq for r in page.records][:3]}… "
          f"cleaned={page.cleaned} 链校验={svc.verify().ok}")
    assert not violations
    assert page.cleaned is True
    assert svc.verify().ok
