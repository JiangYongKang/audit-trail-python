"""条件查询测试：过滤边界、分页不重不漏、倒序、已清理区间提示、并发读写一致性。"""
from __future__ import annotations

import itertools
import threading

from audit.config import AuditConfig
from audit.models import AuditEvent, Outcome
from audit.query import QueryFilter
from audit.service import AuditService

DAY = 86400.0


def _event(i: int, **kw) -> AuditEvent:
    defaults = {
        "actor": f"user{i % 3}", "action": ("deploy" if i % 2 else "read"),
        "target": f"doc{i % 2}", "outcome": Outcome.SUCCESS,
        "occurred_at": 1_000.0 + i, "source": ("http" if i % 2 else "job"),
    }
    defaults.update(kw)
    return AuditEvent(**defaults)


def _svc(tmp_path, n: int) -> AuditService:
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    for i in range(n):
        svc.record(_event(i, idempotency_key=f"k{i}"))
    return svc


def _all_pages(svc, flt=None, limit=3, descending=False):
    pages, cursor, gap_seen = [], None, None
    while True:
        page = svc.query(flt, limit=limit, cursor=cursor, descending=descending)
        pages.append(page)
        if page.cleaned_gap and gap_seen is None:
            gap_seen = page.cleaned_gap
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    return pages, gap_seen


def test_time_window_is_half_open_boundaries(tmp_path):
    svc = _svc(tmp_path, 5)  # occurred_at = 1000..1004
    # [1001, 1003)：左边界包含、右边界排除
    page = svc.query(QueryFilter(start_time=1001.0, end_time=1003.0), limit=10)
    seqs = [r.seq for r in page.records]
    print(f"[输入] 时间窗 [1001,1003)，记录时间 1000..1004 | [判定] 命中 seq={seqs}")
    assert seqs == [2, 3]


def test_field_filters_exact_match(tmp_path):
    svc = _svc(tmp_path, 6)
    cases = [
        ("actor=user0", QueryFilter(actor="user0"), {1, 4}),
        ("action=deploy", QueryFilter(action="deploy"), {2, 4, 6}),
        ("target=doc1", QueryFilter(target="doc1"), {2, 4, 6}),
        ("source=job", QueryFilter(source="job"), {1, 3, 5}),
    ]
    for label, flt, expected in cases:
        seqs = {r.seq for r in svc.query(flt, limit=100).records}
        print(f"[输入] {label} | [判定] 命中 seq={sorted(seqs)}")
        assert seqs == expected


def test_pagination_no_dup_no_gap_forward(tmp_path):
    n = 10
    svc = _svc(tmp_path, n)
    pages, _ = _all_pages(svc, QueryFilter(actor="user1"), limit=2)
    seqs = [r.seq for p in pages for r in p.records]
    print(f"[输入] 过滤 actor=user1 共 {n} 条底数据，limit=2 翻页 | "
          f"[判定] 页序号={[ [r.seq for r in p.records] for p in pages ]} 并集={seqs}")
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))  # 不重
    # 不漏：与一次性全量过滤结果一致
    full = [r.seq for r in svc.query(QueryFilter(actor="user1"), limit=1000).records]
    assert seqs == full


def test_pagination_no_dup_no_gap_descending(tmp_path):
    svc = _svc(tmp_path, 10)
    pages, _ = _all_pages(svc, limit=3, descending=True)
    seqs = [r.seq for p in pages for r in p.records]
    print(f"[输入] 倒序 limit=3 翻全部 | [判定] 首页={[r.seq for r in pages[0].records]} "
          f"总数={len(seqs)} 严格递减={all(a > b for a, b in itertools.pairwise(seqs))}")
    assert seqs == list(range(10, 0, -1))  # 倒序不重不漏


def test_new_writes_during_forward_paging_not_lost(tmp_path):
    svc = _svc(tmp_path, 5)
    first = svc.query(limit=3)
    assert [r.seq for r in first.records] == [1, 2, 3]
    # 翻页间隙链尾新增 3 条：只能出现在后续页，已取页不受影响
    for i in range(5, 8):
        svc.record(_event(i, idempotency_key=f"k{i}"))
    second = svc.query(limit=10, cursor=first.next_cursor)
    seqs = [r.seq for r in second.records]
    print(f"[输入] 取第 1 页(1..3) 后新写 6..8 再取第 2 页 | [判定] 第 2 页 seq={seqs}")
    assert seqs == [4, 5, 6, 7, 8]  # 不重（没有 1..3）不漏（含新写入）


def test_query_overlapping_cleaned_range_signals_gap(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)  # seq 1..5(时间1000..1004) 过期
    # 窗口覆盖被清理段与存活段：必须明确告知 gap，且只返回存活记录
    page = svc.query(QueryFilter(start_time=999.0, end_time=1010.0), limit=50)
    live_seqs = [r.seq for r in page.records]
    gap = page.cleaned_gap
    print(f"[输入] 查询 [999,1010)，seq1..5 已清理 | "
          f"[判定] 存活命中={live_seqs} gap.up_to_seq={gap and gap.cleaned_up_to_seq} "
          f"gap.removed={gap and gap.removed_count}")
    assert live_seqs == [6, 7, 8, 9, 10]
    assert gap is not None and gap.cleaned_up_to_seq == 5
    assert gap.cleaned_from_seq == 1 and gap.removed_count == 5


def test_query_entirely_within_cleaned_range_still_signals(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)
    page = svc.query(QueryFilter(start_time=1001.0, end_time=1003.0), limit=50)
    print(f"[输入] 查询窗口完全落在已清理段 [1001,1003) | "
          f"[判定] 返回条数={len(page.records)} gap={page.cleaned_gap is not None}")
    assert page.records == []
    assert page.cleaned_gap is not None  # 不能悄悄返回空


def test_query_outside_cleaned_range_no_gap(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)
    page = svc.query(QueryFilter(start_time=1006.0, end_time=1009.0), limit=50)
    print(f"[输入] 查询窗口完全在存活段 [1006,1009) | "
          f"[判定] seq={[r.seq for r in page.records]} gap={page.cleaned_gap}")
    assert [r.seq for r in page.records] == [7, 8, 9]
    assert page.cleaned_gap is None


def test_gap_reported_once_then_paging_continues(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)
    pages, gap_seen = _all_pages(svc, limit=2)
    gaps = [p.cleaned_gap for p in pages]
    print(f"[输入] 清理后 limit=2 正序翻完 | [判定] 各页 gap={[g is not None for g in gaps]} "
          f"并集={[r.seq for p in pages for r in p.records]}")
    assert gap_seen is not None
    assert sum(1 for g in gaps if g) == 1  # 只在首页告知一次
    assert [r.seq for p in pages for r in p.records] == [6, 7, 8, 9, 10]


def test_concurrent_writes_cleanup_queries_consistent(tmp_path):
    svc = _svc(tmp_path, 200)
    violations: list[str] = []
    stop = threading.Event()

    def reader() -> None:
        cursor = None
        while not stop.is_set():
            page = svc.query(QueryFilter(actor="user1"), limit=7, cursor=cursor)
            seqs = [r.seq for r in page.records]
            if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
                violations.append(f"页内乱序/重复: {seqs}")
            cursor = page.next_cursor or None
            if cursor is None:
                cursor = None  # 重新从头翻，压力下反复与写/清理交错

    def writer() -> None:
        for i in range(200, 260):
            svc.record(_event(i, idempotency_key=f"k{i}"))

    def cleaner() -> None:
        for step in range(6):
            svc.cleanup(1000.0 + 30 * DAY + 10 + step * 20)

    readers = [threading.Thread(target=reader) for _ in range(4)]
    for t in readers:
        t.start()
    w = threading.Thread(target=writer)
    w.start()
    cleaner()
    w.join()
    stop.set()
    for t in readers:
        t.join()

    print(f"[输入] 4 查询线程翻页 + 60 条并发写 + 6 轮清理 | "
          f"[判定] 违规={violations[:1]} 链校验={svc.verify().ok}")
    assert not violations
    assert svc.verify().ok
