"""按条件查询审计记录：过滤、倒序、键集分页、已清理区间提示。

快照一致性：查询基于存储在同一把锁下取出的快照，与写入/清理互斥，
不会看到乱序、重复或只写了一半的数据。

分页（键集分页，不使用易丢/易重的 OFFSET）：
- 游标是不透明字符串，内容即“本页最后一条记录的 seq”；
- 正序下一页从 seq > cursor 继续，倒序从 seq < cursor 继续，
  前后两页因此既不重复也不会漏；
- 写入只发生在链尾：正序翻页期间新写入的记录只会出现在后续页，
  不会让已取页重排；倒序同理，新记录自然排到最前，不影响旧页边界。

已清理区间：保留期清理后链首只留锚点。查询窗口与锚点声明的被清理
区段（时间跨度/序号跨度）重叠时，页结果携带 cleaned_gap 明确告知，
而不是悄悄少返回几条。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import AuditRecord, Outcome


@dataclass(frozen=True)
class QueryFilter:
    """查询条件；时间窗口为左闭右开 [start_time, end_time)。"""

    start_time: float | None = None
    end_time: float | None = None
    actor: str | None = None
    action: str | None = None
    target: str | None = None
    outcome: Outcome | None = None
    source: str | None = None


@dataclass(frozen=True)
class CleanedGap:
    """查询区间与已被保留期清理的区段发生重叠的提示。"""

    cleaned_up_to_seq: int
    cleaned_from_seq: int
    cleaned_from_occurred_at: float
    cleaned_up_to_occurred_at: float
    removed_count: int


@dataclass(frozen=True)
class Page:
    """一页查询结果。游标为不透明字符串（内容即上一页最后一条的 seq）。"""

    records: list[AuditRecord]
    next_cursor: str | None
    cleaned_gap: CleanedGap | None = field(default=None)


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        value = int(cursor)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法分页游标: {cursor!r}") from exc
    if value < 0:
        raise ValueError(f"非法分页游标: {cursor!r}")
    return value


def _gap_from_anchor(anchor: AuditRecord) -> CleanedGap:
    d = anchor.event.details
    return CleanedGap(
        cleaned_up_to_seq=anchor.seq,
        cleaned_from_seq=int(d.get("removed_from_seq", 1)),
        cleaned_from_occurred_at=float(
            d.get("removed_from_occurred_at", anchor.event.occurred_at)
        ),
        cleaned_up_to_occurred_at=float(
            d.get("removed_up_to_occurred_at", anchor.event.occurred_at)
        ),
        removed_count=int(d.get("removed_count", 0)),
    )


def _matches(rec: AuditRecord, flt: QueryFilter) -> bool:
    ev = rec.event
    if flt.start_time is not None and ev.occurred_at < flt.start_time:
        return False
    if flt.end_time is not None and ev.occurred_at >= flt.end_time:
        return False
    if flt.actor is not None and ev.actor != flt.actor:
        return False
    if flt.action is not None and ev.action != flt.action:
        return False
    if flt.target is not None and ev.target != flt.target:
        return False
    if flt.outcome is not None and ev.outcome != flt.outcome:
        return False
    return flt.source is None or ev.source == flt.source


def _gap_visible(
    gap: CleanedGap, flt: QueryFilter, cursor_seq: int, cursor_given: bool,
    descending: bool,
) -> bool:
    # 时间窗口与被清理区段 [from_ts, up_to_ts] 是否重叠
    if flt.start_time is not None and flt.start_time > gap.cleaned_up_to_occurred_at:
        return False
    if flt.end_time is not None and flt.end_time <= gap.cleaned_from_occurred_at:
        return False
    if not cursor_given:
        return True  # 全新查询的首页：窗口重叠即告知
    if descending:
        # 倒序翻页已经翻过锚点（游标 <= 锚点 seq）后不再重复告知
        return cursor_seq > gap.cleaned_up_to_seq
    # 正序：游标仍落在被清理区段内或其之前时告知
    return cursor_seq < gap.cleaned_up_to_seq


def query(
    records: list[AuditRecord],
    flt: QueryFilter | None = None,
    *,
    limit: int = 50,
    cursor: str | None = None,
    descending: bool = False,
) -> Page:
    """在记录快照上执行条件查询。

    records 须为按 seq 升序的一致性快照（可含链首锚点）。返回单页结果，
    通过 next_cursor 翻页；命中已清理区段时返回 cleaned_gap。
    """
    if limit <= 0:
        raise ValueError("limit 必须为正整数")
    flt = flt or QueryFilter()
    cursor_seq = _decode_cursor(cursor)

    anchor = records[0] if records and records[0].anchor else None
    live = [r for r in records if not r.anchor]

    if descending:
        # cursor 缺省从链尾开始；倒序每页取 seq < cursor
        ordered = list(reversed(live)) if cursor is None \
            else [r for r in reversed(live) if r.seq < cursor_seq]
    else:
        ordered = [r for r in live if r.seq > cursor_seq]

    filtered = [r for r in ordered if _matches(r, flt)]
    page = filtered[:limit]
    more = len(filtered) > limit
    next_cursor = str(page[-1].seq) if more and page else None

    gap = None
    if anchor is not None:
        candidate = _gap_from_anchor(anchor)
        if _gap_visible(candidate, flt, cursor_seq, cursor is not None, descending):
            gap = candidate

    return Page(records=page, next_cursor=next_cursor, cleaned_gap=gap)
