"""条件查询：多条件过滤、时间序正/倒序浏览、游标分页与已清理区间告知。

- 过滤维度：时间范围（两端含边界）、操作者、动作、对象、结果、来源。
- 分页：基于单调序号的键集分页（游标不透明），首页固定一个“读取窗口”
  （首页快照时刻的链首/链尾），后续页只在窗口内移动——并发写入产生的新记录
  不会混进本次翻页，因此前后两页不重、不漏。
- 已清理告知：窗口起始锚点承载了被移除记录的发生时间区间，查询时间段与该区间
  相交时通过 Page.cleaned 显式告知；翻页若落入已被清理的位置则抛 CursorExpired。
- 一致性：每次读取都是存储锁保护下的完整快照，写入/清理进行中也看不到
  乱序、重复或写了一半的中间态。
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass

from .models import AuditRecord, Outcome
from .service import AuditService


class QueryError(Exception):
    """查询相关错误的基类。"""


class CursorInvalid(QueryError):
    """游标无法解析或与本次过滤条件不一致。"""


class CursorExpired(QueryError):
    """翻页位置已落入保留期清理区段，继续翻页将不可避免地漏数据。"""


@dataclass(frozen=True)
class QueryFilter:
    """查询条件；任何一项为 None 表示不过滤该维度。时间范围两端均含边界。"""

    start_time: float | None = None
    end_time: float | None = None
    actor: str | None = None
    action: str | None = None
    target: str | None = None
    outcome: Outcome | None = None
    source: str | None = None


@dataclass(frozen=True)
class Page:
    """一页查询结果。

    - records：本页记录（不含锚点），按请求方向有序；
    - next_cursor：下一页游标，窗口内无更多数据时为 None；
    - has_more：窗口内是否还有可翻的数据；
    - cleaned：查询的时间范围是否与已被保留期清理的时间区间相交；
    - cleaned_*：最近一次清理的接续信息（锚点序号、清理时刻、累计移除条数、
      被移除记录的发生时间起止）。
    """

    records: list[AuditRecord]
    next_cursor: str | None
    has_more: bool
    cleaned: bool = False
    cleaned_up_to_seq: int | None = None
    cleaned_at: float | None = None
    removed_count: int | None = None
    removed_from_ts: float | None = None
    removed_up_to_ts: float | None = None


def _filter_fingerprint(flt: QueryFilter) -> str:
    payload = asdict(flt)
    if payload.get("outcome") is not None:
        payload["outcome"] = flt.outcome.value  # type: ignore[union-attr]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _encode_cursor(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> dict:
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + padding)
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise CursorInvalid(f"游标无法解析: {cursor[:16]}…") from exc
    required = {"f", "d", "wlo", "whi", "a"}
    if not required.issubset(data):
        raise CursorInvalid("游标缺少必要字段")
    return data


class QueryReader:
    """对审计服务做条件查询与游标分页（每次读取都是存储一致性快照）。"""

    def __init__(self, service: AuditService, page_size: int = 50) -> None:
        if page_size < 1:
            raise ValueError("page_size 必须 >= 1")
        self._service = service
        self._page_size = page_size

    # ---- 过滤 ----

    @staticmethod
    def _matches(rec: AuditRecord, flt: QueryFilter) -> bool:
        if rec.anchor:
            return False  # 锚点是接续点，不作为业务记录返回
        ev = rec.event
        if flt.start_time is not None and ev.occurred_at < flt.start_time:
            return False
        if flt.end_time is not None and ev.occurred_at > flt.end_time:
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
    # ---- 锚点/已清理信息 ----

    @staticmethod
    def _head_anchor(snapshot: list[AuditRecord]) -> AuditRecord | None:
        return snapshot[0] if snapshot and snapshot[0].anchor else None

    @staticmethod
    def _cleaned_info(anchor: AuditRecord | None) -> dict:
        if anchor is None:
            return {}
        d = anchor.event.details
        return {
            "cleaned": True,
            "cleaned_up_to_seq": anchor.seq,
            "cleaned_at": anchor.event.occurred_at,
            "removed_count": d.get("removed_count"),
            "removed_from_ts": d.get("removed_from_ts"),
            "removed_up_to_ts": d.get("removed_up_to_ts"),
        }

    @staticmethod
    def _range_hits_cleaned(flt: QueryFilter, info: dict) -> bool:
        """查询时间段与被移除记录的发生时间区间是否相交（两端含边界）。"""
        if not info:
            return False
        start = flt.start_time if flt.start_time is not None else float("-inf")
        end = flt.end_time if flt.end_time is not None else float("inf")
        removed_from = info.get("removed_from_ts")
        removed_to = info.get("removed_up_to_ts")
        if removed_from is None or removed_to is None:
            return True  # 旧锚点无时间区间信息：保守告知
        return start <= removed_to and end >= removed_from

    # ---- 分页 ----

    def first_page(self, flt: QueryFilter | None = None,
                   descending: bool = False) -> Page:
        flt = flt or QueryFilter()
        snapshot = self._service.records()
        anchor = self._head_anchor(snapshot)
        window_low = anchor.seq if anchor else 0
        window_high = snapshot[-1].seq if snapshot else 0

        eligible = [r for r in snapshot if self._matches(r, flt)]
        if descending:
            eligible.reverse()
        return self._build_page(eligible, flt, descending, window_low, window_high,
                                anchor, cleaned_window_shrunk=False)

    def next_page(self, cursor: str, flt: QueryFilter | None = None) -> Page:
        data = _decode_cursor(cursor)
        flt = flt or QueryFilter()
        if data["f"] != _filter_fingerprint(flt):
            raise CursorInvalid("游标对应的过滤条件与本次查询不一致，请从第一页重新开始")
        descending = bool(data["d"])
        window_low, window_high, after_seq = data["wlo"], data["whi"], data["a"]

        snapshot = self._service.records()
        anchor = self._head_anchor(snapshot)
        head_seq = anchor.seq if anchor else 0
        cleaned_shrunk = head_seq > window_low

        # 正/倒序同理：游标引用的“上一条位置”若已被压缩到锚点之前，继续翻页
        # 必然漏数据，显式报错。
        if after_seq < head_seq:
            raise CursorExpired(
                f"游标位置 seq={after_seq} 已被保留期清理（当前最早可读序号 {head_seq}）"
            )

        eligible = [r for r in snapshot if self._matches(r, flt)]
        if descending:
            eligible.reverse()
            window = [r for r in eligible
                      if r.seq < after_seq and r.seq >= head_seq
                      and r.seq <= window_high]
        else:
            window = [r for r in eligible
                      if r.seq > after_seq and r.seq <= window_high]
        return self._build_page(window, flt, descending, window_low, window_high,
                                anchor, cleaned_window_shrunk=cleaned_shrunk)

    def _build_page(self, window: list[AuditRecord], flt: QueryFilter,
                    descending: bool, window_low: int, window_high: int,
                    anchor: AuditRecord | None,
                    cleaned_window_shrunk: bool) -> Page:
        page_items = window[: self._page_size]
        has_more = len(window) > len(page_items)

        info = self._cleaned_info(anchor)
        cleaned = self._range_hits_cleaned(flt, info) or cleaned_window_shrunk
        result_kwargs = {
            "records": page_items,
            "next_cursor": None,
            "has_more": has_more,
            "cleaned": cleaned,
            **(info if cleaned else {}),
        }
        if has_more and page_items:
            cursor = _encode_cursor({
                "f": _filter_fingerprint(flt),
                "d": descending,
                "wlo": window_low,
                "whi": window_high,
                "a": page_items[-1].seq,
            })
            result_kwargs["next_cursor"] = cursor
        return Page(**result_kwargs)  # type: ignore[arg-type]
