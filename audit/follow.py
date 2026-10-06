"""持续跟读审计记录：按位置续读，不丢不重。

位置语义：游标 = 已读到的最后一条记录 seq（0 表示从最旧的现存记录开始）。
断线/下游重启后拿同一游标继续读即可：
- 只取 seq > cursor 的记录，严格续读，不丢（游标后的全部记录）不重（游标及以前不再返回）；
- 记录的顺序就是写入时定序的 seq 顺序，与真实发生顺序一致；
- 若游标已落入被保留期清理掉的区段（0 < cursor <= 锚点 seq），
  抛出 CursorExpiredError 明确告知，调用方应改走导出/重新初始化，而不是装作无事发生。

等待通过服务锁上的条件变量完成：写入与清理提交后通知，读取在同一把锁下
取快照，因此不会读到半条或乱序数据。
"""
from __future__ import annotations

from typing import Self

from .models import AuditRecord

# 单次批量读取上限，避免一次交付过多记录
DEFAULT_BATCH_LIMIT = 100


class CursorExpiredError(Exception):
    """续读游标已落入被保留期清理掉的区段，无法再从该位置继续。"""


class FollowReader:
    """基于服务条件变量等待新记录的跟读器。

    游标语义对服务重启同样成立：seq 与链一起持久化，重启后新服务
    仍能识别同一游标。
    """

    def __init__(self, service, *, start_after: int = 0,
                 batch_limit: int = DEFAULT_BATCH_LIMIT) -> None:
        if start_after < 0:
            raise ValueError("start_after 不能为负")
        self._service = service
        self._batch_limit = batch_limit
        self._closed = False
        self._cursor = start_after
        self._check_cursor()  # 初始化即拒绝已失效游标，避免静默错读

    def _snapshot(self) -> list[AuditRecord]:
        return self._service.snapshot()

    def _check_cursor(self) -> None:
        records = self._snapshot()
        if records and records[0].anchor and 0 < self._cursor <= records[0].seq:
            gap = records[0].event.details
            raise CursorExpiredError(
                f"游标 {self._cursor} 已落入被清理区段"
                f"（seq {gap.get('removed_from_seq', 1)}..{records[0].seq} 已被保留期清理），"
                "无法从该位置续读，请改用区间导出获取接续点或从现存最旧记录重新跟读"
            )

    def position(self) -> int:
        """返回当前游标（已读到的最后一条 seq）。"""
        return self._cursor

    def read_batch(self, timeout: float | None = None) -> list[AuditRecord]:
        """读取游标之后的新记录（seq 升序，至多 batch_limit 条）。

        无新记录时阻塞至有写入/清理通知或超时；超时返回空列表，游标不变。
        游标失效（等待期间发生清理）时抛 CursorExpiredError。
        """
        service = self._service
        with service._cond:
            if self._closed:
                return []
            snapshot = service._store.read_all()
            # 游标一旦落入被清理区段，无论后面是否有新记录都必须先明确报错
            self._check_cursor_locked(snapshot)
            records = self._live_after_locked(snapshot)
            if not records:
                service._cond.wait(timeout)
                if self._closed:
                    return []
                # 等待期间可能发生了清理：醒来先复查游标，再取记录
                self._check_cursor_locked(service._store.read_all())
                records = self._live_after_locked(service._store.read_all())
            batch = records[: self._batch_limit]
            if batch:
                self._cursor = batch[-1].seq
            return batch

    def _live_after_locked(self, records: list[AuditRecord]) -> list[AuditRecord]:
        self._check_cursor_locked(records)
        return [r for r in records if not r.anchor and r.seq > self._cursor]

    def _check_cursor_locked(self, records: list[AuditRecord]) -> None:
        if records and records[0].anchor and 0 < self._cursor <= records[0].seq:
            gap = records[0].event.details
            raise CursorExpiredError(
                f"游标 {self._cursor} 已落入被清理区段"
                f"（seq {gap.get('removed_from_seq', 1)}..{records[0].seq} 已被保留期清理），"
                "无法从该位置续读"
            )

    def close(self) -> None:
        """释放跟读器并唤醒其等待。"""
        with self._service._cond:
            self._closed = True
            self._service._cond.notify_all()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
