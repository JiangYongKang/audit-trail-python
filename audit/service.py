"""审计服务：归一化、去重、定序、链式落盘、校验。

- 定序：单把锁内分配单调递增序号并链接 prev_hash，
  并发下记录顺序与进入临界区的真实顺序一致，不分叉、不断链。
- 去重：携带相同 idempotency_key 的重复提交直接返回首次记录，不产生新记录。
- 重启恢复：启动时从存储读取链尾（seq / prev_hash）与已见幂等键，链保持连续。
- 写失败：存储层重试后仍失败则向上抛出，序号不回溯、事件不丢失（调用方可重试同一事件）。
"""
from __future__ import annotations

import threading
import time

from .config import AuditConfig
from .hashchain import GENESIS_HASH, compute_record_hash, verify_chain
from .models import AuditEvent, AuditRecord, VerifyResult
from .query import Page, QueryFilter
from .query import query as query_snapshot
from .redaction import redact_event
from .store import AuditStore


class AuditService:
    """线程安全的审计服务入口。"""

    def __init__(self, config: AuditConfig | None = None, store: AuditStore | None = None) -> None:
        self._config = config or AuditConfig()
        self._store = store or AuditStore(self._config)
        # RLock + Condition 共用同一把锁：跟读等待与写入/清理通知互斥且可重入
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        tail = self._store.tail()
        self._seq = tail.seq if tail else 0
        self._prev_hash = tail.record_hash if tail else GENESIS_HASH
        # 恢复已见幂等键，保证重启后重复提交仍不产生重复记录
        self._seen_keys: dict[str, int] = {}
        self._records_by_key: dict[str, AuditRecord] = {}
        for rec in self._store.read_all():
            key = rec.event.idempotency_key
            if key:
                self._seen_keys[key] = rec.seq
                self._records_by_key[key] = rec

    def record(self, event: AuditEvent) -> AuditRecord:
        """记录一条审计事件：去重 -> 脱敏 -> 定序 -> 链式落盘。"""
        with self._lock:
            key = event.idempotency_key
            if key and key in self._seen_keys:
                return self._records_by_key[key]  # 重复提交：返回首次记录

            redacted = redact_event(event)
            if not redacted.occurred_at:
                redacted = AuditEvent(
                    **{**redacted.__dict__, "occurred_at": time.time()}
                )
            seq = self._seq + 1
            draft = AuditRecord(seq=seq, event=redacted, prev_hash=self._prev_hash,
                                record_hash="")
            record = AuditRecord(seq=seq, event=redacted, prev_hash=self._prev_hash,
                                 record_hash=compute_record_hash(draft))
            self._store.append(record)  # 失败抛异常，状态不前进，事件可由调用方重试
            self._seq = seq
            self._prev_hash = record.record_hash
            if key:
                self._seen_keys[key] = seq
                self._records_by_key[key] = record
            self._cond.notify_all()  # 唤醒跟读器：链尾已推进
            return record

    def verify(self) -> VerifyResult:
        """校验当前存储中的整条链。"""
        return verify_chain(self._store.read_all())

    def records(self) -> list[AuditRecord]:
        """读取当前全部记录。"""
        return self._store.read_all()

    def snapshot(self) -> list[AuditRecord]:
        """在服务锁内取一致性快照（与写入/清理互斥）。"""
        with self._lock:
            return self._store.read_all()

    def query(
        self,
        flt: QueryFilter | None = None,
        *,
        limit: int = 50,
        cursor: str | None = None,
        descending: bool = False,
    ) -> Page:
        """按条件分页查询。快照在服务锁内取得，并发写入/清理下读一致。"""
        with self._lock:
            return query_snapshot(
                self._store.read_all(), flt,
                limit=limit, cursor=cursor, descending=descending,
            )

    def cleanup(self, now: float) -> int:
        """触发保留期清理（只压缩链首前缀，不影响内存中的链尾状态）。

        清理在服务锁内进行，与查询/跟读互斥；清理后唤醒跟读器，
        游标落入被清理区段的跟读器会在下一次读取时得到明确错误。
        """
        with self._lock:
            try:
                return self._store.cleanup_expired(now)
            finally:
                self._cond.notify_all()
