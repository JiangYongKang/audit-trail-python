"""审计记录的持久化存储：JSONL 段文件、轮转、写重试、保留期清理。

- 追加写：当前段超过 max_file_bytes 即轮转到新段。
- 写失败：按配置次数重试（指数退避），最终失败抛出 OSError，绝不静默吞掉。
- 清理：过期记录移除后留下锚点记录（承载被移除区段末尾哈希），
  新段先写临时文件再原子替换，清理与读取在同一把锁下互斥，
  查询不会看到残缺或重排的中间态。
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from .config import AuditConfig
from .hashchain import event_to_payload
from .models import AuditEvent, AuditRecord, Outcome, Sensitivity

logger = logging.getLogger("audit.store")

_SEGMENT_PREFIX = "segment-"
_SEGMENT_SUFFIX = ".jsonl"


def record_to_line(record: AuditRecord) -> str:
    payload = event_to_payload(record)
    payload["record_hash"] = record.record_hash
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def record_from_line(line: str) -> AuditRecord:
    payload = json.loads(line)
    ev = payload["event"]
    event = AuditEvent(
        actor=ev["actor"],
        action=ev["action"],
        target=ev["target"],
        outcome=Outcome(ev["outcome"]),
        deny_reason=ev.get("deny_reason"),
        correlation_id=ev.get("correlation_id", ""),
        idempotency_key=ev.get("idempotency_key"),
        sensitivity=Sensitivity(ev["sensitivity"]),
        occurred_at=ev["occurred_at"],
        details=ev.get("details", {}),
    )
    return AuditRecord(
        seq=payload["seq"],
        event=event,
        prev_hash=payload["prev_hash"],
        record_hash=payload["record_hash"],
        anchor=payload.get("anchor", False),
    )


class AuditStore:
    """基于 JSONL 段文件的追加式存储（进程内线程安全）。"""

    def __init__(self, config: AuditConfig) -> None:
        self._config = config
        self._dir = Path(config.storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    # ---- 段文件管理 ----

    def _segments(self) -> list[Path]:
        segs = sorted(
            p for p in self._dir.iterdir()
            if p.name.startswith(_SEGMENT_PREFIX) and p.name.endswith(_SEGMENT_SUFFIX)
        )
        return segs

    def _next_segment_path(self) -> Path:
        segs = self._segments()
        idx = int(segs[-1].name[len(_SEGMENT_PREFIX):-len(_SEGMENT_SUFFIX)]) + 1 if segs else 1
        return self._dir / f"{_SEGMENT_PREFIX}{idx:06d}{_SEGMENT_SUFFIX}"

    # ---- 写入 ----

    def append(self, record: AuditRecord) -> None:
        """追加一条记录，失败时按配置重试，最终失败抛 OSError。"""
        line = record_to_line(record) + "\n"
        with self._lock:
            path = self._current_writable_segment(len(line))
            self._write_with_retry(path, line)

    def _current_writable_segment(self, incoming: int) -> Path:
        segs = self._segments()
        if segs:
            last = segs[-1]
            if last.stat().st_size + incoming <= self._config.max_file_bytes:
                return last
        return self._next_segment_path()

    def _write_with_retry(self, path: Path, line: str) -> None:
        attempts = max(1, self._config.write_retries)
        last_exc: OSError | None = None
        for attempt in range(1, attempts + 1):
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
                return
            except OSError as exc:  # 不静默吞掉：记录日志并重试
                last_exc = exc
                logger.error("审计写入失败 path=%s 第 %d/%d 次: %s", path, attempt, attempts, exc)
                if attempt < attempts:
                    time.sleep(self._config.retry_backoff_s * attempt)
        raise OSError(f"审计写入在 {attempts} 次尝试后仍失败: {path}") from last_exc

    # ---- 读取 ----

    def read_all(self) -> list[AuditRecord]:
        """读取当前全部记录（含锚点），按序号升序。"""
        with self._lock:
            records: list[AuditRecord] = []
            for seg in self._segments():
                with open(seg, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            records.append(record_from_line(line))
            records.sort(key=lambda r: r.seq)
            return records

    def tail(self) -> AuditRecord | None:
        """返回最后一条记录（用于重启后恢复链头），无记录返回 None。"""
        with self._lock:
            segs = self._segments()
            for seg in reversed(segs):
                last_line = ""
                with open(seg, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            last_line = line
                if last_line:
                    return record_from_line(last_line)
            return None

    # ---- 保留期清理 ----

    def cleanup_expired(self, now: float) -> int:
        """按保留期清理过期记录，留下锚点保持链可校验；返回清理条数。"""
        with self._lock:
            records = self.read_all()
            if not records:
                return 0
            kept: list[AuditRecord] = []
            removed: list[AuditRecord] = []
            # 只移除“过期的最长前缀”：锚点压缩只能作用于链首连续区段，
            # 否则中间空洞会破坏链式校验。
            prefix_open = True
            for rec in records:
                if rec.anchor:
                    kept.append(rec)
                    continue
                retention_s = self._config.retention_days[rec.event.sensitivity] * 86400.0
                if prefix_open and rec.event.occurred_at < now - retention_s:
                    removed.append(rec)
                else:
                    prefix_open = False
                    kept.append(rec)
            if not removed:
                return 0

            last_removed = removed[-1]
            anchor = AuditRecord(
                seq=last_removed.seq,
                event=AuditEvent(
                    actor="__retention__",
                    action="__compact__",
                    target="__audit_log__",
                    outcome=Outcome.SUCCESS,
                    correlation_id=last_removed.event.correlation_id,
                    occurred_at=now,
                    details={
                        "removed_up_to_seq": last_removed.seq,
                        "removed_count": len(removed) + sum(
                            1 for k in kept if k.anchor and k.seq < last_removed.seq
                        ),
                    },
                ),
                prev_hash=last_removed.prev_hash,
                record_hash=last_removed.record_hash,  # 锚点承载被移除区段末尾哈希
                anchor=True,
            )
            new_records = [a for a in kept if a.anchor] + [anchor] + [
                r for r in kept if not r.anchor
            ]
            # 去重锚点（保留最新）并按序号排序
            anchors = [a for a in new_records if a.anchor]
            latest_anchor = anchors[-1]
            rest = [r for r in new_records if not r.anchor]
            final = [latest_anchor] + rest
            final.sort(key=lambda r: r.seq)

            self._rewrite_segments(final)
            logger.info("保留期清理完成：移除 %d 条，锚点 seq=%d", len(removed), last_removed.seq)
            return len(removed)

    def _rewrite_segments(self, records: list[AuditRecord]) -> None:
        """把记录集原子地重写为新的段文件（临时文件 + rename，再删旧段）。"""
        lines = [record_to_line(r) + "\n" for r in records]
        # 先写全部新段（临时名），再原子替换名，最后删旧段
        new_paths: list[Path] = []
        start_idx = int(self._segments()[-1].name[len(_SEGMENT_PREFIX):-len(_SEGMENT_SUFFIX)]) + 1 \
            if self._segments() else 1
        buf: list[str] = []
        size = 0
        idx = start_idx
        tmp_paths: list[tuple[Path, Path]] = []
        for line in lines + [None]:  # type: ignore[list-item]
            if line is not None:
                buf.append(line)
                size += len(line.encode("utf-8"))
            if (line is None or size > self._config.max_file_bytes) and buf:
                final_path = self._dir / f"{_SEGMENT_PREFIX}{idx:06d}{_SEGMENT_SUFFIX}"
                fd, tmp_name = tempfile.mkstemp(dir=self._dir, prefix=".tmp-")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.writelines(buf)
                    f.flush()
                    os.fsync(f.fileno())
                tmp_paths.append((Path(tmp_name), final_path))
                new_paths.append(final_path)
                idx += 1
                buf, size = [], 0
        old_segments = [p for p in self._segments() if p not in new_paths]
        for tmp, final in tmp_paths:
            os.replace(tmp, final)
        for old in old_segments:
            old.unlink()
