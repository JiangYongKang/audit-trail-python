"""审计记录的持久化存储（骨架）：段文件、轮转、重试、保留期清理。"""
from __future__ import annotations

from pathlib import Path

from .config import AuditConfig
from .models import AuditRecord


class AuditStore:
    """基于 JSONL 段文件的追加式存储。"""

    def __init__(self, config: AuditConfig) -> None:
        self._config = config
        self._dir = Path(config.storage_dir)

    def append(self, record: AuditRecord) -> None:
        """追加一条记录，失败时按配置重试，最终失败抛异常。"""
        raise NotImplementedError

    def read_all(self) -> list[AuditRecord]:
        """读取当前全部记录（含锚点），按序号升序。"""
        raise NotImplementedError

    def tail(self) -> AuditRecord | None:
        """返回最后一条记录（用于重启后恢复链头），无记录返回 None。"""
        raise NotImplementedError

    def cleanup_expired(self, now: float) -> int:
        """按保留期清理过期记录，留下锚点保持链可校验；返回清理条数。"""
        raise NotImplementedError
