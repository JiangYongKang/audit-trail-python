"""审计服务：归一化、去重、定序、落盘、校验（骨架）。"""
from __future__ import annotations

from .config import AuditConfig
from .models import AuditEvent, AuditRecord, VerifyResult
from .store import AuditStore


class AuditService:
    """线程安全的审计服务入口。"""

    def __init__(self, config: AuditConfig | None = None, store: AuditStore | None = None) -> None:
        self._config = config or AuditConfig()
        self._store = store or AuditStore(self._config)

    def record(self, event: AuditEvent) -> AuditRecord:
        """记录一条审计事件：脱敏 -> 去重 -> 定序 -> 链式落盘。"""
        raise NotImplementedError

    def verify(self) -> VerifyResult:
        """校验当前存储中的整条链。"""
        raise NotImplementedError

    def records(self) -> list[AuditRecord]:
        """读取当前全部记录。"""
        raise NotImplementedError

    def cleanup(self, now: float) -> int:
        """触发保留期清理。"""
        raise NotImplementedError
