"""按敏感级别脱敏（骨架）。"""
from __future__ import annotations

from .models import AuditEvent


def redact_event(event: AuditEvent) -> AuditEvent:
    """按事件敏感级别对 details 中的敏感字段脱敏，返回新事件。"""
    raise NotImplementedError
