"""审计事件与记录的数据模型定义。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Outcome(str, enum.Enum):
    """业务动作的处理结果。"""

    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class Sensitivity(str, enum.Enum):
    """事件敏感级别，决定脱敏方式与保留期。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class AuditEvent:
    """归一化后的审计事件（落盘前的内存形态）。"""

    actor: str
    action: str
    target: str
    outcome: Outcome
    deny_reason: str | None = None
    correlation_id: str = ""
    idempotency_key: str | None = None
    sensitivity: Sensitivity = Sensitivity.LOW
    occurred_at: float = 0.0
    source: str = ""  # 事件来源（入口标识，如 http / job / cli），空串视为“未标注”
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditRecord:
    """落盘的审计记录：事件 + 序号 + 哈希链指针。"""

    seq: int
    event: AuditEvent
    prev_hash: str
    record_hash: str
    anchor: bool = False  # 清理后留下的锚点记录，承载被移除区段的末尾哈希


@dataclass(frozen=True)
class VerifyResult:
    """链式校验结果。"""

    ok: bool
    first_bad_seq: int | None = None
    reason: str = ""
    checked: int = 0
