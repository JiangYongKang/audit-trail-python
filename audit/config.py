"""审计链路配置（骨架）。"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Sensitivity


@dataclass(frozen=True)
class AuditConfig:
    """审计服务配置项。"""

    storage_dir: str = "audit_data"
    max_file_bytes: int = 1_048_576  # 单个日志段文件大小上限，超过即轮转
    write_retries: int = 3           # 写入失败重试次数
    retry_backoff_s: float = 0.05
    retention_days: dict[Sensitivity, float] = field(
        default_factory=lambda: {
            Sensitivity.LOW: 30.0,
            Sensitivity.MEDIUM: 90.0,
            Sensitivity.HIGH: 365.0,
        }
    )
