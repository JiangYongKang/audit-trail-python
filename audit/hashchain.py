"""哈希链计算与校验（骨架）。"""
from __future__ import annotations

from .models import AuditRecord, VerifyResult

GENESIS_HASH = "0" * 64


def compute_record_hash(record: AuditRecord) -> str:
    """计算一条记录的哈希（覆盖序号、事件内容与 prev_hash）。"""
    raise NotImplementedError


def verify_chain(records: list[AuditRecord]) -> VerifyResult:
    """校验记录序列的哈希链，定位首个不一致位置。"""
    raise NotImplementedError
