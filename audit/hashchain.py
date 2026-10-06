"""哈希链计算与校验。

每条记录的哈希覆盖：序号、事件全部字段、前一条记录的哈希。
校验时同时检查：序号连续性、prev_hash 链接、记录内容哈希，
可在改写 / 插入 / 删除 / 乱序时定位首个不一致位置。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from .models import AuditRecord, VerifyResult

GENESIS_HASH = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_to_payload(record: AuditRecord) -> dict[str, Any]:
    """把记录序列化为规范字典（枚举取值、键排序由 _canonical 保证）。

    兼容性：历史记录没有 source 字段（等价于空串），空 source 不写入载荷，
    使旧记录重算哈希保持不变；非空 source 参与哈希，改不掉。
    """
    event = asdict(record.event)
    event["outcome"] = record.event.outcome.value
    event["sensitivity"] = record.event.sensitivity.value
    if not event.get("source"):
        event.pop("source", None)
    return {
        "seq": record.seq,
        "anchor": record.anchor,
        "event": event,
        "prev_hash": record.prev_hash,
    }


def compute_record_hash(record: AuditRecord) -> str:
    """计算一条记录的哈希（覆盖序号、事件内容与 prev_hash）。"""
    return hashlib.sha256(_canonical(event_to_payload(record)).encode("utf-8")).hexdigest()


def verify_chain(records: list[AuditRecord]) -> VerifyResult:
    """校验记录序列的哈希链，定位首个不一致位置。

    锚点记录（anchor=True）是被清理区段的占位：其内容不可重算，
    仅作为链的起点被信任，后续记录的 prev_hash 必须等于锚点哈希。
    """
    return verify_segment(records, expected_first_seq=None,
                          expected_first_prev_hash=None)


def verify_segment(
    records: list[AuditRecord],
    expected_first_seq: int | None = None,
    expected_first_prev_hash: str | None = None,
) -> VerifyResult:
    """校验一段连续记录（供离线导出独立核验）。

    - 期望起点均为 None：完整链校验，首条必须 seq=1，prev_hash=GENESIS，
      或首条为锚点（清理后的接续点）；
    - 给出期望起点：校验首条 seq 与其 prev_hash 是否匹配清单声明
      （用于导出区间从链中间开始、既非 genesis 也非锚点的情况）。
    锚点只能作为首条出现，其内容不可重算，仅信任其承载的哈希。
    """
    if not records:
        return VerifyResult(ok=True, reason="空链", checked=0)

    first = records[0]
    if first.anchor:
        expected_prev = first.record_hash
        expected_seq = first.seq + 1
        checked = 1
    elif expected_first_seq is not None:
        if first.seq != expected_first_seq:
            return VerifyResult(
                ok=False, first_bad_seq=first.seq,
                reason=(f"首条记录序号为 {first.seq}，清单声明区间起点为 "
                        f"{expected_first_seq}（导出内容与清单不一致，疑似删除/截断）"),
                checked=0,
            )
        if expected_first_prev_hash is not None and \
                first.prev_hash != expected_first_prev_hash:
            return VerifyResult(
                ok=False, first_bad_seq=first.seq,
                reason=(f"首条 prev_hash 与清单声明的接续点不一致：期望 "
                        f"{expected_first_prev_hash[:16]}…，实际 {first.prev_hash[:16]}…"),
                checked=0,
            )
        actual = compute_record_hash(first)
        if actual != first.record_hash:
            return VerifyResult(
                ok=False, first_bad_seq=first.seq,
                reason=(f"记录内容哈希不匹配：存储 {first.record_hash[:16]}…，"
                        f"重算 {actual[:16]}…（内容被改写）"),
                checked=0,
            )
        expected_prev = first.record_hash
        expected_seq = first.seq + 1
        checked = 1
    else:
        if first.seq != 1:
            return VerifyResult(
                ok=False, first_bad_seq=first.seq,
                reason=f"首条记录序号为 {first.seq}，既非 1 也非锚点（链头缺失）",
                checked=0,
            )
        expected_prev = GENESIS_HASH
        expected_seq = 1
        checked = 0

    for rec in records[1:] if (first.anchor or expected_first_seq is not None) else records:
        if rec.seq != expected_seq:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason=f"序号不连续：期望 {expected_seq}，实际 {rec.seq}（疑似删除/插入/乱序）",
                checked=checked,
            )
        if rec.anchor:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason="锚点记录只能出现在链首（疑似插入伪造锚点）",
                checked=checked,
            )
        if rec.prev_hash != expected_prev:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason=f"prev_hash 断裂：期望 {expected_prev[:16]}…，实际 {rec.prev_hash[:16]}…",
                checked=checked,
            )
        actual = compute_record_hash(rec)
        if actual != rec.record_hash:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason=f"记录内容哈希不匹配：存储 {rec.record_hash[:16]}…，重算 {actual[:16]}…（内容被改写）",
                checked=checked,
            )
        expected_prev = rec.record_hash
        expected_seq += 1
        checked += 1

    return VerifyResult(ok=True, reason="链校验通过", checked=checked)
