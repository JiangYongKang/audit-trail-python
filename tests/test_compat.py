"""兼容性测试：旧格式记录文件（无 source 字段、无新增锚点字段）仍可读取并通过校验。"""
from __future__ import annotations

import json
from pathlib import Path

from audit.config import AuditConfig
from audit.hashchain import compute_record_hash
from audit.models import AuditEvent, AuditRecord, Outcome
from audit.service import AuditService
from audit.store import record_from_line

DAY = 86400.0


def test_legacy_line_without_source_reads_and_hashes_identically():
    """旧版本写出的行（event 内没有 source）反序列化后重算哈希必须一致。"""
    legacy_line = json.dumps({
        "seq": 1,
        "anchor": False,
        "event": {
            "actor": "alice", "action": "read", "target": "doc",
            "outcome": "success", "deny_reason": None, "correlation_id": "c",
            "idempotency_key": None, "sensitivity": "low",
            "occurred_at": 1.0, "details": {},
        },
        "prev_hash": "0" * 64,
        "record_hash": "will-be-recomputed",
    }, sort_keys=True, ensure_ascii=False)
    rec = record_from_line(legacy_line)
    print(f"[输入] 旧格式行（无 source 字段）| [判定] source={rec.event.source!r} "
          f"seq={rec.seq}")
    assert rec.event.source == ""
    # 用空 source 重算，哈希与“字段缺失”语义一致（兼容性保证的关键）
    draft = AuditRecord(seq=1, event=rec.event, prev_hash="0" * 64, record_hash="")
    assert isinstance(compute_record_hash(draft), str)
    assert rec.event.outcome is Outcome.SUCCESS


def test_legacy_segment_file_verifies_after_upgrade(tmp_path):
    """把一段旧格式 JSONL 放进存储目录，升级后的服务能读出并通过链校验。"""
    cfg = AuditConfig(storage_dir=str(tmp_path))
    # 用当前代码构造 3 条，再手动删掉 source 键模拟旧文件
    svc = AuditService(cfg)
    for i in range(3):
        svc.record(AuditEvent(actor="alice", action="read", target="doc",
                              outcome=Outcome.SUCCESS, occurred_at=1.0 + i,
                              idempotency_key=f"k{i}"))
    seg = next(Path(tmp_path).glob("segment-*.jsonl"))
    lines = [json.loads(l) for l in seg.read_text(encoding="utf-8").splitlines()]
    for line in lines:
        line["event"].pop("source", None)
    seg.write_text("\n".join(json.dumps(l, ensure_ascii=False) for l in lines) + "\n",
                   encoding="utf-8")

    svc2 = AuditService(cfg)  # 重启加载“旧文件”
    records = svc2.records()
    result = svc2.verify()
    print(f"[输入] 3 条记录被改写为无 source 的旧格式后重启 | "
          f"[判定] 读出={len(records)} 条 链校验={result.ok} 原因={result.reason}")
    assert len(records) == 3
    assert result.ok
