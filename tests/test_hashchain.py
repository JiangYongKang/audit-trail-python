"""哈希链校验测试：篡改 / 插入 / 删除 / 乱序 / 锚点连续性。"""
from __future__ import annotations

from audit.hashchain import GENESIS_HASH, compute_record_hash, verify_chain
from audit.models import AuditEvent, AuditRecord, Outcome


def _mk(seq: int, prev: str, actor: str = "alice", ts: float = 1.0) -> AuditRecord:
    event = AuditEvent(actor=actor, action="read", target="doc",
                       outcome=Outcome.SUCCESS, correlation_id=f"c{seq}",
                       occurred_at=ts)
    draft = AuditRecord(seq=seq, event=event, prev_hash=prev, record_hash="")
    return AuditRecord(seq=seq, event=event, prev_hash=prev,
                       record_hash=compute_record_hash(draft))


def _chain(n: int) -> list[AuditRecord]:
    out, prev = [], GENESIS_HASH
    for i in range(1, n + 1):
        rec = _mk(i, prev)
        out.append(rec)
        prev = rec.record_hash
    return out


def test_clean_chain_passes():
    chain = _chain(5)
    result = verify_chain(chain)
    print(f"[输入] 5 条正常记录 | [判定] ok={result.ok} checked={result.checked}")
    assert result.ok and result.checked == 5


def test_tampered_content_located():
    chain = _chain(5)
    evil = AuditEvent(actor="eve", action="read", target="doc",
                      outcome=Outcome.SUCCESS, correlation_id="c3", occurred_at=1.0)
    chain[2] = AuditRecord(seq=3, event=evil, prev_hash=chain[2].prev_hash,
                           record_hash=chain[2].record_hash)
    result = verify_chain(chain)
    print(f"[输入] 第 3 条 actor 被改写为 eve | [判定] first_bad_seq={result.first_bad_seq} 原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 3
    assert "哈希不匹配" in result.reason


def test_deleted_record_located():
    chain = _chain(5)
    del chain[2]  # 删除第 3 条
    result = verify_chain(chain)
    print(f"[输入] 删除 seq=3 | [判定] first_bad_seq={result.first_bad_seq} 原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 4
    assert "序号不连续" in result.reason


def test_inserted_record_located():
    chain = _chain(3)
    chain.insert(1, chain[1])  # 重复插入 seq=2
    result = verify_chain(chain)
    print(f"[输入] 在 seq=2 后重复插入一条 | [判定] first_bad_seq={result.first_bad_seq} 原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 2
    assert "序号不连续" in result.reason


def test_reordered_records_located():
    chain = _chain(4)
    chain[1], chain[2] = chain[2], chain[1]  # 交换 seq 2 和 3
    result = verify_chain(chain)
    print(f"[输入] 交换 seq=2 与 seq=3 | [判定] first_bad_seq={result.first_bad_seq} 原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 3


def test_anchor_chain_continuity():
    """清理后锚点 + 后续记录，校验必须保持通过。"""
    chain = _chain(5)
    anchor = AuditRecord(
        seq=3,
        event=AuditEvent(actor="__retention__", action="__compact__",
                         target="__audit_log__", outcome=Outcome.SUCCESS,
                         occurred_at=99.0),
        prev_hash=chain[2].prev_hash,
        record_hash=chain[2].record_hash,
        anchor=True,
    )
    compacted = [anchor, chain[3], chain[4]]
    result = verify_chain(compacted)
    print(f"[输入] 锚点(seq=3)+seq4+seq5 | [判定] ok={result.ok} 原因={result.reason}")
    assert result.ok


def test_wrong_anchor_hash_detected():
    chain = _chain(5)
    anchor = AuditRecord(
        seq=3,
        event=AuditEvent(actor="__retention__", action="__compact__",
                         target="__audit_log__", outcome=Outcome.SUCCESS,
                         occurred_at=99.0),
        prev_hash=chain[2].prev_hash,
        record_hash="f" * 64,  # 伪造锚点哈希
        anchor=True,
    )
    result = verify_chain([anchor, chain[3], chain[4]])
    print(f"[输入] 锚点哈希被伪造 | [判定] first_bad_seq={result.first_bad_seq} 原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 4
    assert "prev_hash 断裂" in result.reason
