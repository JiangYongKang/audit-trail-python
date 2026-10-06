"""离线交付与核验测试：区间导出、锚点接续点、篡改定位、并发一致性、无敏感原文。"""
from __future__ import annotations

import threading

from audit.config import AuditConfig
from audit.export import (
    export_range,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from audit.models import AuditEvent, AuditRecord, Outcome, Sensitivity
from audit.service import AuditService

DAY = 86400.0


def _event(i: int, **kw) -> AuditEvent:
    defaults = {"actor": "alice", "action": "read", "target": "doc",
                "outcome": Outcome.SUCCESS, "occurred_at": 1000.0 + i,
                "idempotency_key": f"k{i}"}
    defaults.update(kw)
    return AuditEvent(**defaults)


def _svc(tmp_path, n: int, **kw) -> AuditService:
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path), **kw))
    for i in range(n):
        svc.record(_event(i))
    return svc


def _roundtrip(tmp_path, manifest) -> tuple:
    path = write_bundle(manifest, str(tmp_path / "bundle.json"))
    on_disk = read_bundle(path)
    return on_disk, path


def test_export_middle_range_verifies_offline(tmp_path):
    svc = _svc(tmp_path, 10)
    m = export_range(svc, seq_from=4, seq_to=7, now=12345.0)
    loaded, _ = _roundtrip(tmp_path, m)
    res = verify_bundle(loaded)
    print(f"[输入] 导出中间区间 seq 4..7（无服务/无原始存储） | "
          f"[判定] 记录 seq={[r.seq for r in loaded.records]} "
          f"manifest_ok={res.manifest_ok} 链校验={res.verify.ok} {res.reason}")
    assert [r.seq for r in loaded.records] == [4, 5, 6, 7]
    assert res.manifest_ok and res.verify.ok


def test_export_overlapping_cleaned_range_includes_anchor(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)  # seq 1..5 清理为锚点 seq=5
    m = export_range(svc, seq_from=3, seq_to=9, now=1.0)
    loaded, _ = _roundtrip(tmp_path, m)
    res = verify_bundle(loaded)
    seqs = [r.seq for r in loaded.records]
    print(f"[输入] seq1..5 已清理，导出请求 3..9 | [判定] 交付 seq={seqs} "
          f"cleaned={loaded.cleaned} 离线校验={res.verify.ok}")
    assert seqs[0] == 5 and loaded.records[0].anchor  # 接续点随附
    assert seqs[1:] == [6, 7, 8, 9]                   # 存活部分连续
    assert loaded.includes_anchor and loaded.cleaned is not None
    assert loaded.cleaned["removed_up_to_seq"] == 5
    assert res.manifest_ok and res.verify.ok


def test_export_fully_cleaned_range_delivers_anchor_only(tmp_path):
    svc = _svc(tmp_path, 10)
    svc.cleanup(1000.0 + 30 * DAY + 5)
    m = export_range(svc, seq_from=1, seq_to=4, now=1.0)
    loaded, _ = _roundtrip(tmp_path, m)
    res = verify_bundle(loaded)
    print(f"[输入] 导出区间 1..4 已全部清理 | [判定] 交付 seq={[r.seq for r in loaded.records]} "
          f"anchor={loaded.includes_anchor} {res.reason}")
    assert len(loaded.records) == 1 and loaded.records[0].anchor
    assert res.manifest_ok and res.verify.ok


def test_offline_tamper_insert_delete_reorder_located(tmp_path):
    svc = _svc(tmp_path, 8)
    base = export_range(svc, now=1.0)

    def bundle_records(records):
        m = export_range(svc, now=1.0)
        object.__setattr__(m, "records", records)
        object.__setattr__(m, "record_count", len(records))
        return verify_bundle(m)

    # 改写第 3 条内容
    tampered = list(base.records)
    r3 = tampered[2]
    tampered[2] = AuditRecord(
        seq=3, event=AuditEvent(actor="eve", action="read", target="doc",
                                outcome=Outcome.SUCCESS, occurred_at=1003.0),
        prev_hash=r3.prev_hash, record_hash=r3.record_hash)
    res = bundle_records(tampered)
    print(f"[输入] 离线文件改写 seq=3 actor | [判定] first_bad_seq={res.verify.first_bad_seq}")
    assert not res.verify.ok and res.verify.first_bad_seq == 3

    # 删除第 4 条
    deleted = [r for i, r in enumerate(base.records) if i != 3]
    res = bundle_records(deleted)
    print(f"[输入] 离线文件删除 seq=4 | [判定] first_bad_seq={res.verify.first_bad_seq}")
    assert not res.verify.ok and res.verify.first_bad_seq == 5

    # 在 seq=2 后重复插入一条 seq=2
    inserted = list(base.records[:2]) + [base.records[1]] + list(base.records[2:])
    res = bundle_records(inserted)
    print(f"[输入] 离线文件插入重复 seq=2 | [判定] first_bad_seq={res.verify.first_bad_seq}")
    assert not res.verify.ok and res.verify.first_bad_seq == 2

    # 交换 seq=2 与 seq=3
    reordered = list(base.records)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    res = bundle_records(reordered)
    print(f"[输入] 离线文件调序 seq2/3 | [判定] first_bad_seq={res.verify.first_bad_seq}")
    assert not res.verify.ok and res.verify.first_bad_seq == 3


def test_export_with_anchor_tamper_detected(tmp_path):
    svc = _svc(tmp_path, 6)
    svc.cleanup(1000.0 + 30 * DAY + 3)  # 锚点 seq=3 + 4,5,6
    m = export_range(svc, seq_from=2, seq_to=6, now=1.0)
    tampered = list(m.records)
    # 伪造锚点承载的哈希：后续 seq=4 的 prev_hash 必然对不上
    tampered[0] = AuditRecord(
        seq=tampered[0].seq, event=tampered[0].event,
        prev_hash=tampered[0].prev_hash, record_hash="f" * 64, anchor=True)
    object.__setattr__(m, "records", tampered)
    res = verify_bundle(m)
    print(f"[输入] 离线文件伪造锚点哈希 | [判定] first_bad_seq={res.verify.first_bad_seq} {res.reason}")
    assert not res.verify.ok and res.verify.first_bad_seq == 4


def test_manifest_record_count_mismatch_detected(tmp_path):
    svc = _svc(tmp_path, 5)
    m = export_range(svc, now=1.0)
    object.__setattr__(m, "record_count", 99)
    res = verify_bundle(m)
    print(f"[输入] 清单 record_count 改为 99 | [判定] manifest_ok={res.manifest_ok} {res.reason}")
    assert not res.manifest_ok


def test_export_concurrent_writes_and_cleanup_is_consistent(tmp_path):
    svc = _svc(tmp_path, 100)
    results: list = []
    errors: list[Exception] = []

    def exporter(idx: int) -> None:
        try:
            m = export_range(svc, seq_from=1, seq_to=500, now=float(idx))
            res = verify_bundle(m)  # 导出物自校验必须立刻成立
            if not (res.manifest_ok and res.verify.ok):
                errors.append(AssertionError(f"导出 {idx} 自校验失败: {res.reason}"))
            results.append(m)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=exporter, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for i in range(100, 160):
        svc.record(_event(i))
    svc.cleanup(1000.0 + 30 * DAY + 120)
    for t in threads:
        t.join()

    print(f"[输入] 5 个导出与 60 条写入、1 轮清理并发 | "
          f"[判定] 成功导出={len(results)} 错误={len(errors)} 全部自校验通过={not errors}")
    assert not errors
    for m in results:
        seqs = [r.seq for r in m.records if not r.anchor]
        assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))


def test_export_contains_no_raw_secrets(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    svc.record(AuditEvent(
        actor="alice", action="login", target="auth", outcome=Outcome.SUCCESS,
        sensitivity=Sensitivity.HIGH, occurred_at=1000.0,
        details={"password": "raw-password-999", "token": "raw-token-zzz",
                 "ip": "8.8.8.8", "note": "hello"}))
    m = export_range(svc, now=1.0)
    _, path = _roundtrip(tmp_path, m)
    raw = path.read_text(encoding="utf-8")
    print(f"[输入] 导出含 HIGH 事件（password/token/note 原文）的区间 | "
          f"[判定] 文件含 password 原文={'raw-password-999' in raw} "
          f"含 token 原文={'raw-token-zzz' in raw}")
    assert "raw-password-999" not in raw
    assert "raw-token-zzz" not in raw
    assert "8.8.8.8" in raw  # 白名单字段保留
