"""离线导出与核验测试：区间导出自证连续（含清理锚点）、离线校验、
改写/插入/删除/乱序的首个位置定位、导出不含脱敏原文、并发写入清理下一致性。"""
from __future__ import annotations

import json
import threading

from audit.config import AuditConfig
from audit.export import ExportBundle, ExportRequest, export_records, verify_offline
from audit.models import AuditEvent, AuditRecord, Outcome, Sensitivity
from audit.service import AuditService
from audit.store import record_to_line

DAY = 86400.0


def _svc(tmp_path, **kw) -> AuditService:
    return AuditService(AuditConfig(storage_dir=str(tmp_path), **kw))


def _event(ts: float, key: str | None = None,
           sensitivity: Sensitivity = Sensitivity.LOW,
           details: dict | None = None) -> AuditEvent:
    return AuditEvent(actor="alice", action="read", target="doc",
                      outcome=Outcome.SUCCESS, correlation_id="c",
                      idempotency_key=key, sensitivity=sensitivity,
                      occurred_at=ts, source="http", details=details or {})


def _bundle_records_json(bundle: ExportBundle) -> list[dict]:
    return [json.loads(record_to_line(r)) for r in bundle.records]


def test_export_range_and_offline_verify(tmp_path):
    svc = _svc(tmp_path)
    for i in range(6):
        svc.record(_event(ts=100.0 + i, key=f"k{i}"))
    bundle = export_records(svc, ExportRequest(start_seq=1, end_seq=4))
    result = verify_offline(bundle)
    print(f"[输入] 导出 seq 1-4（无清理，链头从 GENESIS 接续）| "
          f"[判定] 导出 seq={[r.seq for r in bundle.records]} "
          f"含锚点={bundle.manifest['includes_anchor']} 凭据={bundle.manifest['chain_basis']} "
          f"离线校验={result.ok}")
    assert [r.seq for r in bundle.records] == [1, 2, 3, 4]
    assert bundle.manifest["includes_anchor"] is False
    assert result.ok


def test_export_middle_subrange_rejected(tmp_path):
    """未清理过却导出跳过链头的中间段：无法自证连续，必须明确报错。"""
    from audit.export import ExportError
    svc = _svc(tmp_path)
    for i in range(6):
        svc.record(_event(ts=100.0 + i, key=f"k{i}"))
    try:
        export_records(svc, ExportRequest(start_seq=3, end_seq=5))
        raised = None
    except ExportError as exc:
        raised = exc
    print(f"[输入] 无锚点时导出中间段 seq3-5 | [判定] 拒绝={raised is not None}（{raised}）")
    assert raised is not None


def test_export_includes_compaction_anchor(tmp_path):
    """区间起点之前被清理过：锚点一并导出，离线仍可自证连续。"""
    from audit.models import Sensitivity
    cfg = AuditConfig(storage_dir=str(tmp_path),
                      retention_days={Sensitivity.LOW: 10.0,
                                      Sensitivity.MEDIUM: 10.0,
                                      Sensitivity.HIGH: 10.0})
    svc = AuditService(cfg)
    t0 = 10_000_000.0
    for i in range(8):
        svc.record(_event(ts=t0 + i, key=f"k{i}"))
    svc.cleanup(t0 + 10 * DAY + 4)  # t0..t0+3 过期（10 天 = t0+10d 之前）-> 锚点 seq=4
    anchor = svc.records()[0]

    bundle = export_records(svc, ExportRequest(start_time=t0 + 4, end_time=t0 + 7))
    seqs = [r.seq for r in bundle.records]
    result = verify_offline(bundle)
    print(f"[输入] 清理后导出 t0+5d 之后的记录 | [判定] 导出 seq={seqs} "
          f"首条为锚点={bundle.records[0].anchor} 锚点seq={anchor.seq} 离线校验={result.ok}")
    assert bundle.records[0].anchor
    assert bundle.records[0].seq == anchor.seq
    assert seqs[0] == anchor.seq and seqs[1] > anchor.seq
    assert bundle.manifest["includes_anchor"] is True
    assert result.ok  # 有接续锚点，导出段可独立校验


def test_offline_verify_from_file_on_machine_without_service(tmp_path):
    """只凭导出文件 + 标准库即可完成离线核验（不触碰服务与原始存储）。"""
    svc = _svc(tmp_path)
    for i in range(4):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    out = tmp_path / "export.json"
    export_records(svc, ExportRequest(start_seq=1, end_seq=4)).write(out)

    # 模拟离线机器：仅从文件重建包并核验
    bundle = ExportBundle.read(out)
    result = verify_offline(bundle)
    print(f"[输入] 仅读取导出文件离线核验（无服务/无原始存储）| "
          f"[判定] ok={result.ok} checked={result.checked} 条数={bundle.manifest['count']}")
    assert result.ok and result.checked == 4


def test_offline_tamper_insert_delete_reorder_located(tmp_path):
    svc = _svc(tmp_path)
    for i in range(6):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    bundle = export_records(svc, ExportRequest(start_seq=1, end_seq=6))

    def check(name: str, mutate) -> None:
        recs = list(bundle.records)
        recs = mutate(recs)
        bad = ExportBundle(manifest=dict(bundle.manifest), records=recs)
        result = verify_offline(bad)
        print(f"[输入] 离线包被{name} | [判定] ok={result.ok} "
              f"first_bad_seq={result.first_bad_seq} 原因={result.reason}")
        assert not result.ok
        return result

    # 改写第 3 条内容（但保留原 record_hash）
    def tamper_content(recs):
        evil = AuditEvent(actor="eve", action="read", target="doc",
                          outcome=Outcome.SUCCESS, occurred_at=2.0)
        recs[2] = AuditRecord(seq=3, event=evil, prev_hash=recs[2].prev_hash,
                              record_hash=recs[2].record_hash)
        return recs

    r = check("改写 seq=3 内容", tamper_content)
    assert r.first_bad_seq == 3

    r = check("删除 seq=3", lambda recs: recs[:2] + recs[3:])
    assert r.first_bad_seq == 4

    r = check("在 seq=2 后插入一条重复 seq=2",
              lambda recs: recs[:2] + [recs[1]] + recs[2:])
    assert r.first_bad_seq == 2

    r = check("交换 seq=2 与 seq=3", lambda recs: _swap(recs, 1, 2))
    assert r.first_bad_seq == 3


def _swap(recs, i, j):
    recs = list(recs)
    recs[i], recs[j] = recs[j], recs[i]
    return recs


def test_tamper_with_recomputed_digest_still_located(tmp_path):
    """即使攻击者重算包摘要/哈希链，首个断裂位置仍由链结构暴露。"""
    svc = _svc(tmp_path)
    for i in range(5):
        svc.record(_event(ts=float(i), key=f"k{i}"))
    bundle = export_records(svc, ExportRequest(start_seq=1, end_seq=5))
    recs = list(bundle.records)
    evil = AuditEvent(actor="eve", action="read", target="doc",
                      outcome=Outcome.SUCCESS, occurred_at=2.0)
    recs[2] = AuditRecord(seq=3, event=evil, prev_hash=recs[2].prev_hash,
                          record_hash=recs[2].record_hash)
    # 攻击者只重算包摘要，无法重算 seq3 的内容哈希（密钥不在包内，链结构揭示问题）
    from audit.export import records_digest
    manifest = dict(bundle.manifest)
    manifest["bundle_digest"] = "records:" + records_digest(recs)
    result = verify_offline(ExportBundle(manifest=manifest, records=recs))
    print(f"[输入] 改写 seq3 且重算包摘要 | [判定] first_bad_seq={result.first_bad_seq} "
          f"原因={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 3


def test_export_contains_no_raw_secret(tmp_path):
    svc = _svc(tmp_path)
    secret = "p@ss-导出绝密"
    svc.record(_event(ts=1.0, sensitivity=Sensitivity.HIGH,
                      details={"password": secret, "email": "spy@x.cn"}, key="k1"))
    svc.record(_event(ts=2.0, key="k2"))
    out = tmp_path / "export.json"
    export_records(svc, ExportRequest(start_seq=1, end_seq=2)).write(out)
    text = out.read_text(encoding="utf-8")
    result = verify_offline(ExportBundle.read(out))
    print(f"[输入] HIGH 含密事件导出为文件 | [判定] 文件无原文={secret not in text} "
          f"离线校验={result.ok}")
    assert secret not in text
    assert result.ok


def test_export_concurrent_with_writes_and_cleanup(tmp_path):
    """导出与写入/清理并发：每次导出都完整、有序、可离线校验。"""
    svc = _svc(tmp_path)
    t0 = 11_000_000.0
    for i in range(30):
        svc.record(_event(ts=t0 + i, key=f"init{i}"))

    errors: list[str] = []

    def exporter() -> None:
        for k in range(30):
            try:
                bundle = export_records(svc, ExportRequest(start_time=0.0))
                seqs = [r.seq for r in bundle.records]
                result = verify_offline(bundle)
                if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
                    errors.append(f"第{k}次导出乱序/重复")
                if not result.ok:
                    errors.append(f"第{k}次导出离线校验失败: {result.reason}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"第{k}次导出异常: {exc}")

    et = threading.Thread(target=exporter)
    et.start()

    def writer() -> None:
        for i in range(30):
            svc.record(_event(ts=t0 + 100 + i, key=f"new{i}"))

    wt = threading.Thread(target=writer)
    wt.start()
    for step in range(8):
        svc.cleanup(t0 + 30 * DAY + step * 2)
    wt.join()
    et.join()

    final = export_records(svc, ExportRequest(start_time=0.0))
    print(f"[输入] 30 次导出与写入+8 轮清理并发 | [判定] 错误数={len(errors)} "
          f"最终导出 seq 头部={[r.seq for r in final.records][:3]} 离线校验={verify_offline(final).ok} "
          f"错误样例={errors[:1]}")
    assert not errors
    assert verify_offline(final).ok
