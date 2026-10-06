"""离线导出与核验。

导出：
- 按序号区间或时间区间选择记录（序号优先），导出包自包含：记录 + 元信息 + 包摘要。
- 若区间起点之前发生过保留期清理，把链首的接续锚点一并带上，使导出的那段
  在离线机器上能自证连续；否则带链头记录（prev_hash=GENESIS）。
- 一致性：导出先在存储锁内硬链接一份段文件快照（与写入/清理互斥，不会拿到
  半截或错序结果），再在快照上慢慢筛选，数据量大也不长期拖住在线服务。
- 导出内容就是落盘内容（已脱敏），脱敏前原文不会进入导出包。

离线核验（verify_offline）只依赖标准库，不需要服务、不需要原始存储：
1. 先核对包摘要 bundle_digest（防止包级别的增删/替换）；
2. 再校验哈希链，改写/插入/删除/乱序都会给出第一个出问题的序号。
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# 支持“拷走 audit/ 目录后在无服务机器上 python audit/export.py verify …”：
# 直接以脚本方式运行时没有包上下文，引导把上级目录加入 sys.path 并用绝对导入。
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from audit.hashchain import GENESIS_HASH, compute_record_hash
    from audit.models import AuditRecord, VerifyResult
    from audit.service import AuditService
    from audit.store import record_from_line, record_to_line
else:
    from .hashchain import GENESIS_HASH, compute_record_hash
    from .models import AuditRecord, VerifyResult
    from .service import AuditService
    from .store import record_from_line, record_to_line

BUNDLE_VERSION = 1
_RECORD_DIGEST_PREFIX = "records:"


class ExportError(Exception):
    """导出参数或导出包相关错误。"""


@dataclass(frozen=True)
class ExportRequest:
    """导出区间：按序号（优先）或时间范围选择，二者至少给一个。"""

    start_seq: int | None = None
    end_seq: int | None = None
    start_time: float | None = None
    end_time: float | None = None


@dataclass(frozen=True)
class ExportBundle:
    """自包含导出包：记录均为落盘的已脱敏内容；首条可能是清理接续锚点。"""

    manifest: dict
    records: list[AuditRecord]

    def to_json(self) -> str:
        return json.dumps({"manifest": self.manifest,
                           "records": [_record_to_dict(r) for r in self.records]},
                          sort_keys=True, ensure_ascii=False, indent=2)

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")
        return p

    @staticmethod
    def from_json(text: str) -> ExportBundle:
        try:
            payload = json.loads(text)
            manifest = payload["manifest"]
            records = [_record_from_dict(d) for d in payload["records"]]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ExportError(f"导出包格式无法解析: {exc}") from exc
        return ExportBundle(manifest=manifest, records=records)

    @staticmethod
    def read(path: str | Path) -> ExportBundle:
        return ExportBundle.from_json(Path(path).read_text(encoding="utf-8"))


def _record_to_dict(record: AuditRecord) -> dict:
    return json.loads(record_to_line(record))


def _record_from_dict(d: dict) -> AuditRecord:
    return record_from_line(json.dumps(d, ensure_ascii=False))


def records_digest(records: list[AuditRecord]) -> str:
    """对导出的有序记录集合计算摘要（覆盖每条记录的规范行）。"""
    h = hashlib.sha256()
    for rec in records:
        h.update(record_to_line(rec).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def _load_snapshot(service: AuditService) -> list[AuditRecord]:
    """读取一致性快照（存储在锁内瞬时硬链接段文件，之后慢慢读不长时间占锁）。"""
    return service.snapshot_records()


def export_records(service: AuditService, req: ExportRequest,
                   exported_at: float | None = None) -> ExportBundle:
    """按区间导出；与写入/清理并发时拿到的仍是一份完整、有序、可校验的快照。"""
    if req.start_seq is None and req.end_seq is None and \
            req.start_time is None and req.end_time is None:
        raise ExportError("必须指定序号区间或时间区间")

    snapshot = _load_snapshot(service)
    anchor = snapshot[0] if snapshot and snapshot[0].anchor else None
    non_anchor = [r for r in snapshot if not r.anchor]

    if req.start_seq is not None or req.end_seq is not None:
        lo = req.start_seq if req.start_seq is not None else 1
        hi = req.end_seq if req.end_seq is not None else (
            non_anchor[-1].seq if non_anchor else 0)
        if lo > hi:
            raise ExportError(f"区间非法：start_seq({lo}) > end_seq({hi})")
        selected = [r for r in non_anchor if lo <= r.seq <= hi]
    else:
        st = req.start_time if req.start_time is not None else float("-inf")
        et = req.end_time if req.end_time is not None else float("inf")
        selected = [r for r in non_anchor if st <= r.event.occurred_at <= et]

    if not selected:
        raise ExportError("指定区间内没有可导出的记录")

    start_seq, end_seq = selected[0].seq, selected[-1].seq
    # 连续性前提：哈希链只能对“连续区段”自证。
    # 区间起点必须紧跟链头（seq=1 或锚点之后第一条），否则中间跳过了仍在
    # 保留期的记录，导出段无法独立校验，明确报错而不是产出断裂的包。
    expected_first = (anchor.seq + 1) if anchor is not None else 1
    if start_seq != expected_first:
        raise ExportError(
            f"导出区间起点 seq={start_seq} 与链头不连续（最早可连续导出的序号 "
            f"为 {expected_first}）；哈希链只支持连续区段导出，请调整区间起点"
        )
    # 区间起点之前若有清理锚点，一并带上作为离线核验的可信接续点
    prefix = [anchor] if anchor is not None and anchor.seq < start_seq else []
    records = prefix + selected

    # 子链凭据：起点记录的 prev_hash 必须等于区间前一条（锚点/GENESIS）的哈希。
    # 该值由导出方从存储读出并写入清单，由 bundle_digest 覆盖防篡改。
    # 连续性校验已保证：有锚点时起点必在锚点之后，否则起点必为 seq=1。
    start_prev_hash = selected[0].prev_hash
    chain_basis = f"anchor:{anchor.seq}" if prefix else "genesis"

    exported_at = exported_at if exported_at is not None else time.time()
    digest = records_digest(records)
    manifest = {
        "version": BUNDLE_VERSION,
        "exported_at": exported_at,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "count": len(selected),
        "includes_anchor": bool(prefix),
        "anchor_seq": prefix[0].seq if prefix else None,
        "chain_basis": chain_basis,
        "start_prev_hash": start_prev_hash,
        "genesis_hash": GENESIS_HASH,
        "bundle_digest": f"{_RECORD_DIGEST_PREFIX}{digest}",
    }
    return ExportBundle(manifest=manifest, records=records)


def verify_subchain(records: list[AuditRecord], start_prev_hash: str,
                    anchor_seq: int | None) -> VerifyResult:
    """校验一段导出子链：从可信的起始哈希/锚点开始检查连续性与每条内容哈希。"""
    if not records:
        return VerifyResult(ok=True, reason="空区间", checked=0)

    if records[0].anchor:
        anchor = records[0]
        if anchor_seq is not None and anchor.seq != anchor_seq:
            return VerifyResult(
                ok=False, first_bad_seq=anchor.seq,
                reason=f"锚点序号与清单不一致：清单 {anchor_seq}，实际 {anchor.seq}")
        expected_prev = anchor.record_hash
        expected_seq = anchor.seq + 1
        checked = 1
        body = records[1:]
    else:
        if start_prev_hash != records[0].prev_hash:
            return VerifyResult(
                ok=False, first_bad_seq=records[0].seq,
                reason="起始记录 prev_hash 与清单中的链头凭据不一致（链头被改动）")
        expected_prev = records[0].record_hash
        expected_seq = records[0].seq + 1
        if compute_record_hash(records[0]) != records[0].record_hash:
            return VerifyResult(
                ok=False, first_bad_seq=records[0].seq,
                reason="起始记录内容哈希不匹配（内容被改写）")
        checked = 1
        body = records[1:]

    for rec in body:
        if rec.anchor:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason="锚点记录只能出现在导出段开头（疑似插入伪造锚点）",
                checked=checked)
        if rec.seq != expected_seq:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason=f"序号不连续：期望 {expected_seq}，实际 {rec.seq}（疑似删除/插入/乱序）",
                checked=checked)
        if rec.prev_hash != expected_prev:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason=f"prev_hash 断裂：期望 {expected_prev[:16]}…，实际 {rec.prev_hash[:16]}…",
                checked=checked)
        if compute_record_hash(rec) != rec.record_hash:
            return VerifyResult(
                ok=False, first_bad_seq=rec.seq,
                reason="记录内容哈希不匹配（内容被改写）", checked=checked)
        expected_prev = rec.record_hash
        expected_seq += 1
        checked += 1
    return VerifyResult(ok=True, reason="导出段链校验通过", checked=checked)


def verify_offline(bundle: ExportBundle) -> VerifyResult:
    """离线核验：先查包摘要，再查哈希链，定位第一个出问题的序号。"""
    manifest = bundle.manifest
    records = bundle.records
    if not records:
        return VerifyResult(ok=False, reason="导出包为空，无法核验")

    expected = manifest.get("bundle_digest", "")
    if not expected.startswith(_RECORD_DIGEST_PREFIX):
        return VerifyResult(ok=False, reason="清单缺少 bundle_digest（包可能被伪造）")
    actual = _RECORD_DIGEST_PREFIX + records_digest(records)
    start_prev = manifest.get("start_prev_hash", "")
    anchor_seq = manifest.get("anchor_seq")
    if actual != expected:
        # 包级别已被改动（增/删/替换记录或改清单）：仍继续链校验以定位首个问题序号
        chain = verify_subchain(records, start_prev, anchor_seq)
        reason = "导出包摘要不匹配（包内容被增删或替换）"
        if not chain.ok:
            reason += f"；首个断裂位置 seq={chain.first_bad_seq}：{chain.reason}"
        return VerifyResult(ok=False, first_bad_seq=chain.first_bad_seq,
                            reason=reason, checked=chain.checked)

    return verify_subchain(records, start_prev, anchor_seq)


def _main(argv: list[str] | None = None) -> int:
    """离线核验命令行（仅依赖标准库）：

        python audit/export.py verify <导出文件.json>

    退出码 0=校验通过，1=校验失败或文件无法解析，2=用法错误。
    """
    import sys

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "verify":
        print("用法: python audit/export.py verify <导出文件.json>")
        return 2
    try:
        bundle = ExportBundle.read(args[1])
        result = verify_offline(bundle)
    except ExportError as exc:
        print(f"[离线核验] 导出包无法解析: {exc}")
        return 1
    m = bundle.manifest
    print(f"[离线核验] 区间 seq={m.get('start_seq')}..{m.get('end_seq')} "
          f"条数={m.get('count')} 含清理锚点={m.get('includes_anchor')} "
          f"导出时刻={m.get('exported_at')}")
    if result.ok:
        print(f"[离线核验] 通过：{result.reason}（核验记录 {result.checked} 条）")
        return 0
    print(f"[离线核验] 失败：首个问题位置 seq={result.first_bad_seq}；{result.reason}")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
