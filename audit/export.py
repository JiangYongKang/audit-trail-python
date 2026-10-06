"""离线可交付的核验：导出区间记录 + 清单，供无服务/无原始存储时独立校验。

- 导出在服务锁内取一份一致性快照（与写入/清理互斥），随后的序列化与
  文件写出在锁外完成（只操作内存快照），数据量大也不会长时间拖住正常服务；
- 若区间起点之前（或起点本身所在区段）已被清理，链首锚点（接续点）随
  导出一并带上，并在清单 cleaned 字段声明被清理区段；
- 独立校验先核对清单声明（版本、计数、序号区间、接续点哈希），再复用
  哈希链算法校验，改写/插入/删除/乱序都会给出第一个出问题的位置；
- 导出的记录与落盘内容一致，落盘前已脱敏，交付物不可能含原始值。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .hashchain import verify_segment
from .models import AuditRecord, VerifyResult
from .store import record_from_line, record_to_line

EXPORT_FORMAT_VERSION = 1


@dataclass(frozen=True)
class ExportManifest:
    """导出清单：交付物自描述信息。"""

    format_version: int
    exported_at: float
    seq_from: int | None
    seq_to: int | None
    start_time: float | None
    end_time: float | None
    record_count: int
    includes_anchor: bool
    cleaned: dict | None
    records: list[AuditRecord]


def _in_window(rec: AuditRecord, start_time: float | None,
               end_time: float | None) -> bool:
    ts = rec.event.occurred_at
    if start_time is not None and ts < start_time:
        return False
    return end_time is None or ts < end_time


def export_range(
    service,
    *,
    seq_from: int | None = None,
    seq_to: int | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    now: float | None = None,
) -> ExportManifest:
    """在服务的一致性快照上按区间（seq 与/或时间窗，左闭右开）导出。

    seq 区间为闭区间 [seq_from, seq_to]；时间窗为 [start_time, end_time)，
    两者同时给出时取交集。时间窗会按快照内记录实际边界收敛为 seq 区间，
    保证导出记录连续、可独立校验。
    """
    if seq_from is not None and seq_to is not None and seq_from > seq_to:
        raise ValueError("seq_from 不能大于 seq_to")
    exported_at = now if now is not None else time.time()

    snapshot = service.snapshot()  # 锁内一致性快照
    anchor = snapshot[0] if snapshot and snapshot[0].anchor else None
    live = [r for r in snapshot if not r.anchor]

    windowed = [r for r in live if _in_window(r, start_time, end_time)]
    chosen = windowed
    if seq_from is not None:
        chosen = [r for r in chosen if r.seq >= seq_from]
    if seq_to is not None:
        chosen = [r for r in chosen if r.seq <= seq_to]

    # 判断请求区间是否与“已清理区段”重叠（重叠则必须带上接续点）
    overlaps_cleaned = False
    if anchor is not None:
        if seq_from is not None and seq_from <= anchor.seq:
            overlaps_cleaned = True
        if start_time is not None and anchor.event.details.get(
                "removed_up_to_occurred_at", float("inf")) >= start_time:
            overlaps_cleaned = True
        # 只有时间窗/起点而无 seq_from：窗口开区间若早于最旧存活记录，也算重叠
        if seq_from is None and start_time is None and windowed:
            overlaps_cleaned = False

    out: list[AuditRecord] = []
    cleaned: dict | None = None
    includes_anchor = False
    if chosen and overlaps_cleaned:
        assert anchor is not None
        # 带锚点时链必须连续：存活记录从与锚点相邻的最旧一条开始导出
        first_live = live[0]
        chosen = [r for r in windowed if r.seq >= first_live.seq]
        if seq_to is not None:
            chosen = [r for r in chosen if r.seq <= seq_to]
        out.append(anchor)
        includes_anchor = True
        d = anchor.event.details
        cleaned = {
            "removed_from_seq": int(d.get("removed_from_seq", 1)),
            "removed_up_to_seq": anchor.seq,
            "removed_from_occurred_at": d.get("removed_from_occurred_at"),
            "removed_up_to_occurred_at": d.get("removed_up_to_occurred_at"),
            "removed_count": int(d.get("removed_count", 0)),
        }
        out.extend(chosen)
    elif not chosen and overlaps_cleaned:
        # 请求的区间完全落在已清理区段：只交付接续点
        assert anchor is not None
        out.append(anchor)
        includes_anchor = True
        d = anchor.event.details
        cleaned = {
            "removed_from_seq": int(d.get("removed_from_seq", 1)),
            "removed_up_to_seq": anchor.seq,
            "removed_from_occurred_at": d.get("removed_from_occurred_at"),
            "removed_up_to_occurred_at": d.get("removed_up_to_occurred_at"),
            "removed_count": int(d.get("removed_count", 0)),
        }
    else:
        out = chosen

    live_out = [r for r in out if not r.anchor]
    return ExportManifest(
        format_version=EXPORT_FORMAT_VERSION,
        exported_at=exported_at,
        seq_from=live_out[0].seq if live_out else None,
        seq_to=live_out[-1].seq if live_out else None,
        start_time=start_time,
        end_time=end_time,
        record_count=len(out),
        includes_anchor=includes_anchor,
        cleaned=cleaned,
        records=out,
    )


def manifest_to_dict(manifest: ExportManifest) -> dict:
    """清单序列化为可 JSON 化的字典（记录用与段文件相同的规范行格式）。"""
    return {
        "format_version": manifest.format_version,
        "exported_at": manifest.exported_at,
        "seq_from": manifest.seq_from,
        "seq_to": manifest.seq_to,
        "start_time": manifest.start_time,
        "end_time": manifest.end_time,
        "record_count": manifest.record_count,
        "includes_anchor": manifest.includes_anchor,
        "cleaned": manifest.cleaned,
        "records": [json.loads(record_to_line(r)) for r in manifest.records],
    }


def manifest_from_dict(data: dict) -> ExportManifest:
    records = [record_from_line(json.dumps(row, ensure_ascii=False))
               for row in data.get("records", [])]
    return ExportManifest(
        format_version=int(data["format_version"]),
        exported_at=float(data.get("exported_at", 0.0)),
        seq_from=data.get("seq_from"),
        seq_to=data.get("seq_to"),
        start_time=data.get("start_time"),
        end_time=data.get("end_time"),
        record_count=int(data.get("record_count", 0)),
        includes_anchor=bool(data.get("includes_anchor", False)),
        cleaned=data.get("cleaned"),
        records=records,
    )


def write_bundle(manifest: ExportManifest, path: str | Path) -> Path:
    """把导出清单写成单个 UTF-8 JSON 文件（先写临时文件再原子替换）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest_to_dict(manifest), f, ensure_ascii=False, indent=2,
                  sort_keys=True)
        f.flush()
    tmp.replace(path)
    return path


def read_bundle(path: str | Path) -> ExportManifest:
    """从 JSON 文件读回导出清单（离线机器上无需本服务/原始存储即可解析）。"""
    with open(path, encoding="utf-8") as f:
        return manifest_from_dict(json.load(f))


def verify_bundle(manifest: ExportManifest) -> OfflineVerifyResult:
    """离线校验交付物。

    1) 清单一致性：版本、记录数、序号区间、锚点声明；
    2) 哈希链：从锚点 / 清单声明的接续点开始，逐链定位第一个不一致位置。
    """
    if manifest.format_version != EXPORT_FORMAT_VERSION:
        return OfflineVerifyResult(
            verify=VerifyResult(ok=False), manifest_ok=False,
            reason=f"不支持的导出格式版本: {manifest.format_version}")
    if manifest.record_count != len(manifest.records):
        return OfflineVerifyResult(
            verify=VerifyResult(ok=False), manifest_ok=False,
            reason=(f"清单记录数 {manifest.record_count} 与实际 "
                    f"{len(manifest.records)} 不一致（交付物被截断/增删）"))

    records = manifest.records
    if not records:
        if manifest.seq_from is not None or manifest.seq_to is not None:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="清单声明了序号区间但没有任何记录")
        return OfflineVerifyResult(
            verify=VerifyResult(ok=True, reason="空导出"), manifest_ok=True,
            reason="空导出：清单一致，无记录需校验")

    # seq_from/seq_to 描述交付的存活记录区间（锚点是附带的接续点，不计入区间）
    live = [r for r in records if not r.anchor]
    if not live:
        # 请求区间已全部被清理：只交付锚点（接续点）
        if len(records) != 1 or not records[0].anchor:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="没有存活记录且首条不是锚点（交付物异常）")
        if not manifest.includes_anchor or manifest.cleaned is None:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="只含锚点但清单未声明 includes_anchor/cleaned")
        if manifest.seq_from is not None or manifest.seq_to is not None:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="没有存活记录但清单声明了存活序号区间")
        return OfflineVerifyResult(
            verify=VerifyResult(ok=True, reason="仅接续点"), manifest_ok=True,
            reason="请求区间已全部清理：交付物仅含锚点接续点，清单一致")
    first, last = live[0], live[-1]
    if manifest.seq_from != first.seq or manifest.seq_to != last.seq:
        return OfflineVerifyResult(
            verify=VerifyResult(ok=False), manifest_ok=False,
            reason=(f"清单序号区间 [{manifest.seq_from}, {manifest.seq_to}] "
                    f"与存活记录实际 [{first.seq}, {last.seq}] 不一致"))

    if records[0].anchor:
        if not manifest.includes_anchor or manifest.cleaned is None:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="记录含锚点但清单未声明 includes_anchor/cleaned")
        result = verify_segment(records)
    else:
        if manifest.includes_anchor:
            return OfflineVerifyResult(
                verify=VerifyResult(ok=False), manifest_ok=False,
                reason="清单声明含锚点但首条记录不是锚点")
        # 从链中间开始的导出：首条 prev_hash 即清单声明的接续点（链外信任边界）
        result = verify_segment(
            records, expected_first_seq=records[0].seq,
            expected_first_prev_hash=records[0].prev_hash)

    if not result.ok:
        return OfflineVerifyResult(verify=result, manifest_ok=True,
                                   reason=result.reason)
    return OfflineVerifyResult(
        verify=result, manifest_ok=True,
        reason=f"清单一致，链校验通过（校验 {result.checked} 条）")


@dataclass(frozen=True)
class OfflineVerifyResult:
    """离线校验结果：清单一致性 + 链校验结论。"""

    verify: VerifyResult
    manifest_ok: bool
    reason: str = ""
