#!/usr/bin/env python3
"""离线核验导出的审计交付物。

用法：
    uv run python offline_verify.py audit-export.json
    # 或在没有本服务/原始存储的机器上（仅需 Python 3.14 标准库，
    # 连同 audit/ 目录一起拷过去）：
    python offline_verify.py audit-export.json

退出码：0 校验通过（含“区间已全部清理、仅接续点”的情形）；1 校验失败。
"""
from __future__ import annotations

import sys

from audit.export import read_bundle, verify_bundle


def main(path: str) -> int:
    manifest = read_bundle(path)
    result = verify_bundle(manifest)
    print(f"格式版本: {manifest.format_version}")
    print(f"存活序号区间: {manifest.seq_from}..{manifest.seq_to}")
    print(f"交付记录数: {manifest.record_count}（含锚点: {manifest.includes_anchor}）")
    if manifest.cleaned:
        c = manifest.cleaned
        print(f"声明已清理区段: seq {c['removed_from_seq']}..{c['removed_up_to_seq']}"
              f"（{c['removed_count']} 条，"
              f"时间 {c['removed_from_occurred_at']}..{c['removed_up_to_occurred_at']}）")
    print(f"清单一致: {result.manifest_ok}")
    print(f"链校验: {result.verify.ok}（校验 {result.verify.checked} 条）")
    print(f"结论: {result.reason}")
    if not result.verify.ok:
        print(f"第一个出问题的位置: seq={result.verify.first_bad_seq}")
    return 0 if result.manifest_ok and result.verify.ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
