"""Command line interface: verify / purge / query.

Examples::

    python -m audit.cli --store ./audit-data verify
    python -m audit.cli --store ./audit-data purge
    python -m audit.cli --store ./audit-data query --action login --limit 5
"""
from __future__ import annotations

import argparse
import json
import sys

from audit.hashing import canonical_json
from audit.service import AuditService
from audit.storage import SegmentStore, Spool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit", description="Audit chain tools")
    parser.add_argument("--store", default="./audit-data", help="storage directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify", help="verify the hash chain")
    sub.add_parser("purge", help="delete records past their retention window")
    sub.add_parser("flush", help="replay spooled events after an outage")

    query = sub.add_parser("query", help="list records (newest tail order)")
    query.add_argument("--action")
    query.add_argument("--operator")
    query.add_argument("--correlation-id")
    query.add_argument("--limit", type=int)
    return parser


def _service(store_dir: str) -> AuditService:
    return AuditService(
        SegmentStore(store_dir),
        Spool(f"{store_dir.rstrip('/')}/spool.jsonl"),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = _service(args.store)

    if args.command == "verify":
        result = service.verify()
        payload = {
            "ok": result.ok,
            "total": result.total,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
            "head_seq": result.head_seq,
            "last_seq": result.last_seq,
            "last_hash": result.last_hash[:16] + "..." if result.last_hash else "",
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if result.ok else 2

    if args.command == "purge":
        report = service.purge_expired()
        print(json.dumps({
            "removed_segments": report.removed_segments,
            "removed_records": report.removed_records,
            "anchor_seq": report.anchor_seq,
            "cutoff_by_level": report.cutoff_by_level,
        }, indent=2, ensure_ascii=False))
        return 0

    if args.command == "flush":
        count = service.flush_spool()
        print(json.dumps({"replayed": count}))
        return 0

    if args.command == "query":
        records = service.query(
            action=args.action,
            operator=args.operator,
            correlation_id=args.correlation_id,
            limit=args.limit,
        )
        for record in records:
            sys.stdout.buffer.write(canonical_json(record.to_dict()) + b"\n")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
