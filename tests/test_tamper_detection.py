"""Tamper evidence: rewrite / insert / delete / reorder are located."""
from __future__ import annotations

import json
import os

from audit.hashing import canonical_json
from audit.service import AuditService
from audit.storage import SegmentStore, Spool

from conftest import make_event, make_service


def _store_dir(tmp_dir: str) -> str:
    return os.path.join(tmp_dir, "store", "segments")


def _read_lines(tmp_dir: str) -> list[tuple[str, list[dict]]]:
    out = []
    for name in sorted(os.listdir(_store_dir(tmp_dir))):
        path = os.path.join(_store_dir(tmp_dir), name)
        lines = [json.loads(line) for line in open(path).read().splitlines() if line]
        out.append((path, lines))
    return out


def _write(path: str, lines: list[dict]) -> None:
    with open(path, "wb") as handle:
        for line in lines:
            handle.write(canonical_json(line) + b"\n")


def _fresh_service(tmp_dir):
    service = make_service(tmp_dir, rotate_bytes=1)
    for i in range(1, 7):
        service.record(make_event(action=f"act-{i}", ts=1000.0 + i))
    assert service.verify().ok
    return service


def test_rewrite_detected_at_first_bad_seq(tmp_dir):
    service = _fresh_service(tmp_dir)
    path, lines = _read_lines(tmp_dir)[2]  # segment holding seq 3
    target = lines[0]
    print(f"[input] rewrite seq={target['seq']} operator alice->mallory")
    target["operator"] = "mallory"
    _write(path, lines)
    result = service.verify()
    print(f"[judgement] ok={result.ok} first_bad_seq={result.first_bad_seq} "
          f"reason={result.reason}")
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.reason == "hash-mismatch"


def test_insertion_detected_as_seq_gap(tmp_dir):
    _fresh_service(tmp_dir)
    segments = _read_lines(tmp_dir)
    path, lines = segments[-1]
    forged = dict(lines[0])
    forged["seq"] = 7
    forged["action"] = "forged"
    # append forged record after seq 6, giving 6 -> 7 then real seq? none.
    # Instead inject an extra record claiming seq 99 before seq 6:
    forged["seq"] = 99
    lines = [forged] + lines
    _write(path, lines)
    service = make_service(tmp_dir, rotate_bytes=1)
    result = service.verify()
    print(f"[input] inserted forged seq=99 before seq=6 -> "
          f"first_bad_seq={result.first_bad_seq} reason={result.reason}")
    assert not result.ok
    assert result.reason in {"seq-gap", "hash-mismatch", "prev-link"}
    assert result.first_bad_seq == 99


def test_deletion_middle_detected_via_prev_link(tmp_dir):
    _fresh_service(tmp_dir)
    segments = _read_lines(tmp_dir)
    # Delete seq 4 entirely: concatenate seg3 + seg5+ by rewriting segments.
    kept = []
    for path, lines in segments:
        for line in lines:
            if line["seq"] != 4:
                kept.append((path, line))
    # Delete seq 4 entirely from its segment file.
    by_path: dict[str, list[dict]] = {}
    for path, line in kept:
        by_path.setdefault(path, []).append(line)
    for path, ls in segments:
        if path in by_path:
            _write(path, by_path[path])
        else:
            os.remove(path)  # segment contained only seq 4
    service = make_service(tmp_dir, rotate_bytes=1)
    result = service.verify()
    print(f"[input] deleted seq=4 -> first_bad_seq={result.first_bad_seq} "
          f"reason={result.reason}")
    assert not result.ok
    # seq 5 now follows seq 3 -> gap first, then prev-link mismatch
    assert result.first_bad_seq == 5
    assert result.reason in {"seq-gap", "prev-link"}


def test_reorder_detected(tmp_dir):
    _fresh_service(tmp_dir)
    segments = _read_lines(tmp_dir)
    all_lines = [line for _, ls in segments for line in ls]
    all_lines[1], all_lines[2] = all_lines[2], all_lines[1]  # swap seq 2 and 3
    # rewrite everything into a single surviving segment file layout is hard;
    # instead swap inside the concatenation and overwrite first two segment files
    grouped: dict[str, list[dict]] = {p: ls for p, ls in segments}
    paths = list(grouped)
    _write(paths[1], [all_lines[1]])
    _write(paths[2], [all_lines[2]])
    service = make_service(tmp_dir, rotate_bytes=1)
    result = service.verify()
    print(f"[input] swapped seq 2<->3 -> first_bad_seq={result.first_bad_seq} "
          f"reason={result.reason}")
    assert not result.ok
    # Physical chain reads 1,3,...: the first displaced record (seq 3) breaks
    # consecutiveness before hash/prev checks; either way it is located.
    assert result.first_bad_seq == 3
    assert result.reason in {"seq-gap", "hash-mismatch", "prev-link"}


def test_truncate_without_anchor_rejected(tmp_dir):
    _fresh_service(tmp_dir)
    segments = _read_lines(tmp_dir)
    # Remove the first two segment files (seq 1-2) with no purge anchor.
    for path, lines in segments[:2]:
        os.remove(path)
    service = make_service(tmp_dir, rotate_bytes=1)
    result = service.verify()
    print(f"[input] removed head segments 1-2 with no anchor -> "
          f"first_bad_seq={result.first_bad_seq} reason={result.reason}")
    assert not result.ok
    assert result.reason == "missing-anchor"
    assert result.first_bad_seq == 3


def test_restart_after_normal_writes_still_verifies(tmp_dir):
    service = _fresh_service(tmp_dir)
    restarted = AuditService(
        SegmentStore(os.path.join(tmp_dir, "store"), rotate_bytes=1),
        Spool(os.path.join(tmp_dir, "spool.jsonl")),
    )
    result = restarted.verify()
    print(f"[judgement after restart] ok={result.ok} total={result.total}")
    assert result.ok and result.total == 6
    # appending after restart extends the chain without a fork
    record = restarted.record(make_event(action="post-restart", ts=2000.0))
    assert record.seq == 7 and record.prev_hash == result.last_hash
    assert restarted.verify().ok
