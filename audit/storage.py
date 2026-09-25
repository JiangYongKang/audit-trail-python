"""Append-only segment storage, WAL spool, and on-disk record layout.

On-disk layout::

    <directory>/
        segments/
            seg-0000000001-0000000050.jsonl
            seg-0000000051-0000000100.jsonl
        spool.jsonl                 # durable WAL for events pending append

Segment files are JSONL (one canonical JSON record per line), named by the
inclusive sequence range they contain, so lexical name order is chain order
across restarts and rotation.

Purges delete a *prefix* of whole segments and first append a normal,
hash-chained **purge anchor** record at the tail. The anchor attests the
sequence number and hash of the last removed record, so verification stays
continuous (see :py:meth:`SegmentStore.verify`).
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from typing import Any, Callable, Iterable

from audit.hashing import GENESIS_HASH, canonical_json, payload_digest
from audit.models import PURGE_ACTION, AuditRecord, Outcome, Sensitivity, VerifyResult

_SEGMENT_RE = re.compile(r"^seg-(\d{12})-(\d{12})\.jsonl$")
ANCHOR_OBJECT = "audit:chain"
ANCHOR_OPERATOR = "system:retention"


class StorageError(RuntimeError):
    """Raised when a durable write cannot be completed."""


class SegmentStore:
    """JSONL segment files named by sequence range, rotated by byte size."""

    def __init__(
        self,
        directory: str,
        rotate_bytes: int = 1 << 20,
        fault_hook: Callable[[], None] | None = None,
    ) -> None:
        self.directory = directory
        self.segments_dir = os.path.join(directory, "segments")
        os.makedirs(self.segments_dir, exist_ok=True)
        self.rotate_bytes = rotate_bytes
        self.fault_hook = fault_hook
        self._lock = threading.RLock()
        self._tail_path: str | None = None
        self._tail_size = 0
        self._last_seq = 0
        self._last_hash = GENESIS_HASH
        self._load_state()

    # ------------------------------------------------------------------ state
    def _load_state(self) -> None:
        names = self.list_segments()
        if not names:
            self._tail_path = None
            self._tail_size = 0
            self._last_seq = 0
            self._last_hash = GENESIS_HASH
            return
        self._tail_path = os.path.join(self.segments_dir, names[-1])
        self._tail_size = os.path.getsize(self._tail_path)
        last: AuditRecord | None = None
        for record in self._read_segment(names[-1]):
            last = record
        if last is None:
            # An empty tail should never exist, but tolerate it by dropping.
            os.remove(self._tail_path)
            return self._load_state()
        self._last_seq = last.seq
        self._last_hash = last.record_hash

    def list_segments(self) -> list[str]:
        with self._lock:
            names = [
                name
                for name in os.listdir(self.segments_dir)
                if _SEGMENT_RE.match(name)
            ]
            return sorted(names)

    @staticmethod
    def _segment_name(first_seq: int, last_seq: int) -> str:
        return f"seg-{first_seq:012d}-{last_seq:012d}.jsonl"

    def _read_segment(self, name: str) -> list[AuditRecord]:
        path = os.path.join(self.segments_dir, name)
        records: list[AuditRecord] = []
        with open(path, "rb") as handle:
            for line_no, raw in enumerate(handle, 1):
                text = raw.decode("utf-8").strip()
                if not text:
                    continue
                try:
                    records.append(AuditRecord.from_dict(json.loads(text)))
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise StorageError(
                        f"corrupt segment {name} line {line_no}: {exc}"
                    ) from exc
        return records

    # ----------------------------------------------------------------- append
    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def last_state(self) -> tuple[int, str]:
        with self._lock:
            return self._last_seq, self._last_hash

    def _open_new_segment(self, first_seq: int) -> None:
        name = self._segment_name(first_seq, first_seq)
        self._tail_path = os.path.join(self.segments_dir, name)
        self._tail_size = 0

    def append(self, record: AuditRecord) -> None:
        line = canonical_json(record.to_dict()).decode("utf-8") + "\n"
        payload = line.encode("utf-8")
        with self._lock:
            try:
                if self.fault_hook is not None:
                    self.fault_hook()
                if self._tail_path is None:
                    self._open_new_segment(record.seq)
                elif self._tail_size > 0 and self._tail_size + len(payload) > self.rotate_bytes:
                    self._rename_tail_on_rotate(record.seq)
                with open(self._tail_path, "ab") as handle:  # type: ignore[arg-type]
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                # State on disk is authoritative; reload before surfacing.
                self._load_state()
                raise StorageError(f"append failed at seq {record.seq}: {exc}") from exc
            self._tail_size += len(payload)
            self._last_seq = record.seq
            self._last_hash = record.record_hash

    def _rename_tail_on_rotate(self, next_seq: int) -> None:
        """Give the about-to-be-sealed tail file its real end-seq name."""
        assert self._tail_path is not None
        match = _SEGMENT_RE.match(os.path.basename(self._tail_path))
        assert match is not None
        first_seq = int(match.group(1))
        records = self._read_segment(os.path.basename(self._tail_path))
        end_seq = records[-1].seq
        final_name = self._segment_name(first_seq, end_seq)
        final_path = os.path.join(self.segments_dir, final_name)
        os.replace(self._tail_path, final_path)
        self._open_new_segment(next_seq)

    # ------------------------------------------------------------------ reads
    def iter_records(self) -> Iterable[AuditRecord]:
        with self._lock:
            names = self.list_segments()
            snapshot = [self._read_segment(name) for name in names]
        for records in snapshot:
            yield from records

    def all_records(self) -> list[AuditRecord]:
        return list(self.iter_records())

    # ---------------------------------------------------------------- verify
    def verify(self) -> VerifyResult:
        """Verify the surviving chain.

        Checks, in physical (chain) order:

        1. sequence numbers are consecutive (detects insertion/deletion/
           reordering);
        2. each record hash seals its body (detects content rewriting);
        3. each record's ``prev_hash`` equals the previous record hash
           (detects forks/breaks);
        4. when the oldest surviving record's predecessor was purged, a
           purge anchor must attest exactly that cut point (seq + hash),
           otherwise the chain head is untrusted.

        ``first_bad_seq`` points at the first record that fails a check.
        """
        with self._lock:
            records = self.all_records()
        if not records:
            return VerifyResult(ok=True, total=0)

        anchors = {r.seq: r for r in records if r.is_purge_anchor}
        head = records[0]

        def fail(record: AuditRecord, reason: str) -> VerifyResult:
            last = records[-1]
            return VerifyResult(
                ok=False,
                total=len(records),
                first_bad_seq=record.seq,
                reason=reason,
                head_seq=head.seq,
                head_hash=head.record_hash,
                last_seq=last.seq,
                last_hash=last.record_hash,
            )

        # Head linkage: genesis, ordinary dangling head, or anchor-attested.
        if head.seq == 1:
            if head.prev_hash != GENESIS_HASH:
                return fail(head, "prev-link")
        elif not _head_matches_anchor(head, anchors):
            return fail(head, "missing-anchor")

        prev_seq: int | None = None
        prev_hash: str | None = None
        for record in records:
            if prev_seq is not None and record.seq != prev_seq + 1:
                return fail(record, "seq-gap")
            if payload_digest(record.prev_hash, record.body()) != record.record_hash:
                return fail(record, "hash-mismatch")
            if record.is_purge_anchor and not _anchor_fields_sane(record):
                return fail(record, "anchor-invalid")
            if prev_hash is not None and record.prev_hash != prev_hash:
                return fail(record, "prev-link")
            prev_seq = record.seq
            prev_hash = record.record_hash

        last = records[-1]
        return VerifyResult(
            ok=True,
            total=len(records),
            head_seq=head.seq,
            head_hash=head.record_hash,
            last_seq=last.seq,
            last_hash=last.record_hash,
        )

    # ----------------------------------------------------------------- purge
    def select_expired_prefix(
        self, cutoffs: dict[str, float]
    ) -> tuple[list[str], list[AuditRecord]]:
        """Return the maximal prefix of segments that is wholly expired.

        A segment qualifies only when *every* record in it is older than its
        level cutoff, so a purge never leaves a chain dangling mid-segment.
        """
        with self._lock:
            names = self.list_segments()
            segments = [(name, self._read_segment(name)) for name in names]
        expired_names: list[str] = []
        expired_records: list[AuditRecord] = []
        for name, records in segments:
            if not records:
                continue
            if any(r.ts >= cutoffs[r.sensitivity] for r in records):
                break
            expired_names.append(name)
            expired_records.extend(records)
        return expired_names, expired_records

    def remove_segments(self, names: Iterable[str]) -> None:
        with self._lock:
            for name in names:
                os.remove(os.path.join(self.segments_dir, name))
            self._load_state()

    def append_purge_anchor(
        self,
        seq: int,
        ts: float,
        removed_through_seq: int,
        removed_through_hash: str,
        removed_records: int,
        cutoffs: dict[str, float],
        prev_hash: str,
    ) -> AuditRecord:
        fields = {
            "removed_through_seq": removed_through_seq,
            "removed_through_hash": removed_through_hash,
            "removed_records": removed_records,
            "cutoffs": cutoffs,
        }
        record = AuditRecord(
            seq=seq,
            ts=ts,
            operator=ANCHOR_OPERATOR,
            action=PURGE_ACTION,
            object=ANCHOR_OBJECT,
            outcome=Outcome.SUCCESS.value,
            reason=None,
            correlation_id="",
            idempotency_key="",
            sensitivity=Sensitivity.REGULATED.value,
            entrypoint="system",
            fields=fields,
            prev_hash=prev_hash,
            record_hash="",
        )
        sealed = AuditRecord(
            **{**record.to_dict(), "record_hash": payload_digest(prev_hash, record.body())}
        )
        self.append(sealed)
        return sealed


def _anchor_fields_sane(record: AuditRecord) -> bool:
    fields = record.fields
    if not isinstance(fields, dict):
        return False
    through_seq = fields.get("removed_through_seq")
    through_hash = fields.get("removed_through_hash")
    if not isinstance(through_seq, int) or not isinstance(through_hash, str):
        return False
    if through_seq < 0 or len(through_hash) != 64:
        return False
    return through_seq < record.seq


def _head_matches_anchor(
    head: AuditRecord, anchors: dict[int, AuditRecord]
) -> bool:
    """A dangling head is trusted only if an anchor attests that exact cut."""
    for anchor in anchors.values():
        fields = anchor.fields
        if (
            fields.get("removed_through_seq") == head.seq - 1
            and fields.get("removed_through_hash") == head.prev_hash
        ):
            return True
    return False


class Spool:
    """Durable write-ahead spool for events whose chain append failed.

    Each line is ``{"id": <uuid>, "ts": <event time>, "event": <body>}``.
    Events are acknowledged (removed) only after their chain append is
    durable; a process crash therefore replays them on next flush.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            open(path, "ab").close()

    def _append_line(self, data: dict[str, Any]) -> None:
        line = canonical_json(data).decode("utf-8") + "\n"
        with open(self.path, "ab") as handle:
            handle.write(line.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())

    def add(self, event_body: dict[str, Any]) -> str:
        with self._lock:
            spool_id = uuid.uuid4().hex
            self._append_line({"id": spool_id, "event": event_body})
            return spool_id

    def pop_ready(self) -> list[dict[str, Any]]:
        with self._lock:
            items: list[dict[str, Any]] = []
            with open(self.path, "rb") as handle:
                for raw in handle:
                    text = raw.decode("utf-8").strip()
                    if text:
                        items.append(json.loads(text))
            return items

    def discard(self, ids: list[str]) -> None:
        with self._lock:
            drop = set(ids)
            kept = [item for item in self.pop_ready() if item["id"] not in drop]
            tmp_path = self.path + ".tmp"
            with open(tmp_path, "wb") as handle:
                for item in kept:
                    handle.write(canonical_json(item).decode("utf-8").encode("utf-8") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)

    def __len__(self) -> int:
        return len(self.pop_ready())
