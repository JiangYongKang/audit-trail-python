"""AuditService: the single ingestion + verification + retention facade.

Concurrency model: sealing (assigning seq/hash) and appending happen inside
one re-entrant lock, so even under concurrent callers the on-disk order is
the true commit order and no two records can fork the chain.

Reliability model: an append is retried in-process; if every attempt fails
the already-serialized event is durably spooled (write-ahead) and the error
is *raised*, never swallowed. ``flush_spool`` replays spooled events in
order after the store recovers.

Idempotency: an explicit ``idempotency_key`` makes repeated submissions of
the same business action return the already-persisted record instead of
writing a duplicate.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from audit.hashing import GENESIS_HASH, payload_digest
from audit.masking import PolicyMasker, default_masker
from audit.models import (
    AuditEvent,
    AuditRecord,
    PurgeReport,
    VerifyResult,
)
from audit.retention import RetentionPolicy
from audit.storage import SegmentStore, Spool, StorageError


class AuditService:
    def __init__(
        self,
        store: SegmentStore,
        spool: Spool | None = None,
        masker: PolicyMasker | None = None,
        retention: RetentionPolicy | None = None,
        max_append_retries: int = 3,
        retry_backoff: float = 0.001,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.spool = spool
        self.masker = masker or default_masker()
        self.retention = retention or RetentionPolicy.default()
        self.max_append_retries = max(1, max_append_retries)
        self.retry_backoff = retry_backoff
        self.clock = clock
        self._lock = threading.RLock()
        self._dedup: dict[str, AuditRecord] = {}
        for record in store.iter_records():
            if record.idempotency_key:
                self._dedup[record.idempotency_key] = record

    # ---------------------------------------------------------------- ingest
    def _spool_event(self, event: AuditEvent) -> None:
        if self.spool is not None:
            self.spool.add(_event_body(event, self.masker))

    def _seal(self, event: AuditEvent, ts: float) -> AuditRecord:
        """Caller must hold the lock; builds the next chained record."""
        last_seq, last_hash = self.store.last_state()
        masked_fields = self.masker.mask_fields(event.fields, event.sensitivity)
        record = AuditRecord(
            seq=last_seq + 1,
            ts=ts,
            operator=event.operator,
            action=event.action,
            object=event.object,
            outcome=event.outcome.value,
            reason=event.reason,
            correlation_id=event.correlation_id,
            idempotency_key=event.idempotency_key or "",
            sensitivity=event.sensitivity.value,
            entrypoint=event.entrypoint,
            fields=masked_fields,
            prev_hash=last_hash,
            record_hash="",
        )
        return AuditRecord(
            **{
                **record.to_dict(),
                "record_hash": payload_digest(last_hash, record.body()),
            }
        )

    def _append_with_retry(self, record: AuditRecord) -> None:
        last_error: Exception | None = None
        for attempt in range(self.max_append_retries):
            try:
                self.store.append(record)
                return
            except StorageError as exc:
                last_error = exc
                if attempt + 1 < self.max_append_retries:
                    time.sleep(self.retry_backoff * (attempt + 1))
        raise StorageError(f"append exhausted retries: {last_error}") from last_error

    def record(self, event: AuditEvent) -> AuditRecord:
        """Seal and persist one normalized event; never silently drops it."""
        ts = event.occurred_at if event.occurred_at is not None else self.clock()
        with self._lock:
            if event.idempotency_key:
                existing = self._dedup.get(event.idempotency_key)
                if existing is not None:
                    return existing
            record = self._seal(event, ts)
            try:
                self._append_with_retry(record)
            except StorageError:
                self._spool_event(event)
                raise
            if event.idempotency_key:
                self._dedup[event.idempotency_key] = record
            return record

    # ------------------------------------------------------------------ spool
    def flush_spool(self) -> int:
        """Replay spooled events in order; returns the number appended."""
        if self.spool is None:
            return 0
        appended = 0
        with self._lock:
            items = self.spool.pop_ready()
            done_ids: list[str] = []
            for item in items:
                body = item["event"]
                key = body.get("idempotency_key") or None
                if key and key in self._dedup:
                    done_ids.append(item["id"])
                    continue
                event = _event_from_body(body)
                record = self._seal(event, body.get("ts") or self.clock())
                try:
                    self._append_with_retry(record)
                except StorageError:
                    break
                if key:
                    self._dedup[key] = record
                done_ids.append(item["id"])
                appended += 1
            if done_ids:
                self.spool.discard(done_ids)
        return appended

    # ------------------------------------------------------------------ query
    def query(
        self,
        action: str | None = None,
        operator: str | None = None,
        correlation_id: str | None = None,
        limit: int | None = None,
    ) -> list[AuditRecord]:
        """Read a consistent snapshot; purge-safe (snapshot taken under lock)."""
        with self._lock:
            records = self.store.all_records()
        out = [
            r
            for r in records
            if (action is None or r.action == action)
            and (operator is None or r.operator == operator)
            and (correlation_id is None or r.correlation_id == correlation_id)
        ]
        if limit is not None:
            out = out[-limit:]
        return out

    # ---------------------------------------------------------------- verify
    def verify(self) -> VerifyResult:
        return self.store.verify()

    # --------------------------------------------------------------- retention
    def purge_expired(self, now: float | None = None) -> PurgeReport:
        now = self.clock() if now is None else now
        cutoff_levels = self.retention.all_cutoffs(now)
        cutoffs = {level.value: cutoff for level, cutoff in cutoff_levels.items()}
        with self._lock:
            names, expired = self.store.select_expired_prefix(cutoffs)
            if not names:
                return PurgeReport(cutoff_by_level=cutoffs)
            last_removed = expired[-1]
            last_seq, last_hash = self.store.last_state()
            anchor = self.store.append_purge_anchor(
                seq=last_seq + 1,
                ts=now,
                removed_through_seq=last_removed.seq,
                removed_through_hash=last_removed.record_hash,
                removed_records=len(expired),
                cutoffs=cutoffs,
                prev_hash=last_hash,
            )
            # Anchor is durable first; only then delete the expired prefix.
            self.store.remove_segments(names)
        return PurgeReport(
            removed_segments=len(names),
            removed_records=len(expired),
            anchor_seq=anchor.seq,
            cutoff_by_level=cutoffs,
        )


def _event_body(event: AuditEvent, masker: PolicyMasker) -> dict[str, Any]:
    """Serialize an event for the spool — already masked, never raw."""
    return {
        "ts": event.occurred_at if event.occurred_at is not None else time.time(),
        "operator": event.operator,
        "action": event.action,
        "object": event.object,
        "outcome": event.outcome.value,
        "sensitivity": event.sensitivity.value,
        "idempotency_key": event.idempotency_key,
        "correlation_id": event.correlation_id,
        "reason": event.reason,
        "entrypoint": event.entrypoint,
        "fields": masker.mask_fields(event.fields, event.sensitivity),
    }


def _event_from_body(body: dict[str, Any]) -> AuditEvent:
    from audit.models import Outcome, Sensitivity

    return AuditEvent(
        operator=body["operator"],
        action=body["action"],
        object=body["object"],
        outcome=Outcome(body["outcome"]),
        sensitivity=Sensitivity(body["sensitivity"]),
        idempotency_key=body.get("idempotency_key"),
        correlation_id=body.get("correlation_id", ""),
        reason=body.get("reason"),
        fields=dict(body.get("fields") or {}),
        entrypoint=body.get("entrypoint", "spool"),
        occurred_at=body.get("ts"),
    )
