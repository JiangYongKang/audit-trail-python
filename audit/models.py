"""Domain types shared across the audit pipeline."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

#: Action name reserved for purge anchor records.
PURGE_ACTION = "audit.purge"


class Sensitivity(str, enum.Enum):
    """Classification level of an audited action (drives masking/retention)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    REGULATED = "regulated"


class Outcome(str, enum.Enum):
    """Result of an audited action."""

    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


@dataclass(frozen=True)
class AuditEvent:
    """A normalized business action collected from any entry point."""

    operator: str
    action: str
    object: str
    outcome: Outcome
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    idempotency_key: str | None = None
    correlation_id: str = ""
    reason: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    entrypoint: str = "unknown"
    occurred_at: float | None = None


# Fields that make up the sealed body of a record. Everything persisted is
# part of the body; prev_hash binds it to the predecessor and record_hash is
# the seal over both.
_BODY_KEYS = (
    "seq",
    "ts",
    "operator",
    "action",
    "object",
    "outcome",
    "reason",
    "correlation_id",
    "idempotency_key",
    "sensitivity",
    "entrypoint",
    "fields",
)


@dataclass(frozen=True)
class AuditRecord:
    """One sealed, append-only record as persisted on disk."""

    seq: int
    ts: float
    operator: str
    action: str
    object: str
    outcome: str
    reason: str | None
    correlation_id: str
    idempotency_key: str
    sensitivity: str
    entrypoint: str
    fields: dict[str, Any]
    prev_hash: str
    record_hash: str

    @property
    def is_purge_anchor(self) -> bool:
        return self.action == PURGE_ACTION

    def body(self) -> dict[str, Any]:
        """The content covered by record_hash (excluding chain linkage)."""
        return {key: getattr(self, key) for key in _BODY_KEYS}

    def to_dict(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in (*_BODY_KEYS, "prev_hash", "record_hash")}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditRecord":
        return cls(**{key: data[key] for key in (*_BODY_KEYS, "prev_hash", "record_hash")})


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a chain verification pass."""

    ok: bool
    total: int = 0
    first_bad_seq: int | None = None
    reason: str = ""
    head_seq: int | None = None
    head_hash: str = ""
    last_seq: int | None = None
    last_hash: str = ""


@dataclass(frozen=True)
class PurgeReport:
    """Summary of one retention purge run."""

    removed_segments: int = 0
    removed_records: int = 0
    anchor_seq: int | None = None
    cutoff_by_level: dict[str, float] = field(default_factory=dict)
