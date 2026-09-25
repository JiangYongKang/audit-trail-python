"""Retention policies per sensitivity level and purge cutoffs."""
from __future__ import annotations

from audit.models import Sensitivity

#: Default retention window per level, in seconds.
#: public=7d, internal=30d, sensitive=90d, regulated=365d
DEFAULT_RETENTION_SECONDS: dict[Sensitivity, float] = {
    Sensitivity.PUBLIC: 7 * 86400.0,
    Sensitivity.INTERNAL: 30 * 86400.0,
    Sensitivity.SENSITIVE: 90 * 86400.0,
    Sensitivity.REGULATED: 365 * 86400.0,
}


class RetentionPolicy:
    """Maps each sensitivity level to a retention duration in seconds."""

    def __init__(self, seconds_by_level: dict[Sensitivity, float]) -> None:
        self.seconds = dict(DEFAULT_RETENTION_SECONDS)
        self.seconds.update(seconds_by_level)

    def cutoff_for(self, level: Sensitivity, now: float) -> float:
        """Records at this level older than the cutoff are eligible to purge."""
        return now - self.seconds[level]

    def all_cutoffs(self, now: float) -> dict[Sensitivity, float]:
        return {level: self.cutoff_for(level, now) for level in Sensitivity}

    def is_expired(self, sensitivity: str, ts: float, now: float) -> bool:
        level = Sensitivity(sensitivity)
        return ts < self.cutoff_for(level, now)

    @classmethod
    def default(cls) -> "RetentionPolicy":
        return cls({})
