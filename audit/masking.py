"""Field masking policies applied before anything is persisted or returned.

Masking is the last transformation before an event leaves the process for
storage, and the same transformation is applied to anything returned to a
caller, so original sensitive values can never reach disk or a response.

Strategies:

* ``full``    -> ``***`` (whole value withheld)
* ``hash``    -> ``sha256: <12 hex chars>`` (stable, correlation-safe)
* ``partial`` -> keep a short non-sensitive prefix/edge, mask the rest
* ``keep``    -> value kept untouched

Rules are keyed by lower-case field name. Unknown fields fall back to a
level-driven default so that *no* level accidentally leaks content:
PUBLIC keeps unknown fields, every higher level fully masks them.
"""
from __future__ import annotations

import hashlib
from typing import Any, Protocol

from audit.models import Sensitivity

FULL = "***"

#: Fixed field-name rules, independent of level.
DEFAULT_FIELD_RULES: dict[str, str] = {
    "password": "full",
    "passwd": "full",
    "secret": "full",
    "token": "full",
    "access_token": "full",
    "refresh_token": "full",
    "api_key": "full",
    "authorization": "full",
    "id_card": "full",
    "id_number": "full",
    "ssn": "full",
    "bank_card": "full",
    "card_number": "full",
    "cvv": "full",
    "email": "partial",
    "phone": "partial",
    "mobile": "partial",
    # Account identifiers are correlation keys: keep a stable non-reversible
    # digest so the same account can be joined across records without the raw
    # account number ever hitting disk.
    "from_account": "hash",
    "to_account": "hash",
    "account": "hash",
    "account_id": "hash",
    "user_id": "hash",
    # Amounts/quantities are non-secret evidence and are needed for
    # accountability, so they remain readable.
    "amount": "keep",
    "currency": "keep",
    "balance": "keep",
    "username": "keep",
    "name": "keep",
    "action": "keep",
}

#: What happens to fields without an explicit rule at each level.
DEFAULT_UNKNOWN_RULE: dict[Sensitivity, str] = {
    Sensitivity.PUBLIC: "keep",
    Sensitivity.INTERNAL: "full",
    Sensitivity.SENSITIVE: "full",
    Sensitivity.REGULATED: "full",
}


class Masker(Protocol):
    def mask_value(self, key: str, value: Any, level: Sensitivity) -> Any:
        ...

    def mask_fields(self, fields: dict[str, Any], level: Sensitivity) -> dict[str, Any]:
        ...


class PolicyMasker:
    """Rule based masker: field-name rules + level-driven defaults."""

    def __init__(
        self,
        field_rules: dict[str, str] | None = None,
        level_unknown: dict[Sensitivity, str] | None = None,
    ) -> None:
        self.field_rules = {
            k.lower(): v for k, v in (field_rules or DEFAULT_FIELD_RULES).items()
        }
        self.level_unknown = level_unknown or dict(DEFAULT_UNKNOWN_RULE)

    def rule_for(self, key: str, level: Sensitivity) -> str:
        return self.field_rules.get(key.lower(), self.level_unknown[level])

    def mask_value(self, key: str, value: Any, level: Sensitivity) -> Any:
        if value is None:
            return None
        rule = self.rule_for(key, level)
        if rule == "keep":
            return value
        if rule == "full":
            return FULL
        if rule == "hash":
            digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
            return f"sha256:{digest}"
        if rule == "partial":
            return mask_simple(value)
        raise ValueError(f"unknown mask strategy: {rule!r}")

    def mask_fields(self, fields: dict[str, Any], level: Sensitivity) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in fields.items():
            if isinstance(value, dict):
                out[key] = self.mask_fields(value, level)
            else:
                out[key] = self.mask_value(key, value, level)
        return out


def mask_simple(value: Any) -> str:
    """Keep at most 2 edge characters, replace the middle with asterisks."""
    text = str(value)
    if len(text) <= 2:
        return "*" * len(text)
    if len(text) <= 6:
        return text[0] + "*" * (len(text) - 2) + text[-1]
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def default_masker() -> PolicyMasker:
    return PolicyMasker()
