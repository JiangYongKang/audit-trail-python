"""按敏感级别脱敏。

规则（落盘前应用，原始值不得出现在任何持久化内容或对外返回中）：
- LOW：不脱敏。
- MEDIUM：默认敏感字段（如 password/token/secret 等）整体替换为掩码。
- HIGH：在 MEDIUM 基础上，额外对 details 中除白名单外的所有字段做单向散列，
  只保留可比对、不可还原的形式。
"""
from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

from .models import AuditEvent, Sensitivity

MASK = "***REDACTED***"

# 任何级别下都被视为敏感的字段名（小写匹配，含子串匹配）
SENSITIVE_KEYS = (
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "authorization", "credential", "private_key", "ssn", "id_card",
)

# HIGH 级别下允许明文保留的字段白名单
HIGH_LEVEL_WHITELIST = ("ip", "user_agent", "path", "method", "status")


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in SENSITIVE_KEYS)


def _hash_value(value: Any) -> str:
    digest = hashlib.sha256(repr(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _redact_details(details: dict[str, Any], sensitivity: Sensitivity) -> dict[str, Any]:
    if sensitivity is Sensitivity.LOW:
        # LOW 级别仍需遮蔽显式敏感字段，其余保留
        return {k: (MASK if _is_sensitive_key(k) else v) for k, v in details.items()}
    if sensitivity is Sensitivity.MEDIUM:
        return {k: (MASK if _is_sensitive_key(k) else v) for k, v in details.items()}
    # HIGH：敏感字段直接掩码，非白名单字段做单向散列
    out: dict[str, Any] = {}
    for k, v in details.items():
        if _is_sensitive_key(k):
            out[k] = MASK
        elif k.lower() in HIGH_LEVEL_WHITELIST:
            out[k] = v
        else:
            out[k] = _hash_value(v)
    return out


def redact_event(event: AuditEvent) -> AuditEvent:
    """按事件敏感级别对 details 中的敏感字段脱敏，返回新事件（不改原对象）。"""
    redacted = _redact_details(event.details, event.sensitivity)
    return replace(event, details=redacted)
