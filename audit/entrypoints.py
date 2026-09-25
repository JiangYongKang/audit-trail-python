"""Normalization adapters that funnel every entry kind into AuditEvent.

The same business action arriving via HTTP, CLI or a scheduled job produces
events with the same stable fields (operator/action/object/outcome/reason/
correlation_id); only ``entrypoint`` records where it came from.
"""
from __future__ import annotations

from typing import Any

from audit.models import AuditEvent, Outcome, Sensitivity


def normalize_http(
    method: str,
    path: str,
    operator: str,
    outcome: Outcome,
    *,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    correlation_id: str = "",
    idempotency_key: str | None = None,
    reason: str | None = None,
    fields: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        operator=operator,
        action=f"http:{method.upper()} {path}",
        object=path,
        outcome=outcome,
        sensitivity=sensitivity,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        reason=reason,
        fields=dict(fields or {}),
        entrypoint="http",
    )


def normalize_cli(
    command: str,
    operator: str,
    outcome: Outcome,
    *,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    correlation_id: str = "",
    idempotency_key: str | None = None,
    reason: str | None = None,
    fields: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        operator=operator,
        action=f"cli:{command}",
        object=command,
        outcome=outcome,
        sensitivity=sensitivity,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        reason=reason,
        fields=dict(fields or {}),
        entrypoint="cli",
    )


def normalize_job(
    job_name: str,
    operator: str,
    outcome: Outcome,
    *,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    correlation_id: str = "",
    idempotency_key: str | None = None,
    reason: str | None = None,
    fields: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        operator=operator,
        action=f"job:{job_name}",
        object=job_name,
        outcome=outcome,
        sensitivity=sensitivity,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        reason=reason,
        fields=dict(fields or {}),
        entrypoint="job",
    )
