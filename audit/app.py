"""FastAPI application demonstrating the audited service.

Endpoints:

* ``GET  /health``              - liveness (unaudited)
* ``POST /transfer``            - business action; audited success or *denied*
* ``GET  /audit/records``       - query the chain (masked records only)
* ``GET  /audit/verify``        - verify chain integrity
* ``POST /audit/purge``         - run retention cleanup

Every audited response carries ``X-Correlation-ID``; denial responses
include the machine-readable ``reason`` that was written to the chain.
"""
from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from audit.entrypoints import normalize_http
from audit.models import Outcome, Sensitivity
from audit.service import AuditService
from audit.storage import SegmentStore, Spool, StorageError

DEFAULT_STORE_DIR = os.environ.get("AUDIT_STORE", "./audit-data")

DENY_REASONS = frozenset({"insufficient-funds", "risk-rejected", "unauthorized"})


class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float
    password: str | None = None
    idempotency_key: str | None = None


def create_app(service: AuditService | None = None) -> FastAPI:
    if service is None:
        directory = DEFAULT_STORE_DIR
        service = AuditService(
            SegmentStore(directory),
            Spool(os.path.join(directory, "spool.jsonl")),
        )

    app = FastAPI(title="audit-trail-demo")
    app.state.audit = service

    def audit(
        request: Request,
        outcome: Outcome,
        reason: str | None,
        correlation_id: str,
        idempotency_key: str | None,
        fields: dict[str, Any],
        sensitivity: Sensitivity = Sensitivity.SENSITIVE,
    ) -> Any:
        operator = request.headers.get("X-Operator", "anonymous")
        event = normalize_http(
            request.method,
            request.url.path,
            operator,
            outcome,
            sensitivity=sensitivity,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            reason=reason,
            fields=fields,
        )
        try:
            return app.state.audit.record(event)
        except StorageError:
            # The event is durably spooled; signal 503 instead of silently
            # accepting a request whose audit trail is not yet sealed.
            raise HTTPException(status_code=503, detail="audit-unavailable")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/transfer")
    def transfer(
        body: TransferRequest,
        request: Request,
        x_correlation_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        correlation_id = x_correlation_id or uuid.uuid4().hex
        fields = {
            "from_account": body.from_account,
            "to_account": body.to_account,
            "amount": body.amount,
            "password": body.password,
        }
        reason: str | None = None
        outcome = Outcome.SUCCESS
        if body.amount <= 0:
            outcome, reason = Outcome.DENIED, "invalid-amount"
        elif body.amount > 10_000:
            outcome, reason = Outcome.DENIED, "risk-rejected"
        record = audit(
            request, outcome, reason, correlation_id,
            body.idempotency_key, fields,
        )
        response = {
            "status": outcome.value,
            "reason": reason,
            "correlation_id": correlation_id,
            "seq": record.seq,
        }
        return response

    @app.get("/audit/records")
    def list_records(
        action: str | None = None,
        operator: str | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        records = app.state.audit.query(
            action=action,
            operator=operator,
            correlation_id=correlation_id,
            limit=limit,
        )
        return {"records": [r.to_dict() for r in records]}

    @app.get("/audit/verify")
    def verify() -> dict[str, Any]:
        result = app.state.audit.verify()
        return {
            "ok": result.ok,
            "total": result.total,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
            "head_seq": result.head_seq,
            "last_seq": result.last_seq,
        }

    @app.post("/audit/purge")
    def purge() -> dict[str, Any]:
        report = app.state.audit.purge_expired()
        return {
            "removed_segments": report.removed_segments,
            "removed_records": report.removed_records,
            "anchor_seq": report.anchor_seq,
        }

    return app


app = create_app()
