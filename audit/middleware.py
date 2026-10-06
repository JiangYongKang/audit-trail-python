"""FastAPI 入口采集：把每个 HTTP 请求归一化为一条审计事件。

无论业务动作从哪个入口进入，都产生字段稳定的记录：
操作者（X-Actor 头）、动作（方法+路由）、对象（路径）、结果（按状态码映射）、
拒绝原因（4xx 时取响应 detail）、关联标识（X-Correlation-ID 或自动生成）。
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .models import AuditEvent, Outcome, Sensitivity
from .service import AuditService


def _outcome_for_status(status: int) -> Outcome:
    if status in (401, 403):
        return Outcome.DENIED
    if status >= 500:
        return Outcome.ERROR
    if status >= 400:
        return Outcome.DENIED
    return Outcome.SUCCESS


class AuditMiddleware(BaseHTTPMiddleware):
    """采集 HTTP 入口请求并产生归一化审计事件。"""

    def __init__(self, app, service: AuditService) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._service = service

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        correlation_id = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        response = await call_next(request)
        event = AuditEvent(
            actor=request.headers.get("x-actor", "anonymous"),
            action=f"{request.method} {request.url.path}",
            target=request.url.path,
            outcome=_outcome_for_status(response.status_code),
            deny_reason=f"http_{response.status_code}" if response.status_code >= 400 else None,
            correlation_id=correlation_id,
            idempotency_key=request.headers.get("x-idempotency-key"),
            sensitivity=Sensitivity.LOW,
            source="http",
            details={"method": request.method, "status": response.status_code},
        )
        self._service.record(event)
        response.headers["x-correlation-id"] = correlation_id
        return response
