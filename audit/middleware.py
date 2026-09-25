"""FastAPI 入口采集：中间件 + 依赖注入（骨架）。"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware

from .service import AuditService


class AuditMiddleware(BaseHTTPMiddleware):
    """采集 HTTP 入口请求并产生归一化审计事件。"""

    def __init__(self, app, service: AuditService) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._service = service
