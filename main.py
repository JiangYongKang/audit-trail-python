"""审计日志链路演示服务。

入口：
- GET  /                     健康检查
- POST /actions/{action}     业务动作入口（演示被拒绝与完成两种结果）
- GET  /audit/records        查询审计记录（已脱敏）
- GET  /audit/verify         校验哈希链
- POST /audit/cleanup        触发保留期清理
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict

import uvicorn
from fastapi import FastAPI, Header, HTTPException

from audit.config import AuditConfig
from audit.middleware import AuditMiddleware
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.service import AuditService

config = AuditConfig(storage_dir=os.environ.get("AUDIT_DIR", "audit_data"))
service = AuditService(config)

app = FastAPI(title="audit-trail-python")
app.add_middleware(AuditMiddleware, service=service)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/actions/{action}")
def do_action(
    action: str,
    x_actor: str = Header(default="anonymous"),
    x_correlation_id: str | None = Header(default=None),
    x_idempotency_key: str | None = Header(default=None),
):
    """业务动作入口：非白名单动作被拒绝，两种结果都会落审计。"""
    allowed = {"read", "write", "deploy"}
    if action not in allowed:
        # 拒绝也产生审计记录（中间件按 403 落一条 DENIED）
        raise HTTPException(status_code=403, detail=f"action {action} not allowed")
    record = service.record(
        AuditEvent(
            actor=x_actor,
            action=action,
            target=f"/actions/{action}",
            outcome=Outcome.SUCCESS,
            correlation_id=x_correlation_id or "",
            idempotency_key=x_idempotency_key,
            sensitivity=Sensitivity.LOW,
        )
    )
    return {"action": action, "audit_seq": record.seq}


@app.get("/audit/records")
def list_records():
    return [
        {**asdict(r.event), "seq": r.seq, "prev_hash": r.prev_hash,
         "record_hash": r.record_hash, "anchor": r.anchor}
        for r in service.records()
    ]


@app.get("/audit/verify")
def verify():
    result = service.verify()
    return asdict(result)


@app.post("/audit/cleanup")
def cleanup(now: float | None = None):
    removed = service.cleanup(now if now is not None else time.time())
    return {"removed": removed}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
