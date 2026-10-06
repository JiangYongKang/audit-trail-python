"""审计日志链路演示服务。

入口：
- GET  /                     健康检查
- POST /actions/{action}     业务动作入口（演示被拒绝与完成两种结果）
- GET  /audit/records        查询审计记录（已脱敏）
- GET  /audit/query          条件查询 + 游标分页（正/倒序）
- GET  /audit/follow         持续跟读（长轮询，按 position 续读）
- POST /audit/export         导出可离线核验的区段
- GET  /audit/verify         校验哈希链
- POST /audit/cleanup        触发保留期清理
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from audit.config import AuditConfig
from audit.export import ExportError, ExportRequest, export_records, verify_offline
from audit.follow import (
    POSITION_START,
    FollowReader,
    PositionCompacted,
    PositionInvalid,
)
from audit.middleware import AuditMiddleware
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.query import CursorExpired, CursorInvalid, QueryFilter, QueryReader
from audit.service import AuditService

config = AuditConfig(storage_dir=os.environ.get("AUDIT_DIR", "audit_data"))
service = AuditService(config)
query_reader = QueryReader(service)
follow_reader = FollowReader(service)

app = FastAPI(title="audit-trail-python")
app.add_middleware(AuditMiddleware, service=service)


def _record_dict(r) -> dict:
    return {**asdict(r.event), "seq": r.seq, "prev_hash": r.prev_hash,
            "record_hash": r.record_hash, "anchor": r.anchor}


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
    return [_record_dict(r) for r in service.records()]


@app.get("/audit/query")
def query_records(
    start_time: float | None = None,
    end_time: float | None = None,
    actor: str | None = None,
    action: str | None = None,
    target: str | None = None,
    outcome: str | None = None,
    source: str | None = None,
    descending: bool = False,
    page_size: int = Query(default=50, ge=1, le=1000),
    cursor: str | None = None,
):
    """条件查询 + 游标分页。首页不传 cursor；翻页原样回传上一页 next_cursor。

    返回 cleaned=True 表示查询时间段与已被保留期清理的区段相交（记录并非
    “本来就没有”，而是已被清理）；游标落到清理区段返回 410 Gone。
    """
    try:
        flt = QueryFilter(
            start_time=start_time, end_time=end_time, actor=actor, action=action,
            target=target,
            outcome=Outcome(outcome) if outcome is not None else None,
            source=source,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail=f"非法 outcome: {outcome}")
    qr = QueryReader(service, page_size=page_size)
    try:
        page = qr.first_page(flt, descending=descending) if cursor is None \
            else qr.next_page(cursor, flt)
    except CursorInvalid as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except CursorExpired as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    return {
        "records": [_record_dict(r) for r in page.records],
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "cleaned": page.cleaned,
        "cleaned_up_to_seq": page.cleaned_up_to_seq,
        "cleaned_at": page.cleaned_at,
        "removed_count": page.removed_count,
        "removed_from_ts": page.removed_from_ts,
        "removed_up_to_ts": page.removed_up_to_ts,
    }


@app.get("/audit/follow")
def follow_records(
    position: str = POSITION_START,
    max_records: int = Query(default=100, ge=1, le=1000),
    wait_timeout_s: float = Query(default=0.0, ge=0.0, le=60.0),
):
    """从 position 之后跟读；断线/重启后回传上次 next_position 即可不重不漏续读。

    位置落到已清理区段返回 410 Gone（不能装作无事继续）。
    wait_timeout_s>0 时长轮询等待新记录。
    """
    try:
        batch = follow_reader.poll(position, max_records=max_records,
                                   wait_timeout_s=wait_timeout_s)
    except PositionCompacted as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    except PositionInvalid as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "records": [_record_dict(r) for r in batch.records],
        "next_position": batch.next_position,
        "waited": batch.waited,
    }


class ExportBody(BaseModel):
    start_seq: int | None = None
    end_seq: int | None = None
    start_time: float | None = None
    end_time: float | None = None
    path: str | None = None  # 同时落盘到该路径（可选）


@app.post("/audit/export")
def export_audit(body: ExportBody):
    """导出可离线核验的连续区段；区间必须从链头（或清理锚点之后第一条）开始。"""
    req = ExportRequest(start_seq=body.start_seq, end_seq=body.end_seq,
                        start_time=body.start_time, end_time=body.end_time)
    try:
        bundle = export_records(service, req)
    except ExportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if body.path:
        bundle.write(body.path)
    result = verify_offline(bundle)
    return {
        "manifest": bundle.manifest,
        "records": [_record_dict(r) for r in bundle.records],
        "offline_verify": asdict(result),
    }


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
