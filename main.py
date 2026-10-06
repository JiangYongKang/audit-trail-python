"""审计日志链路演示服务。

入口：
- GET  /                     健康检查
- POST /actions/{action}     业务动作入口（演示被拒绝与完成两种结果）
- GET  /audit/records        全量查看审计记录（已脱敏，兼容旧用法）
- GET  /audit/query          条件查询（时间窗/操作者/动作/对象/结果/来源 + 分页 + 倒序）
- GET  /audit/follow         持续跟读（SSE 长连接，after 指定续读位置）
- POST /audit/export         按区间导出交付物（JSON 文件）
- POST /audit/verify-bundle  离线校验上传的导出交付物
- GET  /audit/verify         校验本地哈希链
- POST /audit/cleanup        触发保留期清理
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from audit.config import AuditConfig
from audit.export import (
    export_range,
    manifest_from_dict,
    verify_bundle,
    write_bundle,
)
from audit.follow import CursorExpiredError, FollowReader
from audit.middleware import AuditMiddleware
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.query import QueryFilter
from audit.service import AuditService
from audit.store import record_to_line

config = AuditConfig(storage_dir=os.environ.get("AUDIT_DIR", "audit_data"))
service = AuditService(config)

app = FastAPI(title="audit-trail-python")
app.add_middleware(AuditMiddleware, service=service)


def _record_dto(r) -> dict:
    return {**asdict(r.event), "seq": r.seq, "prev_hash": r.prev_hash,
            "record_hash": r.record_hash, "anchor": r.anchor}


def _gap_dto(gap) -> dict | None:
    return None if gap is None else asdict(gap)


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
            source="http",
        )
    )
    return {"action": action, "audit_seq": record.seq}


@app.get("/audit/records")
def list_records():
    return [_record_dto(r) for r in service.records()]


@app.get("/audit/query")
def query_records(
    start_time: float | None = None,
    end_time: float | None = None,
    actor: str | None = None,
    action: str | None = None,
    target: str | None = None,
    outcome: str | None = None,
    source: str | None = None,
    limit: int = Query(default=50, gt=0, le=1000),
    cursor: str | None = None,
    desc: bool = False,
):
    """条件分页查询。

    时间窗为左闭右开 [start_time, end_time)；响应中的 next_cursor 用于
    翻下一页；命中已清理区段时返回 cleaned_gap 提示。
    """
    try:
        outcome_enum = Outcome(outcome) if outcome is not None else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"非法 outcome: {outcome}")
    flt = QueryFilter(start_time=start_time, end_time=end_time, actor=actor,
                      action=action, target=target, outcome=outcome_enum,
                      source=source)
    try:
        page = service.query(flt, limit=limit, cursor=cursor, descending=desc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "records": [_record_dto(r) for r in page.records],
        "next_cursor": page.next_cursor,
        "cleaned_gap": _gap_dto(page.cleaned_gap),
    }


@app.get("/audit/follow")
def follow(after: int = Query(default=0, ge=0), limit: int = Query(default=100, gt=0)):
    """SSE 持续跟读。after 为上次读到的 seq（断线/重启后原样带回）。

    每个事件帧 data 为一条记录 JSON；游标失效（位置落入已清理区段）时推送
    error 帧后结束。
    """
    reader = FollowReader(service, start_after=after, batch_limit=limit)

    def event_stream():
        try:
            while True:
                try:
                    batch = reader.read_batch(timeout=15.0)
                except CursorExpiredError as exc:
                    yield f"event: error\ndata: {json.dumps({'reason': str(exc)})}\n\n"
                    return
                for rec in batch:
                    yield f"data: {record_to_line(rec)}\n\n"
        finally:
            reader.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/audit/export")
def export_records(
    seq_from: int | None = None,
    seq_to: int | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
):
    """按 seq 区间（闭区间）和/或时间窗（左闭右开）导出，返回 JSON 交付文件。"""
    try:
        manifest = export_range(service, seq_from=seq_from, seq_to=seq_to,
                                start_time=start_time, end_time=end_time)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    out_dir = Path(tempfile.mkdtemp(prefix="audit-export-"))
    path = write_bundle(manifest, out_dir / "audit-export.json")
    return FileResponse(path, filename="audit-export.json",
                        media_type="application/json")


@app.post("/audit/verify-bundle")
async def verify_uploaded_bundle(file: UploadFile):
    """离线校验：上传导出的 JSON 交付物，返回清单一致性与链校验结论。"""
    raw = await file.read()
    try:
        manifest = manifest_from_dict(json.loads(raw.decode("utf-8")))
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"交付物解析失败: {exc}")
    res = verify_bundle(manifest)
    return {
        "manifest_ok": res.manifest_ok,
        "ok": res.verify.ok,
        "first_bad_seq": res.verify.first_bad_seq,
        "reason": res.reason,
        "checked": res.verify.checked,
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
