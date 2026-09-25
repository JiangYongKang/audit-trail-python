"""脱敏测试：敏感字段不落盘、不出现在对外返回；各级别策略差异。"""
from __future__ import annotations

from pathlib import Path

from audit.config import AuditConfig
from audit.models import AuditEvent, Outcome, Sensitivity
from audit.redaction import MASK, redact_event
from audit.service import AuditService


def _event(sensitivity: Sensitivity, details: dict) -> AuditEvent:
    return AuditEvent(actor="alice", action="login", target="auth",
                      outcome=Outcome.DENIED, deny_reason="bad_password",
                      correlation_id="c1", sensitivity=sensitivity,
                      occurred_at=1.0, details=details)


def test_medium_masks_sensitive_keys():
    e = _event(Sensitivity.MEDIUM, {"password": "s3cret", "token": "tok-1", "note": "ok"})
    r = redact_event(e)
    print(f"[输入] MEDIUM details={e.details} | [判定] 脱敏后={r.details}")
    assert r.details["password"] == MASK
    assert r.details["token"] == MASK
    assert r.details["note"] == "ok"


def test_high_hashes_non_whitelist_fields():
    e = _event(Sensitivity.HIGH,
               {"password": "s3cret", "email": "a@b.c", "ip": "10.0.0.1"})
    r = redact_event(e)
    print(f"[输入] HIGH details={e.details} | [判定] 脱敏后={r.details}")
    assert r.details["password"] == MASK
    assert r.details["email"].startswith("sha256:")
    assert r.details["ip"] == "10.0.0.1"  # 白名单字段保留


def test_raw_values_never_persisted_or_returned(tmp_path):
    svc = AuditService(AuditConfig(storage_dir=str(tmp_path)))
    secret_pwd = "p@ssw0rd-绝密"
    secret_mail = "spy@example.com"
    svc.record(_event(Sensitivity.HIGH,
                      {"password": secret_pwd, "email": secret_mail, "ip": "1.1.1.1"}))

    # 1) 持久化内容中不得出现原始值
    persisted = "".join(p.read_text(encoding="utf-8")
                        for p in Path(tmp_path).glob("segment-*.jsonl"))
    # 2) 对外返回（records 接口的数据）中不得出现原始值
    returned = str(svc.records())

    ok_disk = secret_pwd not in persisted and secret_mail not in persisted
    ok_api = secret_pwd not in returned and secret_mail not in returned
    print(f"[输入] HIGH 事件含原始密码/邮箱 | "
          f"[判定] 落盘无原文={ok_disk} 返回无原文={ok_api} 链校验={svc.verify().ok}")
    assert ok_disk and ok_api
    assert svc.verify().ok  # 脱敏后链依然可校验
