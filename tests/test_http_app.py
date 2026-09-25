"""End-to-end behavior through the HTTP entry point."""
from fastapi.testclient import TestClient

from audit.app import create_app

from conftest import make_service


def _client(tmp_dir):
    return TestClient(create_app(make_service(tmp_dir)))


def test_success_denied_and_audit_trail(tmp_dir):
    client = _client(tmp_dir)
    ok = client.post("/transfer", json={
        "from_account": "acct-a", "to_account": "acct-b", "amount": 100,
        "password": "abc123", "idempotency_key": "tx-1",
    }, headers={"X-Operator": "alice"})
    assert ok.status_code == 200
    assert ok.json()["status"] == "success"
    cid = ok.json()["correlation_id"]

    denied = client.post("/transfer", json={
        "from_account": "acct-a", "to_account": "acct-b", "amount": 99_999,
    }, headers={"X-Operator": "alice"})
    print(f"[input] amount=99999 -> {denied.json()}")
    assert denied.json()["status"] == "denied"
    assert denied.json()["reason"] == "risk-rejected"

    records = client.get("/audit/records",
                         params={"correlation_id": cid}).json()["records"]
    print(f"[query correlation_id={cid}] -> {len(records)} record(s)")
    assert len(records) == 1
    assert records[0]["fields"]["password"] == "***"
    verify = client.get("/audit/verify").json()
    print(f"[judgement] /audit/verify -> {verify}")
    assert verify["ok"] and verify["total"] == 2
    purge = client.post("/audit/purge").json()
    assert "anchor_seq" in purge


def test_idempotent_http_retry(tmp_dir):
    client = _client(tmp_dir)
    payload = {"from_account": "a", "to_account": "b", "amount": 1,
               "idempotency_key": "retry-1"}
    first = client.post("/transfer", json=payload).json()
    second = client.post("/transfer", json=payload).json()
    print(f"[input] same payload POSTed twice -> seqs {first['seq']}, "
          f"{second['seq']}")
    assert first["seq"] == second["seq"]


def test_audit_backend_failure_returns_503_and_keeps_event(tmp_dir):
    service = make_service(tmp_dir)
    def boom():
        raise OSError("io")
    service.store.fault_hook = boom
    client = TestClient(create_app(service), raise_server_exceptions=False)
    response = client.post("/transfer", json={
        "from_account": "a", "to_account": "b", "amount": 1,
    })
    print(f"[input] storage down -> http {response.status_code} "
          f"body={response.json()}")
    assert response.status_code == 503
    assert response.json()["detail"] == "audit-unavailable"
    assert len(service.spool) == 1, "failed audit event must be in the WAL"
