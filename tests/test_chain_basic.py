"""Basic sealing, normalization and idempotency behavior."""
from audit.entrypoints import normalize_cli, normalize_http, normalize_job
from audit.models import Outcome, Sensitivity
from audit.storage import SegmentStore

from conftest import make_event, make_service


def test_normalized_event_from_any_entrypoint_has_stable_fields(tmp_dir):
    service = make_service(tmp_dir)
    base = dict(
        operator="alice",
        outcome=Outcome.SUCCESS,
        fields={"password": "hunter2"},
    )
    h = normalize_http("POST", "/transfer", idempotency_key="k-http", **base)
    c = normalize_cli("transfer", idempotency_key="k-cli", **base)
    j = normalize_job("transfer", idempotency_key="k-job", **base)
    for label, event in [("http", h), ("cli", c), ("job", j)]:
        record = service.record(event)
        print(f"[input:{label}] -> seq={record.seq} action={record.action} "
              f"fields={record.fields}")
        assert record.operator == "alice"
        assert record.idempotency_key == f"k-{label}"
        assert record.fields["password"] == "***"
        assert "hunter2" not in str(record.to_dict())
        assert record.entrypoint == label
    result = service.verify()
    print(f"[judgement] verify ok={result.ok} total={result.total}")
    assert result.ok and result.total == 3


def test_denied_event_records_reason(tmp_dir):
    service = make_service(tmp_dir)
    event = make_event(outcome=Outcome.DENIED, reason="risk-rejected")
    record = service.record(event)
    print(f"[input] outcome=denied reason=risk-rejected -> "
          f"outcome={record.outcome} reason={record.reason}")
    assert record.outcome == "denied"
    assert record.reason == "risk-rejected"
    assert service.verify().ok


def test_duplicate_submission_writes_once(tmp_dir):
    service = make_service(tmp_dir)
    event = make_event(key="idem-1")
    first = service.record(event)
    second = service.record(event)
    third = service.record(make_event(key="idem-1", correlation_id="cid-other"))
    print(f"[input] same idempotency_key submitted 3x -> seqs "
          f"{first.seq},{second.seq},{third.seq}")
    assert first is second is third or first.seq == second.seq == third.seq
    assert len(service.query()) == 1
    assert service.verify().ok


def test_records_link_hash_chain(tmp_dir):
    service = make_service(tmp_dir)
    records = [service.record(make_event(action=f"a{i}", ts=100.0 + i))
               for i in range(5)]
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.record_hash
        assert cur.seq == prev.seq + 1
    print(f"[judgement] 5 records chained genesis..{records[-1].record_hash[:8]}")
    assert service.verify().ok
