import json
import os

from audit.cli import main

from conftest import make_event, make_service


def test_cli_verify_and_query(tmp_dir, capsys):
    # Lay out storage exactly as the CLI expects: <root>/segments + spool.
    service = make_service(tmp_dir)
    service.record(make_event(action="login"))
    root = os.path.join(tmp_dir, "store")

    code = main(["--store", root, "verify"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0 and payload["ok"] and payload["total"] == 1

    code = main(["--store", root, "query", "--action", "login"])
    out = capsys.readouterr().out
    lines = [json.loads(line) for line in out.splitlines()]
    assert code == 0 and len(lines) == 1 and lines[0]["action"] == "login"
    print(f"[cli verify] {payload}")
    print(f"[cli query] returned seq={lines[0]['seq']}")


def test_cli_reports_failure_exit_code(tmp_dir, capsys):
    service = make_service(tmp_dir)
    service.record(make_event(action="login"))
    root = os.path.join(tmp_dir, "store")
    seg = sorted(os.listdir(os.path.join(root, "segments")))[0]
    path = os.path.join(root, "segments", seg)
    data = json.loads(open(path).read())
    data["operator"] = "TAMPERED"
    open(path, "w").write(json.dumps(data, separators=(",", ":")))

    code = main(["--store", root, "verify"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    print(f"[cli verify tampered] exit={code} payload={payload}")
    assert code == 2 and payload["ok"] is False
    assert payload["first_bad_seq"] == 1
