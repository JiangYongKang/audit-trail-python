"""HTTP 接口端到端测试：条件查询/分页、SSE 跟读续读、导出与上传离线校验。"""
from __future__ import annotations

import threading
import time

import httpx
import pytest
import uvicorn

import main as main_mod
from audit.config import AuditConfig
from audit.service import AuditService


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api-data")
    main_mod.service = AuditService(AuditConfig(storage_dir=str(tmp)))
    cfg = uvicorn.Config(main_mod.app, host="127.0.0.1", port=0,
                         log_level="warning")
    srv = uvicorn.Server(cfg)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    while not srv.started:
        time.sleep(0.01)
    sock = srv.servers[0].sockets[0]
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    yield base
    srv.should_exit = True


def _post_action(base: str, key: str, actor: str) -> None:
    r = httpx.post(f"{base}/actions/read",
                   headers={"X-Actor": actor, "X-Idempotency-Key": key},
                   timeout=5)
    assert r.status_code == 200


def _all_seqs(base: str) -> list[int]:
    rows = httpx.get(f"{base}/audit/records", timeout=5).json()
    return [r["seq"] for r in rows]


def test_query_filter_pagination_and_desc(server):
    base = server
    for i in range(6):
        _post_action(base, f"q-{i}", f"u{i % 2}")
    r = httpx.get(f"{base}/audit/query",
                  params={"actor": "u0", "limit": 2}, timeout=5).json()
    first = [x["seq"] for x in r["records"]]
    print(f"[输入] HTTP 查询 actor=u0 limit=2 | [判定] 首页 seq={first} cursor={r['next_cursor']}")
    assert len(first) == 2 and r["next_cursor"]
    r2 = httpx.get(f"{base}/audit/query",
                   params={"actor": "u0", "limit": 2, "cursor": r["next_cursor"]},
                   timeout=5).json()
    second = [x["seq"] for x in r2["records"]]
    print(f"[输入] 带 cursor 翻第 2 页 | [判定] seq={second}")
    assert not set(first) & set(second)  # 两页不重
    rd = httpx.get(f"{base}/audit/query",
                   params={"limit": 3, "desc": "true"}, timeout=5).json()
    desc_seqs = [x["seq"] for x in rd["records"]]
    print(f"[输入] desc=true limit=3 | [判定] seq={desc_seqs}")
    assert desc_seqs == sorted(desc_seqs, reverse=True) and len(desc_seqs) == 3


def test_follow_sse_resumes_after_position(server):
    base = server
    last = max(_all_seqs(base))
    got = threading.Event()
    received: list[int] = []

    def listen() -> None:
        with httpx.stream("GET", f"{base}/audit/follow",
                          params={"after": last}, timeout=10) as resp:
            for line in resp.iter_lines():
                if line.startswith("data:"):
                    import json as _json
                    received.append(_json.loads(line[5:])["seq"])
                    got.set()
                    return  # 拿到断线后续读的第一条即退出

    th = threading.Thread(target=listen, daemon=True)
    th.start()
    time.sleep(0.3)
    _post_action(base, "follow-late", "late")  # 跟读建立后再写
    got.wait(5)
    expected = max(_all_seqs(base))
    print(f"[输入] SSE after={last} 建立后写入 | [判定] 收到 seq={received} 链尾={expected}")
    assert received == [expected]  # 不重（after 之前的不来）不丢（正好是新的一条）
    th.join(timeout=3)


def test_export_and_upload_verify(server, tmp_path):
    base = server
    r = httpx.post(f"{base}/audit/export",
                   params={"seq_from": 1, "seq_to": 5}, timeout=10)
    assert r.status_code == 200
    bundle = r.content
    print(f"[输入] HTTP 导出 seq 1..5（{len(bundle)} 字节）并上传校验 | ", end="")
    v = httpx.post(f"{base}/audit/verify-bundle",
                   files={"file": ("b.json", bundle, "application/json")},
                   timeout=5).json()
    print(f"[判定] ok={v['ok']} checked={v['checked']} reason={v['reason']}")
    assert v["ok"] and v["manifest_ok"]

    # 篡改交付物后必须定位首个问题位置
    import json as _json
    data = _json.loads(bundle)
    data["records"][2]["event"]["actor"] = "mallory"
    v2 = httpx.post(
        f"{base}/audit/verify-bundle",
        files={"file": ("bad.json", _json.dumps(data), "application/json")},
        timeout=5).json()
    print(f"[输入] 上传被改写 actor 的交付物 | [判定] first_bad_seq={v2['first_bad_seq']}")
    assert not v2["ok"] and v2["first_bad_seq"] == data["records"][2]["seq"]
