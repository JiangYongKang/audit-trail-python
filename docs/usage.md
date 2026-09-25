# 使用说明

## 运行 HTTP 演示服务

```bash
uv run python run_demo.py          # http://127.0.0.1:8000
# 或 uv run python main.py
# 存储目录可用环境变量覆盖：
AUDIT_STORE=/var/lib/audit uv run python run_demo.py
```

接口：

| 方法/路径 | 说明 |
| --- | --- |
| `POST /transfer` | 业务动作；成功写 `success`，超额写 `denied/risk-rejected` |
| `GET  /audit/records?action=&operator=&correlation_id=&limit=` | 查询脱敏后的记录 |
| `GET  /audit/verify` | 校验哈希链完整性 |
| `POST /audit/purge` | 执行保留期清理 |
| `GET  /health` | 健康检查（不审计） |

示例：

```bash
curl -s -X POST localhost:8000/transfer \
  -H 'Content-Type: application/json' -H 'X-Operator: alice' \
  -H 'X-Correlation-ID: req-001' \
  -d '{"from_account":"a","to_account":"b","amount":100,
       "password":"p@ss","idempotency_key":"tx-1"}'
# -> {"status":"success","reason":null,"correlation_id":"req-001","seq":1}
# 重复提交（相同 idempotency_key）返回相同 seq，不产生重复记录

curl -s localhost:8000/audit/verify
# -> {"ok":true,"total":1,"first_bad_seq":null,...}
```

## 作为库使用（任意入口归一化）

```python
from audit.service import AuditService
from audit.storage import SegmentStore, Spool
from audit.entrypoints import normalize_http, normalize_cli

svc = AuditService(
    SegmentStore("./audit-data"),
    Spool("./audit-data/spool.jsonl"),
)

# 同一业务动作从 HTTP 或 CLI 进入，字段结构完全一致：
svc.record(normalize_http("POST", "/transfer", "alice", outcome, ...))
svc.record(normalize_cli("transfer", "alice", outcome, ...))

for record in svc.query(correlation_id="req-001"):
    print(record.to_dict())

print(svc.verify())          # VerifyResult(ok=True, ...)
print(svc.purge_expired())   # PurgeReport(removed_segments=..., anchor_seq=...)
svc.flush_spool()            # 存储故障恢复后重放 WAL
```

存储暂时不可用时 `record()` 会重试；重试用尽后事件进入 `spool.jsonl`
并抛出 `audit.storage.StorageError`，调用方应向客户端返回可重试错误
（HTTP 层映射为 `503 audit-unavailable`），而不是假装成功。

## 命令行

```bash
uv run python -m audit.cli --store ./audit-data verify   # 校验；失败退出码 2
uv run python -m audit.cli --store ./audit-data query --action login --limit 5
uv run python -m audit.cli --store ./audit-data purge    # 清理过期段
uv run python -m audit.cli --store ./audit-data flush    # 重放 spool
```

`verify` 输出示例（被改写时）：

```json
{"ok": false, "total": 6, "first_bad_seq": 3, "reason": "hash-mismatch", ...}
```

`reason` 取值：`hash-mismatch`（内容改写）、`seq-gap`（插入/删除/乱序）、
`prev-link`（断链/分叉）、`missing-anchor`（链头无有效清理锚点）、
`anchor-invalid`（锚点字段不自洽）。

## 手工验证防篡改

```bash
# 1. 制造若干记录后停服，直接改写段文件中的某个字段
python - <<'PY'
import json, glob
path = sorted(glob.glob("./audit-data/segments/*.jsonl"))[0]
line = json.loads(open(path).readline()); line["operator"] = "mallory"
open(path, "w").write(json.dumps(line, separators=(",", ":")))
PY
# 2. 校验会定位到第一个被篡改的序号
uv run python -m audit.cli --store ./audit-data verify   # exit code 2
```

## 运行测试

```bash
uv run pytest -s          # -s 打印每条用例的输入与判定依据
```

覆盖场景：多入口归一化、并发写入顺序与去重、写失败重试/WAL/重启重放、
过期清理边界与清理中并发读一致性、改写/插入/删除/乱序/无锚点截断等
人为篡改定位，以及 HTTP/CLI 端到端行为。
