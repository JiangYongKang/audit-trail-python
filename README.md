# audit-trail-python

本地可运行的审计日志链路：请求从进入、被处理到被拒绝或完成的全过程可审计，
在进程重启、并发写入与保留期清理之后依然可信、可验证；并支持**条件查询、
持续跟读、离线交付核验**三条读链路。

## 运行

```bash
uv run python main.py          # 启动服务（AUDIT_DIR 环境变量指定存储目录，默认 audit_data/）
uv run pytest -s               # 运行测试（-s 可看到每条用例的输入与判定依据）
```

### HTTP 入口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 健康检查 |
| POST | `/actions/{action}` | 业务动作入口（`read/write/deploy` 之外的 action 返回 403，拒绝同样落审计） |
| GET | `/audit/records` | 全量查看审计记录（已脱敏，兼容旧用法） |
| GET | `/audit/query` | 条件查询：时间窗/操作者/动作/对象/结果/来源 + 分页 + 倒序 |
| GET | `/audit/follow` | 持续跟读（SSE 长连接，`after` 指定续读位置） |
| POST | `/audit/export` | 按区间导出自核验交付物（JSON 文件） |
| POST | `/audit/verify-bundle` | 上传交付物做离线式核验（返回首个问题位置） |
| GET | `/audit/verify` | 校验本地哈希链 |
| POST | `/audit/cleanup` | 触发保留期清理（可选 `now` 参数便于测试） |

请求头：`X-Actor`（操作者）、`X-Correlation-ID`（关联标识，缺省自动生成）、
`X-Idempotency-Key`（幂等键，重复提交不产生重复记录）。

## 事件模型

每个入口的请求都被归一化为一条 `AuditEvent`，字段稳定、可用于追责：

| 字段 | 含义 |
| --- | --- |
| `actor` | 操作者 |
| `action` | 动作（HTTP 入口为 `METHOD path`） |
| `target` | 操作对象 |
| `outcome` | `success / denied / error` |
| `deny_reason` | 拒绝原因（仅拒绝时） |
| `correlation_id` | 关联标识，串联同一请求的多条记录 |
| `idempotency_key` | 幂等键；重复提交返回首次记录，不产生新记录 |
| `sensitivity` | 敏感级别 `low / medium / high` |
| `occurred_at` | 发生时间（Unix 秒） |
| `source` | 来源（HTTP 入口自动填 `http`），可按来源过滤/跟读 |
| `details` | 附加上下文（落盘前按级别脱敏） |

落盘时在事件外包裹 `AuditRecord`：`seq`（单调递增序号）、`prev_hash`、
`record_hash`、`anchor`（是否清理锚点）。

- **定序**：序号与 `prev_hash` 在同一把锁内分配，并发下记录顺序与真实发生
  顺序一致，不分叉、不断链。
- **去重**：相同 `idempotency_key` 的重复提交直接返回首次记录。
- **写失败**：按 `write_retries` 重试（退避），重试幂等（fsync 阶段失败不产生
  重复行）；最终失败抛出 `OSError` 并记日志，不丢事件、不静默吞掉，序号不前进，
  调用方可原样重试。

## 条件查询

```python
from audit.query import QueryFilter
page = service.query(
    QueryFilter(start_time=t0, end_time=t1,     # 时间窗左闭右开 [start, end)
                actor="alice", action="read",   # 各字段为精确匹配
                target="doc", outcome=Outcome.SUCCESS, source="http"),
    limit=50, cursor=None, descending=False,
)
page.records       # 本页记录
page.next_cursor   # 下一页游标（不透明字符串）；为 None 表示没有下一页
page.cleaned_gap   # 命中已清理区段时的提示，否则为 None
```

HTTP：`GET /audit/query?actor=alice&limit=50&cursor=...&desc=true`

- **分页语义（不重不漏）**：采用键集分页而非 OFFSET。游标内容是“上一页最后
  一条记录的 `seq`”；正序下一页只取 `seq > cursor`，倒序只取 `seq < cursor`，
  因此相邻两页天然不重、不漏。写入只发生在链尾，翻页期间的新记录只会出现在
  后续页，不会让已取页重排。
- **倒序看最近**：`descending=True`（HTTP 传 `desc=true`），首页即最新的一页。
- **查到已清理区间**：保留期清理会移除链首过期记录并留下锚点。若查询时间窗与
  被清理区段重叠，响应携带 `cleaned_gap`（含被清理的序号区间、时间跨度、条数），
  **明确告知“这段已经被清理”**，而不是悄悄少返回几条；窗口完全落在已清理段
  （记录为空）时同样返回该提示。翻页时该提示只在首页出现一次。
- **读一致性**：每次查询在服务锁内取一致性快照，与写入/清理互斥，不会看到
  乱序、重复或只写了一半的数据。

## 持续跟读

```python
from audit.follow import FollowReader, CursorExpiredError

reader = FollowReader(service, start_after=0)   # 0 = 从现存最旧记录开始
batch = reader.read_batch(timeout=15.0)         # 阻塞至有新记录或超时
pos = reader.position()                         # 保存这个位置：已读到的最后一条 seq
reader.close()
# 断线/下游重启后，原样带回位置即可续读：
reader2 = FollowReader(service, start_after=pos)
```

HTTP：`GET /audit/follow?after=<pos>`（SSE，每个 `data:` 帧是一条记录 JSON；
位置失效时推送 `event: error` 帧）。

- **续读位置含义**：游标 = 已读到的最后一条记录的 `seq`。只返回
  `seq > cursor` 的记录，严格续读——游标之后的一条不丢，游标及以前的一条不重。
  顺序就是写入定序的 seq 顺序，与真实发生顺序一致。
- **重启**：seq 与哈希链一起持久化，服务重启后同一游标仍可识别。
- **位置落入已清理区段**：若 `0 < cursor <= 锚点 seq`（游标最后读过的记录已被
  保留期清理，或等待期间被清理推进覆盖），立即抛出 `CursorExpiredError`
  （SSE 为 error 帧），**不会装作无事继续往下走**；调用方应改用区间导出获取
  接续点，或从现存最旧记录重新跟读。
- 跟读返回的是落盘后的记录，同样已经脱敏，不会带出敏感原文。

## 离线交付与核验

```python
from audit.export import export_range, write_bundle, read_bundle, verify_bundle

manifest = export_range(service, seq_from=100, seq_to=199)   # seq 闭区间
# 或按时间窗（左闭右开）：export_range(service, start_time=t0, end_time=t1)
path = write_bundle(manifest, "audit-export.json")           # 单个 JSON 文件
```

HTTP：`POST /audit/export?seq_from=100&seq_to=199` 直接下载 JSON 文件。

交付物是**自描述的单个 JSON 文件**：含格式版本、导出时间、序号区间、记录数组
（与段文件相同的规范 JSONL 行格式）、记录数，以及（如有）被清理区段声明。

**在没有本服务、没有原始存储的机器上核验**（把 `audit/` 目录和导出文件拷过去，
仅需 Python 标准库）：

```bash
python offline_verify.py audit-export.json
# 或上传到任一运行中的本服务：POST /audit/verify-bundle
```

- **自证连续**：核验先对清单声明（版本、记录数、序号区间、锚点声明），再从
  接续点跑哈希链校验。被改写内容、插入一条、删除一条、调换顺序都会失败并返回
  **第一个出问题的位置** `first_bad_seq` 与区分性原因。
- **接续点随附**：若请求区间与已清理区段重叠，导出会把链首**锚点**（承载被移除
  区段末尾哈希的接续点）一并带上，并在 `cleaned` 字段声明被清理的序号/时间跨度
  与条数；请求区间已全部被清理时，交付物仅含锚点。从链中间开始（起点之前的
  记录仍存活但未导出）的交付物，首条记录的 `prev_hash` 即清单声明的链外信任
  边界。
- **导出一致性**：导出在服务锁内取一份一致性快照（与写入/清理互斥），序列化与
  写文件在锁外只操作内存快照，导出过程中并发写入/清理不会产生半截或错序结果，
  数据量大也不会长时间拖住正常服务。
- **不含原始值**：导出的就是落盘内容，而脱敏在落盘前完成，交付物不可能含脱敏前
  的原始值。

### 离线核验结果含义

| 输出 | 含义 |
| --- | --- |
| `manifest_ok=true` 且 `链校验=true` | 清单声明一致且链完整（或仅交付了合法接续点） |
| `manifest_ok=false` | 交付物被截断/增删、版本不符、区间与记录不一致 |
| `链校验=false, first_bad_seq=N` | 第 N 条是第一个对不上的位置（改写/插入/删除/乱序） |

## 防篡改与校验

每条记录的 `record_hash = sha256(seq + 事件全部字段 + prev_hash)`，与前面的记录
形成哈希链。`GET /audit/verify`（或 `audit.hashchain.verify_chain`）依次检查：

1. 序号连续性（缺号/重号 → 删除、插入或乱序）；
2. `prev_hash` 链接（断链 → 链指针被改动）；
3. 记录内容哈希（不匹配 → 内容被改写）。

失败时返回**首个**不一致位置的 `first_bad_seq` 与可区分的原因文案。
进程重启后从存储链尾恢复 `seq / prev_hash`，段文件轮转不影响链连续性。

## 脱敏与保留策略

脱敏在**落盘前**完成，原始值不出现在任何持久化内容或对外返回中（查询结果、
跟读流、离线交付物三者同样如此）：

| 级别 | 规则 | 默认保留期 |
| --- | --- | --- |
| `low` | 显式敏感字段（password/token/secret 等）掩码为 `***REDACTED***` | 30 天 |
| `medium` | 同 `low` | 90 天 |
| `high` | 敏感字段掩码；白名单（ip/user_agent/path/method/status）保留；其余字段单向散列 `sha256:…` | 365 天 |

**保留期清理**：`occurred_at < now - retention` 的记录过期。清理只压缩链首的
**连续过期前缀**，被移除区段由一条锚点记录（`anchor=True`）承接——锚点携带被移除
区段末尾的 `record_hash`（校验从锚点继续，无法被旧内容重放伪造）、被清理的序号
区间与时间跨度（供查询提示与导出声明）。清理通过临时文件 + 原子替换完成，并在
服务锁内与查询/跟读/导出互斥，不会让任何读链路看到残缺或重排的数据。

## 兼容性

- **记录格式**：新增的 `source` 字段对历史记录向后兼容——旧文件没有该字段时按
  空串读取，且空 `source` 不参与哈希载荷，旧记录重算哈希结果不变，老数据无需
  迁移。
- **校验结论**：`GET /audit/verify` 与 `verify_chain` 的判定逻辑和结论字段
  （`ok / first_bad_seq / reason / checked`）保持不变；新增的
  `verify_segment` 仅服务于离线交付的“从中间/锚点开始校验”场景。
- **锚点格式**：锚点 details 新增字段（被清理序号/时间跨度等）为附加声明，
  锚点的哈希语义（承载被移除区段末尾哈希）不变，历史锚点仍按仅有序号信息处理。
- 旧的 `GET /audit/records` 全量读取接口保留。

## 配置项（`audit.config.AuditConfig`）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `storage_dir` | `audit_data` | 段文件存储目录（也可用环境变量 `AUDIT_DIR`） |
| `max_file_bytes` | 1048576 | 单段大小上限，超过即轮转 |
| `write_retries` | 3 | 写失败重试次数 |
| `retry_backoff_s` | 0.05 | 重试退避基数（秒） |
| `retention_days` | low=30 / medium=90 / high=365 | 各级别保留期（天） |

## 本地复现验证

```bash
uv run pytest -s                       # 全量（每条用例打印 [输入]/[判定]）
uv run pytest tests/test_query.py -s   # 条件边界/分页不重不漏/已清理区间/并发一致性
uv run pytest tests/test_follow.py -s  # 阻塞等待/断线与重启续读/顺序/游标失效/无原文
uv run pytest tests/test_export.py -s  # 区间导出/锚点随附/篡改定位/并发导出/无原文
uv run pytest tests/test_api.py -s     # HTTP 端到端（真实 uvicorn + SSE 跟读）
uv run pytest tests/test_service.py tests/test_retention.py tests/test_hashchain.py tests/test_redaction.py -s  # 旧场景不回归
```

离线核验手工复现：

```bash
uv run python main.py            # 另一个终端：
# curl -XPOST 'localhost:PORT/actions/read' -H 'X-Idempotency-Key: a'（多打几条）
# curl -XPOST 'localhost:PORT/audit/export?seq_from=1&seq_to=3' -o audit-export.json
# （可选）手改 JSON 中某条 event 的 actor
uv run python offline_verify.py audit-export.json
```

## 代码结构

```
audit/
  models.py      事件/记录/校验结果模型
  hashchain.py   哈希链计算与校验（整链 + 从中间/锚点开始，首个不一致定位）
  redaction.py   按敏感级别脱敏
  store.py       JSONL 段文件存储：轮转、幂等重试、锚点式清理
  service.py     定序、去重、链式落盘、重启恢复、锁内快照（查询/跟读/导出共用）
  query.py       条件过滤、键集分页（正/倒序）、已清理区间提示
  follow.py      持续跟读：按游标续读、阻塞等待、游标失效报错
  export.py      区间导出、交付物读写、离线核验（清单一致性 + 哈希链）
  middleware.py  HTTP 入口采集
  config.py      配置项
main.py          HTTP 入口（查询/跟读 SSE/导出/上传核验）
offline_verify.py 离线核验 CLI（仅依赖标准库）
tests/           并发、重试、清理边界、篡改、查询、跟读、导出等场景测试
```
