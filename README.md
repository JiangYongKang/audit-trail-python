# audit-trail-python

本地可运行的审计日志链路：请求从进入、被处理到被拒绝或完成的全过程可审计，
在进程重启、并发写入与保留期清理之后依然可信、可验证。除“写进去、本地校验”外，
还提供**条件查询 / 持续跟读 / 离线导出核验**三条把审计数据“读出去、交出去”的能力。

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
| GET | `/audit/records` | 查询全部审计记录（已脱敏） |
| GET | `/audit/query` | 条件查询 + 游标分页（时间范围/操作者/动作/对象/结果/来源，正序或倒序） |
| GET | `/audit/follow` | 持续跟读（长轮询，按 `position` 断线/重启后续读） |
| POST | `/audit/export` | 导出可离线核验的连续区段（可同时落盘） |
| GET | `/audit/verify` | 校验哈希链，返回 `ok / first_bad_seq / reason / checked` |
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
| `details` | 附加上下文（落盘前按级别脱敏） |
| `source` | 事件来源（HTTP 入口采集固定为 `http`；直接写入可为空或自定义） |

落盘时在事件外包裹 `AuditRecord`：`seq`（单调递增序号）、`prev_hash`、
`record_hash`、`anchor`（是否清理锚点）。

- **定序**：序号与 `prev_hash` 在同一把锁内分配，并发下记录顺序与真实发生
  顺序一致，不分叉、不断链。
- **去重**：相同 `idempotency_key` 的重复提交直接返回首次记录。
- **写失败**：按 `write_retries` 重试（退避），重试幂等（fsync 阶段失败不产生
  重复行）；最终失败抛出 `OSError` 并记日志，不丢事件、不静默吞掉，序号不前进，
  调用方可原样重试。

## 防篡改与校验

每条记录的 `record_hash = sha256(seq + 事件全部字段 + prev_hash)`，与前面的记录
形成哈希链。`GET /audit/verify`（或 `audit.hashchain.verify_chain`）依次检查：

1. 序号连续性（缺号/重号 → 删除、插入或乱序）；
2. `prev_hash` 链接（断链 → 链指针被改动）；
3. 记录内容哈希（不匹配 → 内容被改写）。

失败时返回**首个**不一致位置的 `first_bad_seq` 与可区分的原因文案。
进程重启后从存储链尾恢复 `seq / prev_hash`，段文件轮转不影响链连续性。

## 脱敏与保留策略

脱敏在**落盘前**完成，原始值不出现在任何持久化内容或对外返回中：

| 级别 | 规则 | 默认保留期 |
| --- | --- | --- |
| `low` | 显式敏感字段（password/token/secret 等）掩码为 `***REDACTED***` | 30 天 |
| `medium` | 同 `low` | 90 天 |
| `high` | 敏感字段掩码；白名单（ip/user_agent/path/method/status）保留；其余字段单向散列 `sha256:…` | 365 天 |

**保留期清理**：`occurred_at < now - retention` 的记录过期。清理只压缩链首的
**连续过期前缀**，被移除区段由一条锚点记录（`anchor=True`）承接——锚点携带被移除
区段末尾的 `record_hash`，校验从锚点继续，清理不破坏校验结论。清理通过
临时文件 + 原子替换完成，并与查询互斥，清理进行中的查询不会看到残缺或重排的数据。

锚点的 `details` 额外记录 `removed_up_to_seq / removed_from_ts /
removed_up_to_ts / removed_count`，供查询与导出判断“哪些时间段已经被清理”。

## 条件查询（读出来）

`GET /audit/query`（或 `audit.query.QueryReader`）支持按**时间范围（两端含边界）、
操作者、动作、对象、结果、来源**过滤，并可 `descending=true` 按时间倒序看最近事件。

**游标分页与“不重不漏”**：分页基于单调序号的键集（keyset），游标 `next_cursor`
是不透明字符串，翻页原样回传即可。首页确定一个“读取窗口”（首页快照时刻的
链首锚点序号到链尾序号），之后每页只在该窗口内移动，因此：

- 翻页期间别的地方**持续写入**的新记录不会混进本次遍历，前后两页不重复、不遗漏；
  想读新数据，用（不带游标的）首页开一个新窗口即可。
- 每页都是存储锁保护下的完整快照，写入/清理并发时看不到乱序、重复或写了一半的数据。
- 游标若与本次过滤条件不一致返回 `400`（`CursorInvalid`）；游标位置已被保留期
  清理返回 `410 Gone`（`CursorExpired`），不会悄悄漏数据。

**查到已清理区间**：当查询时间段与“被保留期清理掉的记录的发生时间区间”相交时，
响应中 `cleaned=true`，并附带 `cleaned_up_to_seq / cleaned_at / removed_count /
removed_from_ts / removed_up_to_ts`。这表示这段时间的记录是“被清理过”，而不是
“本来就不存在”——不会用少返回几条来蒙混。

```
GET /audit/query?actor=alice&outcome=success&start_time=1700000000&page_size=50
GET /audit/query?action=read&descending=true&cursor=<上一页 next_cursor>
```

## 持续跟读（实时交付）

`GET /audit/follow`（或 `audit.follow.FollowReader`）让下游一直读到新记录，适合
实时告警。核心是**续读位置 `position`**，语义为“已经读到的最后一条记录序号”：

- 首次调用不传（= `0`，从链头开始）；每次响应带 `next_position`，下游持久化它。
- 断线 / 下游重启后，把上次的 `next_position` 原样传回，即从其后一条继续，
  **不丢、不重**；返回顺序严格按序号升序，与真实写入（定序）顺序一致。
- `wait_timeout_s > 0` 时长轮询等待新记录；返回 `waited` 标识本次是否发生等待。
- 若手里的位置已落入被保留期清理的区段（`position < 当前锚点序号`），返回
  `410 Gone`（`PositionCompacted`）并给出当前最早可读序号——**明确报错，绝不装作
  没事往下走**；位置无法解析返回 `400`（`PositionInvalid`）。下游应从锚点之后
  重新开始跟读，并按业务处理那段无法补读的缺口。
- 跟读内容即落盘内容，天然不含脱敏前原文。

```
GET /audit/follow?max_records=100&wait_timeout_s=5
GET /audit/follow?position=152        # 重启/断线后从 seq152 之后续读
```

## 离线导出与核验（离线交付）

`POST /audit/export`（或 `audit.export.export_records`）把一段记录导出为
**自包含 JSON 包**（清单 `manifest` + 记录 + 包摘要 `bundle_digest`），可拷到
**没有本服务、也没有原始存储**的机器上独立检查。

- **区间**：按序号（`start_seq/end_seq`，优先）或时间范围（`start_time/end_time`）
  选择。哈希链只能对**连续区段**自证，因此区间起点必须是链头（`seq=1`）或
  **清理锚点之后的第一条**；否则返回 `400`，不产出看似合法实则断裂的包。
- **带上清理接续点**：若区间起点之前发生过保留期清理，导出包会把链首锚点一并
  打包（`manifest.includes_anchor=true / anchor_seq=…`），并记录子链起始哈希
  凭据 `start_prev_hash`。离线核验从 GENESIS 或该锚点/凭据起续，导出段即可自证连续。
- **不拖垮服务**：导出先在存储锁内用硬链接（跨设备自动回退拷贝）瞬间拍下段文件
  快照，再在快照上慢慢筛选；与写入/清理并发时结果不会变成半截或错序，大数据量也
  不长时间占用服务锁。
- **不含原文**：导出的就是落盘的已脱敏内容，脱敏前原始值不会进入导出包。

**离线核验**只需 Python 标准库（连同 `audit/` 目录一起拷走即可，不需要服务在运行、
不需要原始存储目录）：

```bash
# 在离线机器上：先看包摘要是否被改动，再逐段校验哈希链
python audit/export.py verify 导出文件.json
# 通过退出码 0；失败退出码 1，并打印第一个出问题的 seq 与原因
```

核验两层：先比对 `bundle_digest`（包级增删/替换/改清单立即暴露），再校验哈希链。
被**改写、插入、删除、调序**都会返回 `ok=false` 和 `first_bad_seq`（第一个出问题
的位置）及可区分原因；即便攻击者重算了包摘要，也无法伪造每条记录的内容哈希与链指针，
第一个断裂点仍会被定位。

## 对现有记录格式与校验结论的兼容范围

- 新增的事件字段 `source` 缺省为空；`source` 为空时**不进入哈希规范载荷**，因此
  升级前写出的旧段文件（无 `source`）读取后重算哈希与落盘一致，`/audit/verify`
  结论不变（见 `tests/test_compat.py`）。
- 清理锚点 `details` 新增 `removed_from_ts / removed_up_to_ts` 等仅为附加信息，
  不参与哈希载荷之外的校验路径；旧锚点缺少时间区间信息时，查询会保守地按
  “可能命中已清理”告知（宁可提示，不静默）。
- 导出包 `manifest.version=1`；离线核验只认包内自带的链头凭据与摘要，不依赖线上
  当前存储状态。

## 配置项（`audit.config.AuditConfig`）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `storage_dir` | `audit_data` | 段文件存储目录（也可用环境变量 `AUDIT_DIR`） |
| `max_file_bytes` | 1048576 | 单段大小上限，超过即轮转 |
| `write_retries` | 3 | 写失败重试次数 |
| `retry_backoff_s` | 0.05 | 重试退避基数（秒） |
| `retention_days` | low=30 / medium=90 / high=365 | 各级别保留期（天） |

## 代码结构

```
audit/
  models.py      事件/记录/校验结果模型
  hashchain.py   哈希链计算与校验（首个不一致定位）
  redaction.py   按敏感级别脱敏
  store.py       JSONL 段文件存储：轮转、幂等重试、锚点式清理、一致性快照
  service.py     定序、去重、链式落盘、重启恢复
  query.py       条件查询 + 游标分页 + 已清理区间告知
  follow.py      持续跟读：按位置续读、清理区段显式报错
  export.py      离线导出与核验（含 export.py verify 命令行）
  middleware.py  HTTP 入口采集
  config.py      配置项
tests/           并发、重试、清理边界、脱敏、篡改、查询、跟读、导出、兼容等测试
```

## 本地复现验证

```bash
# 1) 全量单测（-s 打印每条用例的“[输入] … [判定] …”）
uv run pytest -s

# 2) 起服务后手工走一遍（端口见启动日志）
uv run python main.py
curl -X POST localhost:<port>/actions/read -H 'X-Actor: alice' -H 'X-Idempotency-Key: a1'
curl 'localhost:<port>/audit/query?actor=alice&page_size=10'
curl 'localhost:<port>/audit/follow?wait_timeout_s=1'
curl -X POST localhost:<port>/audit/export -H 'Content-Type: application/json' \
     -d '{"start_seq":1,"path":"/tmp/audit-bundle.json"}'

# 3) 把 audit/ 目录与导出文件拷到一台“离线”机器，仅用标准库核验
python audit/export.py verify /tmp/audit-bundle.json
```
