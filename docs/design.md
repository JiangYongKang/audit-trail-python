# 审计日志链路设计

本文档说明审计事件模型、落盘格式、哈希链校验、脱敏与保留策略以及关键配置项。

## 1. 事件模型（归一化）

无论请求从 HTTP、CLI 还是定时作业进入，都被归一化为同一个 `AuditEvent`，
再由 `AuditService` 封存为 `AuditRecord`：

| 字段 | 含义 |
| --- | --- |
| `operator` | 操作者（HTTP 取 `X-Operator`，缺省 `anonymous`） |
| `action` | 业务动作，带入口前缀，如 `http:POST /transfer`、`cli:backup`、`job:report` |
| `object` | 操作对象 |
| `outcome` | `success` / `denied` / `error` |
| `reason` | 被拒绝或失败的机器可读原因，如 `risk-rejected` |
| `correlation_id` | 关联标识（HTTP 取 `X-Correlation-ID`，缺省自动生成），可跨系统串联同一请求 |
| `idempotency_key` | 幂等键，重复提交同一业务动作只产生一条记录 |
| `sensitivity` | 敏感级别：`public` / `internal` / `sensitive` / `regulated` |
| `fields` | 业务附加字段，落盘前按脱敏策略处理 |
| `entrypoint` | 实际入口：`http` / `cli` / `job` / `system` |
| `occurred_at` | 事件时间（UNIX 秒），缺省取服务时钟 |

封存后的 `AuditRecord` 额外包含链信息：

* `seq`：全局连续递增序号；
* `ts`：封存时间；
* `prev_hash`：前一条记录的 `record_hash`，首条为 64 个 0（创世哈希）；
* `record_hash`：对本条内容与前驱的封印哈希。

### 顺序、并发与幂等

* 封存（分配序号、计算哈希）与追加写入在同一把可重入锁内完成，因此
  并发提交时磁盘上的顺序就是真实提交顺序，序号连续、不会分叉。
* `idempotency_key` 在进程内做去重，服务重启后从已有链重建去重索引；
  同一键的重复提交直接返回已落盘记录。
* 写入先在进程内重试（默认 3 次，指数退避）；全部失败时事件进入
  **WAL 缓冲盘（spool）** 并向上抛出错误，绝不静默吞掉。恢复后
  `flush_spool` / `python -m audit.cli flush` 按序重放。

## 2. 存储格式

```
<store>/
  segments/
    seg-000000000001-000000000050.jsonl
    seg-000000000051-000000000100.jsonl
  spool.jsonl
```

* 段文件为 JSONL，每行一条规范化 JSON 记录；文件名按序号区间命名，
  文件名排序即链顺序，进程重启与轮转后顺序不变。
* 段大小达到 `rotate_bytes`（默认 1 MiB）后轮转：先将旧段重命名为
  真实尾序号文件名，再开新段。
* 每次写入都 `flush + fsync`；写失败时以磁盘状态为准重新装载后再报错。

## 3. 防篡改哈希链与校验

封印计算：

```
body        = 除 prev_hash/record_hash 外的全部字段
record_hash = sha256(canonical_json({"prev": prev_hash, "body": body}))
```

`canonical_json` 采用键排序、固定分隔符、无空白的 UTF-8 JSON，保证跨进程
结果一致。

`SegmentStore.verify()` 按物理顺序逐条检查，返回 `VerifyResult`：

1. **序号连续** —— 检测插入 / 删除 / 乱序（`reason=seq-gap`）；
2. **封印哈希** —— 重新计算并比对，检测内容改写（`reason=hash-mismatch`）；
3. **前驱链接** —— `prev_hash` 必须等于上一条哈希，检测断链 / 分叉
   （`reason=prev-link`）；
4. **链头锚点** —— 清理后链头的前驱已不存在，必须有清理锚点恰好证明该
   切口（序号与哈希同时匹配），否则判定 `missing-anchor`。

`first_bad_seq` 给出**首个**不一致位置；校验在进程重启、段轮转、保留期
清理后均可连续进行。

### 清理锚点（purge anchor）

过期清理采用“**先追加锚点并 fsync，再删除过期段**”的顺序：

* 锚点本身是一条普通的链式记录（`action=audit.purge`，
  `sensitivity=regulated`），字段包含被删除最后一条记录的
  `removed_through_seq` 与 `removed_through_hash`、删除条数、各级别截止时间；
* 因此清理后链头的“悬空前驱”由锚点背书，验证仍然成立；
* 若有人直接删除头部段文件而没有锚点，校验立即在新链头失败；
* 锚点内容被改写同样触发 `hash-mismatch` / `anchor-invalid`。

## 4. 脱敏策略

脱敏发生在**离开进程去落盘之前**（链记录与 spool 都只保存脱敏后内容），
对外查询返回的也是同一份落盘记录，原始敏感值不会出现在任何持久化字节或
响应中。

| 策略 | 结果 | 示例 |
| --- | --- | --- |
| `full` | `***` | password、token、api_key、id_card、bank_card |
| `partial` | 仅保留首尾少量字符 | `alice@example.com` → `al***********om` |
| `hash` | `sha256:<12hex>` | 需要可关联但不可逆的字段 |
| `keep` | 原样保留 | username |

* 字段规则按小写字段名匹配，内置规则见 `audit/masking.py::DEFAULT_FIELD_RULES`；
* 无显式规则的字段按级别兜底：`public` 保留，其余级别一律 `full`；
* 可在构造 `PolicyMasker(field_rules=..., level_unknown=...)` 时覆盖。

## 5. 保留策略与清理

`RetentionPolicy` 为每个敏感级别配置保留秒数，默认：

| 级别 | 默认保留期 |
| --- | --- |
| `public` | 7 天 |
| `internal` | 30 天 |
| `sensitive` | 90 天 |
| `regulated` | 365 天 |

* 清理只删除**整段完全过期**的最长前缀：段内任一条记录未过期，该段及
  之后全部保留，因此链永远不会在段中间断开；
* 边界为严格小于截止时间（`ts < now - retention`），恰好等于截止时间的
  记录保留；
* 清理与封存共用同一把锁，查询在锁内取一致性快照，清理进行中的读者只能
  看到“清理前”或“锚点已落盘后”的完整状态，不会看到残缺或重排数据；
* 锚点按 `regulated` 级别长期保留，历史清理事实本身可审计。

## 6. 配置项

| 配置 | 位置 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `AUDIT_STORE` | 环境变量 | `./audit-data` | HTTP 服务的存储目录 |
| `rotate_bytes` | `SegmentStore(...)` | `1048576` | 段轮转字节数 |
| `max_append_retries` | `AuditService(...)` | `3` | 写失败重试次数 |
| `retry_backoff` | `AuditService(...)` | `0.001` | 重试退避基数（秒） |
| `RetentionPolicy({Sensitivity.X: seconds})` | 构造参数 | 见第 5 节 | 各级别保留期 |
| `PolicyMasker(field_rules, level_unknown)` | 构造参数 | 内置规则 | 脱敏规则覆盖 |
| `fault_hook` | `SegmentStore`（仅测试） | `None` | 故障注入钩子 |
