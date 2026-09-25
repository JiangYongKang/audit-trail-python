# audit-trail-python

本地可运行的审计日志链路：请求从进入、被处理到被拒绝或完成的全过程可审计，
在进程重启、并发写入与保留期清理之后依然可信、可验证。

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
| GET | `/audit/records` | 查询审计记录（已脱敏） |
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
  store.py       JSONL 段文件存储：轮转、幂等重试、锚点式清理
  service.py     定序、去重、链式落盘、重启恢复
  middleware.py  HTTP 入口采集
  config.py      配置项
tests/           并发、重试、清理边界、篡改等场景测试
```
