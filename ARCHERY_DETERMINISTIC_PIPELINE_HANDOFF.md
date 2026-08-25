# Archery 确定性慢查询流水线交接说明

## 1. 用户要求

### 1.1 问题背景

- 修复 Archery MCP 将合法出站查询误判为 `actual_sql_mismatch` 或 `direct_statement_forbidden` 的问题。
- 原始故障链路是 MCP 给单一顶层 `SELECT` 自动追加了与 `limit_num` 相同的末尾 `LIMIT`，严格 SQL 等值校验将其拒绝，导致 `t_instance_member -> sql_instance` 的目标解析链路中断。
- Run `2cbd4238-dbf6-4e91-87a4-a3006e14e2bf` 的远端 SQL 总耗时只占很小部分，主要耗时来自逐行模型决策和逐条结果完整性评估。旧流程在 40 个 history ID 上产生了 77 次串行模型决策，随后尚有大量 Explain、表结构和索引任务未开始。

### 1.2 新流程必须满足的行为

- history 恢复改为 Host 确定性编排，模型不参与分页、逐行完整性判断、sample 恢复、元数据查询和 Explain 调度等机械步骤。
- 使用两个逻辑 history 扫描：
  - 第一阶段固定投影 `id, Query_time_max, Query_time_sum`。
  - 第二阶段查询紧凑证据字段，并固定使用 `LENGTH(sample) AS sample_full_length`。
- 两个逻辑扫描均可在超过单页上限时拆成 Host 生成的 `ORDER BY id DESC`、`id < last_id` keyset 物理分页，禁止 `OFFSET`。
- 分别按 `Query_time_max` 和 `Query_time_sum` 降序取 `ceil(N * 20%)`，至少各一条，并以 `id DESC` 打破截止位并列；两组 ID 取并集作为高优先级，其余记录随后处理。
- `sample_full_length <= 12000` 时查询完整 sample。
- 超长或直接查询仍截断时，使用 `SUBSTRING(sample, offset, size)` 分块恢复。`max_result_chars` 固定为 `12000`，分片大小应尽量接近响应上限以减少调用次数，并为 JSON/MCP 信封预留空间。
- 分片必须按 offset 重组，并以 MySQL `LENGTH(sample)` 的 UTF-8 字节数进行严格核验。
- 超长普通 literal `IN/NOT IN` 可生成不超过约 12000 字符的结构化展示 SQL，保留头尾真实值以及原始、保留、遗漏数量；`IN (SELECT ...)` 不做这种压缩。
- 结构化或压缩后的 SQL只能用于降低主 Agent 上下文压力，绝不能用于 Explain。
- 所有 Explain 必须使用分片重组并完成长度、SHA-256 绑定后的完整原始 SQL。
- 完整原始 SQL不得进入主 Agent 消息、history 展示行或最终 Explain 证据；允许保存在 Host checkpoint、内部 MCP 参数和审计边界中。
- 所有可安全进行普通 Explain 的记录都应尝试 Explain。Top 20% 并集优先，其余记录继续，直到全部完成或内部预算耗尽。
- Explain 复用边界为 `(instance_id, db_name, checksum)`。
- 保留原有 SQL 完整性校验、目标 provenance、证据绑定、Explain 资格、根因资格、partial/completeness 语义和审计能力。
- Archery harness 内部调查预算为 `120s`，外层工具超时为 `150s`。预算到期时保留紧凑 history、已完成 sample/Explain、未完成 ID 和覆盖率，不得只返回通用 `TIMEOUT`。

### 1.3 安全和操作约束

- Archery MCP 服务端不在本次修改范围内，恢复和压缩均在本仓库 Host 侧完成。
- 未经明确要求不得发起真实 MCP 出站请求。
- 不修改本地告警数据库 `data/alerts.db`。
- 不修改用户现有的 `data/runtime-settings.json`。
- Python、pytest 和项目脚本使用 `.venv/Scripts/python.exe` 或对应虚拟环境可执行文件。
- 发现后续问题时默认先只读定位、说明根因和修改建议，获得用户确认后再改代码或配置。

## 2. 实施计划

1. 保留并验证 provider 末尾 `LIMIT` 的受约束等价规则，只允许原请求为无顶层 `LIMIT/OFFSET` 的单一顶层 `SELECT`，且追加值与调用参数 `limit_num` 精确一致。
2. 在 Archery Host 中建立 `RANKING -> COMPACT -> RECONCILE -> ENRICHMENT -> COMPLETED` 确定性状态机。
3. 对两个逻辑扫描实施固定投影、快照最大 ID、keyset 分页、页结构/顺序/唯一性校验以及 ID 集一致性检查。
4. 计算两套 Top 20% 排名并形成统一优先队列。
5. 按长度预检结果直接读取或分片恢复 sample，验证 UTF-8 字节长度并保存 SHA-256。
6. 将超长 sample 转换为有界展示结构，但将完整 SQL只保留在 Host 内部的当前 sample 状态中。
7. 依次完成业务实例定向 allowlist、数据库确认、显式 schema 校验、表字段、索引和普通 Explain；Explain 参数只能从 Host 保存的完整 SQL生成。
8. 按业务实例、数据库和 checksum 复用 Explain，并将结果绑定回各 history ID。
9. 接入 120 秒内部预算和 150 秒外层超时，在各阶段停止时物化可用的部分证据。
10. 将 Host 内部调用从模型消息和模型调用审计中隔离，同时保留独立 Host 调用计数、请求 ID 和持久化审计。
11. 同步 workflow、README、环境变量示例、配置校验、factory 和测试。
12. 完成静态检查、Archery 回归、隔离运行时配置的完整测试；真实 MCP 验证继续保持禁用，除非用户另行批准。

## 3. 目前进度

### 3.1 已完成

- `app/adapters/archery_mcp.py`
  - 已实现受约束的 provider 末尾 `LIMIT` 等价校验。
  - 已实现固定 ranking/compact SQL、keyset 条件、单 ID reconcile、sample 全文和 `SUBSTRING` 分片 SQL生成与解析。
  - 已实现 Top 20% 双排名并集。
  - 已实现超长 literal `IN/NOT IN` 的头尾保留结构化展示及相关计数元数据。
  - 已实现 sample 原始字节长度、展示结构和 Explain 资格辅助逻辑。
  - 已实现实例目录 endpoint 到精确 `instance_ref` 的导航映射；目录映射本身不授予执行权限。
- `app/adapters/archery_harness.py`
  - 已加入确定性 history 状态机和 Host 调用注册表。
  - 已实现两个逻辑扫描、快照上界、keyset 分页、截断后缩小页大小、ID 集 reconcile 和一致性标记。
  - 已实现高优先级 sample 队列、直接 sample 查询、初始约 10000 字符分片、截断/失败后减半和最低 1000 字符限制。
  - 已实现重组后 UTF-8 字节长度核验和 SHA-256 记录。
  - 已保证结构化展示 SQL无法获得 Explain 授权；Explain 实际参数来自 Host 内保存的完整原始 SQL。
  - 已实现业务目标、数据库、显式 schema、字段、索引和 Explain 的顺序绑定；单条 history 的 enrichment 固定为字段、索引、Explain。
  - 已实现相同 `(instance_id, db_name, checksum)` 的 Explain 复用；复用依据持久化 target provenance，且排除当前 history ID 自复用。
  - 已实现预算停止时保留完整紧凑扫描或已取得的部分扫描行，并列出 enrichment 未完成 ID。
  - 已将 Host 调用与模型调用分别记录为 `host_executed_tool_calls`、`host_request_ids` 和 `model_executed_tool_calls`、`model_request_ids`；`mcp_tool_call_count` 统计两类远端调用总和。
- `app/mcp_runtime/harness.py`
  - `internal_only` 的 Host 调用结果不再追加到模型消息，避免完整 sample 或机械调用结果进入后续模型上下文。
- `app/config.py`、`app/application/factory.py`、`.env.example`、`README.md`
  - 已加入 `ARCHERY_INVESTIGATION_BUDGET_SECONDS=120`。
  - 默认 `ARCHERY_MCP_TOOL_TIMEOUT_SECONDS` 已调整为 `150`。
  - 已加入内部预算必须小于外层工具超时的配置校验。
- `config/mcp/prompts/archery/workflow.md`
  - 已同步两个逻辑扫描、keyset 分页、Top 20%、sample 字节长度、分片、结构化展示、完整原 SQL Explain、目标绑定、partial 结果和 provider `LIMIT` 契约。
- 测试
  - 新增 `tests/unit/test_archery_harness_deterministic.py`。
  - 新增 `tests/unit/test_archery_harness_deterministic_checkpoint.py` 和 `tests/unit/test_archery_harness_deterministic_replay.py`。
  - 已覆盖无表发现缓存启动、Top 20% 并集、Host 规划不调用模型、缺失 compact ID reconcile、扫描/补充预算停止、超长 IN 分片恢复、完整原 SQL Explain、上下文不泄漏以及 Host/模型审计拆分。
  - 已覆盖 ranking/compact 分页、sample 分片、完整 sample、Explain 暂存响应和预算停止的 checkpoint 恢复。
  - 已覆盖 Explain 同目标复用及跨实例/数据库隔离、各远端阶段故障隔离，以及使用真实 Archery 工具 Schema 的离线 Replay。
  - 其它 Archery、配置、factory 和 catalog 测试已同步。

### 3.2 当前分支和提交上下文

- 工作分支：`dev`。
- 本轮补测和修正建立在提交 `b9dfd16 fix: 实现慢查询确定性恢复并绑定完整原始语句执行计划` 之上。
- 开始本轮工作时，本地 `dev` 与 `origin/dev` 同步。

## 4. 当前验证

### 4.1 已通过

- Archery 关键回归：

```bash
.venv/Scripts/pytest.exe -q \
  tests/unit/test_archery_harness_deterministic.py \
  tests/unit/test_archery_harness_deterministic_checkpoint.py \
  tests/unit/test_archery_harness_deterministic_replay.py \
  tests/unit/test_archery_mcp.py \
  tests/unit/test_archery_harness_policy.py \
  tests/unit/test_archery_harness_history.py \
  tests/unit/test_archery_harness_persistence.py \
  tests/unit/test_archery_harness_projection.py \
  tests/unit/test_archery_harness_runtime.py \
  tests/unit/test_archery_harness_session.py \
  tests/unit/test_archery_harness_analysis.py -x
```

结果：`348 passed`。

- 隔离现有运行时配置后的完整测试：

```bash
runtime_settings_path="$PWD/.pytest-runtime-settings-$$.json"
trap 'rm -f "$runtime_settings_path"' EXIT
RUNTIME_SETTINGS_PATH="$runtime_settings_path" .venv/Scripts/pytest.exe -q
```

结果：`1074 passed, 4 skipped`。跳过项均要求显式启用外部集成或 Kafka 环境，本轮未启用。

- 前端测试和生产构建：

```bash
npm test
npm run build
```

结果：`23 passed`，生产构建通过。

- 静态和语法检查：

```bash
.venv/bin/ruff check app tests migrations
.venv/bin/python -m compileall -q app tests
git diff --check
```

结果：全部通过。

### 4.2 验证注意事项

- 如果工作区存在 `data/runtime-settings.json`，不隔离 `RUNTIME_SETTINGS_PATH` 时它会覆盖测试配置并可能造成与代码无关的失败。不得为了测试修改或删除该用户文件。
- 测试期间没有发起真实 MCP 请求，也没有写入 `data/alerts.db`。
- 原 Run `2cbd4238-dbf6-4e91-87a4-a3006e14e2bf` 在当前数据库和只读备份中均不存在，因此使用脱敏的真实 Schema Replay 完成离线验证；Replay 确认确定性处理开始前只有 3 次模型决策，且没有逐行模型评估。
- `ruff format --check` 没有作为全仓门槛执行。现有大文件在 `HEAD` 中已有格式差异，整文件格式化会引入大规模无关机械变更；新测试文件已经按 Ruff 格式化。

## 5. 本轮补足与后续事项

### 5.1 已补足

1. checkpoint 恢复专项覆盖已完成，包括 ranking/compact 分页中途、sample 分片中途、完整 sample 已恢复但 Explain 未执行、Explain 响应已暂存但状态转换未持久化，以及预算停止后的恢复。
2. 真实 Archery 工具 Schema 的离线 Replay 已完成，验证目录 endpoint 到定向 `instance_ref` 的导航和定向查询后的执行 allowlist 授权。
3. Explain 复用边界和结果脱敏专项覆盖已完成，跨实例或跨数据库不会复用。
4. 远端故障专项覆盖已完成，失败会保留部分证据或继续下一个阶段/history ID。
5. 原 Run artifact 因本地不存在无法直接回放，已用等价的脱敏真实 Schema Replay 验证模型决策次数和无逐行模型评估行为。

### 5.2 后续非阻断事项

1. `app/adapters/archery_harness.py` 的确定性状态机后续可考虑提取为独立模块；现有 checkpoint 和 Replay 测试应作为重构保护。
2. 部署到公司内网后观察实际 `host_executed_tool_calls`、`model_decision_count`、预算覆盖率、未完成 ID 和 Explain 成功率，确认 120 秒预算在真实 MCP 延迟下合理；调整预算属于部署配置变更，应先获得用户确认。
3. 本机不具备公司内网连通性，本轮不要求也不执行 Archery MCP 或 Prometheus MCP 的真实请求。

## 6. 建议接手顺序

1. 阅读 `config/mcp/prompts/archery/workflow.md`，确认业务契约。
2. 阅读 `app/adapters/archery_mcp.py` 中 history SQL、优先级、sample 分片和结构化展示辅助函数。
3. 阅读 `app/adapters/archery_harness.py` 中 `_HISTORY_PIPELINE_*` 状态、`next_host_call`、pipeline result transitions 和 `_finalize_deterministic_pipeline_stop`。
4. 修改确定性路径时同步运行 deterministic、checkpoint 和 Replay 三组专项测试。
5. 每轮修改先运行相关 Archery 测试，最后使用隔离 `RUNTIME_SETTINGS_PATH` 执行完整测试。
6. 保持 `data/alerts.db`、`data/runtime-settings.json` 和真实 MCP 不变，除非用户明确授权。
