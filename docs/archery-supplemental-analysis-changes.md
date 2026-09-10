# Archery 慢查询补充分析变更说明

## 背景与目标

本次修改基于 `dev` 分支提交 `24473e347a8e106d27491a5f0ee748ef946cb1fd`，继续完成
Archery 慢查询 history 后的补充分析，并落实以下边界：

- history 是独立的基础证据，补充分析不得修改、替换或降级它；
- history 中的任何 sample 都不得直接执行，包括 SELECT、WITH 和 DML；
- 与完整 history sample 严格绑定的普通 `EXPLAIN` 可以执行，支持 SELECT、WITH 以及目标
  MySQL/TiDB 能由普通 EXPLAIN 处理的 INSERT、UPDATE、DELETE、REPLACE；
- `EXPLAIN ANALYZE`、多语句、截断 sample 前缀、DDL、CALL 和未绑定 EXPLAIN 始终禁止；
- 使用 replay/fake 完成离线验证。

## 修改原因

### 1. 提示词约束不能代替 transport 前门禁

原实现主要依赖内层 Agent 遵守提示词。模型一旦生成直接 sample、任意业务 SQL、混合 history
数据源或 `EXPLAIN ANALYZE`，调用仍可能到达 MCP。恢复旧 checkpoint 时还可能复用旧策略生成的
PENDING 调用，从而绕过升级后的限制。

### 2. History 完整恢复缺少统一契约

旧路径可把紧凑字段或 sample 前缀合并成看似成功的 history，并错误获得根因资格；业务字段还可能因
与 `raw`、`request_id`、`usage`、`hash` 等 provenance 名称相同而在模型边界被递归删除。History
完整性必须由真实 schema、完整行集合和逐行精确 sample 共同证明，内部来源元数据则按类型和位置隔离。

### 3. 补充结果需要同时绑定请求、history 和真实目标

仅识别返回类型不足以证明 EXPLAIN、字段或索引属于选中的 history 行。MCP 回显的实际 SQL、实例、
host:port、数据库、schema 或表与请求冲突时，结果必须作为证据缺口处理，不能进入补充事实。

### 4. SQL 识别需要可复用且失败关闭

正则分散在 Adapter 和 Harness 中时，CTE、DML、派生表、DELETE USING、引号标识符、optimizer
hint 等语法容易出现不一致。SQL 词法与结构提取需要集中维护，并在无法可靠识别时拒绝执行或关联。

## 改动结果

### Transport 前安全策略

- Archery SQL 只能通过正式 SQL 查询工具发送；未知 SQL 工具和 history 后的未知工具会被本地拒绝。
- 动态认证工具仅在明确声明 `readOnlyHint=true` 且未声明 `destructiveHint=true` 时放行；每次重新
  发现工具都会重建认证 allowlist，冲突或过期声明不会沿用到新会话。
- history 查询强制使用单一数据源、真实解析的 endpoint 和完整告警时间边界；确定性 Host 先读取真实
  schema，再执行排名扫描、全部非 sample 字段扫描和逐行精确 sample 恢复。
- history 后仅允许受约束的恢复查询、真实目标发现、字段/索引元数据查询及绑定 sample 的普通 EXPLAIN。
- sample 直接执行使用格式无关但不改写字面量的 SQL 身份核对；普通 SELECT sample 也不能例外。
- `EXPLAIN ANALYZE`、多语句、未绑定 EXPLAIN、DDL、CALL、管理语句和带副作用的直接查询在
  transport 前失败关闭。

### History 无损恢复

- 排名扫描和完整非 sample 字段扫描都使用固定快照上界及 `id` keyset 分页，禁止 OFFSET；第二轮字段
  来自真实 schema，不使用固定业务白名单。
- 第二轮仅增加 Host 内部的 `LENGTH(sample) AS __history_sample_octet_length`。该 alias、排名、优先级、
  恢复状态和 hash 不注入最终业务行。
- 两次扫描 id 集必须一致；分页、字段、快照或行集合无法完整核验时，已收到内容保留为内部 artifact，
  但 History 保持 incomplete 且不能获得 `root_cause_eligible`。
- 所有 id 的 sample 都通过单行读取或 Host 生成的 `SUBSTRING` 分片恢复，UTF-8 字节长度必须与
  `LENGTH(sample)` 精确相等。完整原 SQL原样写回真实 `sample` 字段，不做压缩、前后缀投影或空白改写。
- 排名只决定恢复和 supplemental 调度顺序；最终 History 保持查询的 `id DESC` 行顺序，并包含 schema
  中每个真实字段。所有 History 行完整后才能开始 supplemental。
- 预算、deadline 或分片失败发生在 History 恢复阶段时 fail closed；若只发生在 supplemental 阶段，
  完整 History 内容和资格保持不变，仅 supplemental 标记为 partial/failed。

### 补充证据绑定

- sample 绑定真实 history `id/checksum/sample`，相同 checksum 只选择优先级最高的一行。
- `hostname_max` 必须唯一匹配 allowlist 实例，`db_max` 必须出现在该实例真实数据库列表中。
- 同一调查中 history 前已经取得的结构化 allowlist 行会保留到补充阶段，但只授权数据库发现；真实
  MCP 无筛选返回的编号文本是实例目录，必须经过精确 `instance_ref` 定向查询成功后才成为执行
  allowlist。数据库清单未确认前仍禁止业务目标 SQL。真实 MCP 文本使用带固定标题的严格解析器，
  普通 prose 或 `allowlist.json` 拒绝文本不能产生授权。
- sample 中的显式 schema、CTE 内物理表和 DML 目标必须与 `db_max` 精确一致。
- 先取得表字段或明确记录字段阶段失败，之后才能执行普通 EXPLAIN；字段和索引事实可在相同实例、
  数据库和表之间复用，EXPLAIN 仍绑定具体 history 行。
- MCP 返回中的全部显式 SQL 声明和目标声明都会参与核对；同层、嵌套或文本回显相互冲突时失败关闭。
- information_schema 结果行中显式返回的 `TABLE_SCHEMA`、`TABLE_NAME` 也必须与绑定目标精确一致。

### 证据契约与恢复语义

- `final_result_payload` 只做 JSON 格式转换和既有秘密净化后完整透传，不过滤、聚合、重排、截断、压缩
  SQL 或设置最终大小上限。业务 History 内与 provenance 同名的键仍是业务字段，必须保留。
- 请求信封、artifact ID、调用 request ID、usage 和 source hash 由类型化 DTO 字段与结构位置隔离，不
  递归扫描并删除业务 payload；artifact payload、History `EvidenceUnit.data` 和模型/trace DTO 精确相等。
- EXPLAIN、字段、索引和失败原因通过独立 `slow_query_analysis` 进入主 Agent；补充失败不改变完整
  History 的成功状态、内容、可用性或根因资格。
- 因目标解析或工具能力导致的内部 `UNAVAILABLE` 会原样进入 evidence unit；`NO_DATA` 仅表示已执行
  的查询没有数据或缺少更精确的历史状态，不能再代替依赖阻断。
- 本地策略拒绝也进入 checkpoint lineage；当前策略直接判定的本地拒绝不会新增远端调用 debit，
  也不会保存成远端响应 artifact。若旧 PENDING 调用在崩溃前已经持久化 append-only remote debit，
  恢复后该 debit 作为不可退款 reservation 保留，但当前策略仍可在 transport 前拒绝该调用。
- 恢复尚未跨 transport 的旧 PENDING 调用时重新应用当前策略；已经 STARTED 且存在远端 debit 的
  调用保持未知结果恢复语义，避免把真实在途调用伪装成本地拒绝。

### 可维护性

- 新增集中式 MySQL 词法与表引用辅助模块；Host 生成器和精确校验器共享动态 schema、快照与分片契约。
- Archery provider 的顺序、SQL 绑定和证据投影规则保留在专用 Adapter/Harness，不向通用 MCP Host
  引入 Archery 业务分支。
- 同步更新 Archery 四份提示词、数据库告警分析技能、主 Agent 提示、README 和项目架构说明，并
  升级相关 policy/schema/prompt 版本。

## 行为矩阵

| 请求 | 结果 |
| --- | --- |
| 直接执行任意完整 history sample | 本地拒绝，不访问 MCP |
| `EXPLAIN <完整且已绑定的 SELECT/WITH sample>` | 满足目标和字段前置条件后允许 |
| `EXPLAIN <完整且已绑定的受支持 DML sample>` | 满足目标和字段前置条件后允许 |
| `EXPLAIN ANALYZE <sample>` | 永久本地拒绝 |
| `EXPLAIN <未完整恢复的 sample 分片>` | 本地拒绝 |
| 未完整恢复所有 History 字段和 sample 时开始 metadata/EXPLAIN | 本地拒绝，History 保持 incomplete |
| MCP 回显实际 SQL 或目标冲突 | 不投影结果，记录结构化证据缺口 |
| History 恢复预算耗尽 | 保留内部 artifact，History 不具备根因资格且不运行 supplemental |
| 完整 History 后 supplemental 权限、空结果或 transport 失败 | History 不变，仅标记对应 supplemental 阶段失败 |

## 验证

最终提交前执行并记录以下离线验证：

```text
pytest -m "not live" -q: 1227 passed, 1 skipped, 3 deselected, 24 warnings
ruff check app tests migrations: 通过
python -m compileall -q app tests migrations: 通过
受影响应用文件的 LSP diagnostics: 通过
```

24 条 warning 来自 Starlette、LangGraph/LangChain 和 Alembic 依赖的弃用提示，没有本次实现产生的
测试失败。该离线套件的持久化 fixture 使用隔离的临时 SQLite 数据库；它不写入已迁移的 MySQL，也不
把 SQLite 结果表述为 MySQL 事务语义验证。

