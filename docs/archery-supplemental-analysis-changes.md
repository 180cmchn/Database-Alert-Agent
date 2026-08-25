# Archery 慢查询补充分析变更说明

## 背景与目标

本次修改基于 `dev` 分支提交 `24473e347a8e106d27491a5f0ee748ef946cb1fd`，继续完成
Archery 慢查询 history 后的补充分析，并落实以下边界：

- history 是独立的基础证据，补充分析不得修改、替换或降级它；
- history 中的任何 sample 都不得直接执行，包括 SELECT、WITH 和 DML；
- 与完整 history sample 严格绑定的普通 `EXPLAIN` 可以执行，支持 SELECT、WITH 以及目标
  MySQL/TiDB 能由普通 EXPLAIN 处理的 INSERT、UPDATE、DELETE、REPLACE；
- `EXPLAIN ANALYZE`、多语句、截断 sample 前缀、DDL、CALL 和未绑定 EXPLAIN 始终禁止；
- 本机无法连接公司内网中的 Archery MCP 和 Prometheus MCP，因此使用 replay/fake 完成离线验证。

## 修改原因

### 1. 提示词约束不能代替 transport 前门禁

原实现主要依赖内层 Agent 遵守提示词。模型一旦生成直接 sample、任意业务 SQL、混合 history
数据源或 `EXPLAIN ANALYZE`，调用仍可能到达 MCP。恢复旧 checkpoint 时还可能复用旧策略生成的
PENDING 调用，从而绕过升级后的限制。

### 2. 截断恢复缺少统一的完成状态

字符截断后的 window 结果、id 清单和 per-id 行曾由多个局部条件判断。只恢复部分 id 时，子集可能
被合并成看似完整的 history，并错误获得根因资格；字段级 sample 前缀也可能覆盖已经取得的完整
sample。

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
- history window 强制使用单一 history 数据源、`SELECT *`、真实解析的 endpoint 和完整告警时间边界。
- history 后仅允许受约束的恢复查询、真实目标发现、字段/索引元数据查询及绑定 sample 的普通
  EXPLAIN。
- sample 直接执行使用格式无关但不改写字面量的 SQL 身份核对；普通 SELECT sample 也不能例外。
- `EXPLAIN ANALYZE`、多语句、未绑定 EXPLAIN、DDL、CALL、管理语句和带副作用的直接查询在
  transport 前失败关闭。

### History 截断恢复

- id 清单必须保留原 endpoint 和时间窗口，并且只有清单真实返回的正整数 id 才能授权 per-id 查询。
- per-id 查询只允许 `SELECT *` 或程序生成的固定字段级 sample 投影；不允许额外字段、换序、漏项、
  重复字段或 `IN (...)` 合并查询。
- per-id 恢复重试中的 `max_result_chars` 只允许缺省值或固定为 `24000`；其它查询继续遵循
  MCP 动态 Schema 中的容量参数约束。
- 统一跟踪 id 清单是否完整、缺失 id、清单外 id、未解析位置行和终态失败。恢复不完整时最终证据
  保持 partial，不能获得 `root_cause_eligible`。
- `sample_full_length` 按 UTF-8 字节长度核对；字段级前缀保留为 history 证据，但不进入 EXPLAIN。
- 字段级前缀不能覆盖已恢复的完整 sample；完整行可以替换前缀并移除过期长度标记。

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

- `final_result_payload` 继续只做格式转换并完整透传，不过滤、聚合、排序或设置程序侧大小上限。
- EXPLAIN、字段、索引和失败原因通过独立 `slow_query_analysis` 进入主 Agent；补充失败不改变 history
  的成功状态、可用性或根因资格。
- 最终完整 history 已覆盖的显式非终态恢复失败投影为 `RECOVERED`；终态或未恢复失败仍为 `FAILED`。
- 因目标解析或工具能力导致的内部 `UNAVAILABLE` 会原样进入 evidence unit；`NO_DATA` 仅表示已执行
  的查询没有数据或缺少更精确的历史状态，不能再代替依赖阻断。
- 本地策略拒绝也进入 checkpoint lineage；当前策略直接判定的本地拒绝不会新增远端调用 debit，
  也不会保存成远端响应 artifact。若旧 PENDING 调用在崩溃前已经持久化 append-only remote debit，
  恢复后该 debit 作为不可退款 reservation 保留，但当前策略仍可在 transport 前拒绝该调用。
- 恢复尚未跨 transport 的旧 PENDING 调用时重新应用当前策略；已经 STARTED 且存在远端 debit 的
  调用保持未知结果恢复语义，避免把真实在途调用伪装成本地拒绝。

### 可维护性

- 新增集中式 MySQL 词法与表引用辅助模块，生成器和精确校验器共享同一字段级投影常量。
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
| `EXPLAIN <字段级截断 sample 前缀>` | 本地拒绝 |
| 未完整恢复 history 时开始 metadata/EXPLAIN | 本地拒绝，history 保持 partial |
| MCP 回显实际 SQL 或目标冲突 | 不投影结果，记录结构化证据缺口 |
| 补充分析权限、空结果或 transport 失败 | 保留 history，仅标记对应补充阶段失败 |

## 验证

最终提交前执行并记录以下离线验证：

```text
pytest -m "not live" -q: 949 passed, 1 skipped, 3 deselected
ruff check app tests migrations: 通过
python -m compileall -q app tests: 通过
git diff --check: 通过
```

pytest 警告来自 FastAPI、Starlette、LangGraph/LangChain、Python 3.14 和 Alembic 依赖的弃用提示，
没有本次实现产生的测试失败。

由于本机不在公司内网，本次未把 Archery MCP 或 Prometheus MCP 连接超时作为实现失败，也未使用
live MCP 结果替代 replay/fake 测试。
