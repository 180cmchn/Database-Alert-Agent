# Database Alert Agent

Database Alert Agent 轮询 FlashDuty 协作空间中的数据库告警，去重入库，并让单一主 Agent 结合告警详情、
所选知识来源和按需查询的 MCP 证据分析根因。系统只输出两种根因结论：证据建立因果机制时返回
`SUPPORTED`；否则返回 `现有结果无法得出根因`。

项目介绍、全局组件关系、Agent 运行机制、MCP 接入和提示词维护方式见
[项目思维导图与运行机制](docs/project-architecture.md)。

## 分析流程

1. 后台轮询由 `FLASHDUTY_POLLING_ENABLED` 控制，默认关闭。轮询器按
   `FLASHDUTY_POLL_CHANNEL_IDS` 查询协作空间，以 `source + alert_id` 去重。新告警完成标准化后先执行
   等级准入：符合策略的告警进入分析队列；被过滤的告警以 `FILTERED` 状态入库，不创建分析运行，
   也不发送企微通知。
2. 分析首先调用 FlashDuty `/alert/info`。详情中的数据库、`alarm_host`、`alarm_port` 和
   `occurred_at` 同时参与知识匹配、MCP 选择和查询；host、port 不从标题推断或补全。
3. 系统检索本次选择的知识来源，保留实际命中的来源、知识 ID、标题和 URI。
4. 主 Agent 进入 ReAct 循环。每轮按 `thought -> action -> observation` 执行一个外层工具，或输出
   `finish`；它根据 MCP 的角色和作用判断是否需要调用，不存在按告警类型硬编码的必调 MCP。
5. MCP 完整原始响应保存为内部审计 artifact。程序侧按 provider 契约产生可追溯 observation；通用
   provider 使用有界投影，Archery History 只做 JSON 格式转换和既有秘密净化后完整透传。认证、导航、
   请求 ID、usage、hash 等内部 provenance 不发送给主 Agent，结果处理阶段不调用模型。
6. 主 Agent 是唯一可以结合不同证据判断根因的组件。达到 `finish` 或 `REACT_MAX_ROUNDS` 后正常结束
   调查并生成结论；程序随后只校验输出结构、证据引用与来源资格，不调用第二个模型判断或否决根因。
   整次分析还受 `ANALYSIS_TIMEOUT_SECONDS` 和主动取消控制。

### 失败、恢复与显式重分析

- 自动调度只处理 `RECEIVED` 和 `QUEUED`。`FAILED`、`CANCELLED` 以及已有业务结论的告警都是终态；
  FlashDuty 重叠轮询、Redis redelivery、进程重启和过期租约恢复都不会为 `FAILED` 自动创建新 attempt。
- 只有 manifest 兼容且 checkpoint 完整的过期运行会在**同一个 run** 内恢复。checkpoint 缺失、损坏或不兼容时，
  原 run 以 `FAILED` 结束；之后只能由管理员显式调用 reanalysis。
- 模型错误按状态码和供应商错误码结构化分类。确认的认证、授权、额度/计费或模型配置错误会持久暂停分析调度；
  未确认语义的 HTTP 429、5xx、连接错误和超时采用有界重试，但不会被误判为额度耗尽或自动暂停。
- 调度暂停不停止 FlashDuty 轮询、去重和入库；新告警保留在待执行队列。保存设置、重启、等待或轮询成功
  都不会清除暂停。管理员必须针对当前模型配置和调度版本执行“验证模型并恢复调度”。验证成功只补投
  `RECEIVED`/`QUEUED`，历史 `FAILED` 仍需逐条显式重分析。

调查主图：

```text
START -> enrich_alert -> fingerprint -> knowledge -> react_decide
                                      react_decide --tool--> execute_one
                                      execute_one -> observation -> react_decide
                                      react_decide --finish/max rounds--> advise
                                      advise -> validate -> report -> END
```

`REACT_MAX_ROUNDS` 限制的是主 Agent 外层决策轮次。MCP 内部认证、目标发现、Schema 发现、分页等辅助
调用不单独消耗 ReAct 轮次，也没有 Archery、Prometheus 或通用 MCP 的独立调用次数预算。达到轮次
上限不是错误；主 Agent 基于已有 observation 正常输出最终结论。运行时记录的
`planner_requests`、`accepted_decisions`、`remote_tool_calls`、`host_bootstrap_calls`、
`session_attempts` 和 `model_tokens` 仅用于审计累计，配置或历史检查点中的同名 limit 不会终止分析。

### 企微通知卡片

企微原生 `text_notice` 卡片的标题先脱敏并折叠空白。不超过 26 个字符时保留原标题；长标题
改用有效且不超过 26 个字符的 `alert_name`，短名为空、为 `unknown`（忽略大小写）或过长时
显示“数据库告警分析”。脱敏后的完整长标题优先放入正文，再用剩余空间分行展示告警原因。
正文总计不超过 112 个字符，原因摘要超出剩余空间时以“…”结尾；标题行本身超长时以
“（完整标题见详情）”明确提示省略，可通过现有卡片入口查看完整标题。原始告警数据不改写。

26/112 字符是发送端的展示预算，不是客户端宽度或字号自适应保证；实际换行和裁切仍需在
企微桌面端、手机窄屏及大字体设置下验收。成功/结论不充分卡片保留事实与分析入口；执行失败使用独立的
确定性卡片，只展示结构化供应商故障和失败详情，不依赖模型生成的 `Recommendation`，也不输出推测性
根因或处置建议。通知意图与分析终态原子落库；明确发送失败最多投递三次，网络超时等结果不确定的发送
标记为 `UNKNOWN`，不会盲目重复发送。

## 实时 Agent 轨迹

告警详情页按持久化顺序展示：

- `thought`：模型 API 实际返回的 `reasoning_content` 或 `reasoning`；
- `action`：本轮选择的一个工具、参数和目标，或 `finish`；
- `observation`：工具状态以及程序侧生成的可追溯事实、异常和限制。

系统不会生成“当前判断摘要”冒充思维链。模型暂未返回 reasoning 时，页面展示
`当前暂时无法显示思维链，但仍在分析中`，分析继续。增量读取接口为：

```http
GET /api/v1/alerts/{alert_id}/runs/{run_id}/trace?after_sequence=0
```

内部 artifact、认证响应、MCP 辅助调用结果和秘密值不进入该用户轨迹。

## 证据与结果契约

告警详情、知识和实时 observation 的职责不同：

| 数据 | 用途 | 能否单独证明根因 |
| --- | --- | --- |
| FlashDuty `/alert/info` | 确认告警语义、目标和时间 | 否 |
| 可选知识来源 | 提供可能机制和处置知识 | 否 |
| MCP 实时 observation | 提供告警目标、告警窗口内的事实 | 需由主 Agent 结合其它证据判断 |
| MCP 辅助响应 | 认证、资源定位、Schema 和目录发现 | 否，仅内部审计 |

程序投影可以过滤、聚合、排序、计算统计量和识别异常，但不能声称某个事实支持或反驳某个根因。
每条 observation 必须能追溯到原始 artifact 及真实数据路径。完整原始结果不设通用字符上限；通用
provider 的模型 DTO 保持有界，Archery History 的业务 payload 则按专用无损契约完整进入主 Agent。

某个 MCP 未被选择、目标未被该 MCP 覆盖、返回 `NO_DATA`、超时或失败，都不会单独把全局
`evidence_sufficient` 置为 false。充分性只取决于主 Agent 最终引用的相关、完整、可用实时证据是否
真正建立因果机制。结果契约固定为：

- 已建立根因：状态 `SUPPORTED`、`verified=true`，并引用合格实时证据 ID；
- 未建立根因：`root_causes=[]`、最终状态 `INCONCLUSIVE`、摘要 `现有结果无法得出根因`。

新分析不输出 `SUPPORT`、`UNKNOWN`、`CONTRADICTED`、暂定原因或被排除原因。调查期间的工具调用保持
只读，但最终处置建议不受只读限制：建立根因后，主 Agent 必须给出能够消除根因、恢复服务或降低影响
的实际动作，不得让 DBA 重复 MCP 已经完成的指标、日志、实例或数据库核查。终止查询或会话、切换、
限流、扩缩容、参数或配置修改等动作必须基于现有证据，并同时说明目标、执行前提、预期结果、风险、
审批或回滚要求；系统只生成建议，不会执行这些动作。无法建立根因时不生成猜测性处置步骤。

结论后的 `validate` 节点是纯程序契约校验：它不读取原始 MCP artifact，不综合证据形成新根因，也不
调用独立模型重新判断 `evidence_sufficient`。历史运行中的 `AGENT` 校验记录仍可读取，但新运行只写入
`RULE` 校验记录。

## 维护入口

重构后的日常维护入口如下：

| 维护内容 | 入口 |
| --- | --- |
| FlashDuty 协作空间 | `.env` 中 `FLASHDUTY_POLL_CHANNEL_IDS`，修改后重启 |
| FlashDuty 轮询开关和间隔 | `.env` / Agent 设置页；模板见 `.env.example` |
| 告警等级过滤开关和仅入库等级多选 | `.env` / Agent 设置页；`ALERT_ANALYSIS_FILTER_*` |
| MCP 连接与提示词引用 | `config/mcp/settings.json` |
| MCP 角色、作用、工作流程和行为边界 | `config/mcp/prompts/<provider>/{role,purpose,workflow,safety}.md` |
| MCP 原始结果的程序投影 | `app/adapters/tool_result_analysis.py` |
| 外部知识来源 | `.env` 中 `EXTERNAL_KNOWLEDGE_*` 和 `KNOWLEDGE_SOURCES` |
| 主 Agent ReAct 轮次与整次超时 | `REACT_MAX_ROUNDS`、`ANALYSIS_TIMEOUT_SECONDS` |
| 主 Agent reasoning 流式记录 | 必填环境变量 `STREAM_MAIN_AGENT_REASONING` / Agent 设置页 |

不要在 Python 中为新告警类型增加 MCP 策略分支。MCP 的“什么时候可能有用”和“选中后如何查询”分别
由 `role/purpose` 和 `workflow` 表达，主 Agent 在运行时判断。

## 扩展 FlashDuty 协作空间

轮询协作空间统一维护在 `FLASHDUTY_POLL_CHANNEL_IDS`。例如从一个空间扩展为三个空间：

```dotenv
FLASHDUTY_POLL_CHANNEL_IDS=[123456789,234567890,345678901]
```

也支持逗号分隔形式。修改后重启服务；当前 Agent 设置页只展示协作空间范围，不在线修改 ID。每轮
`/alert/list` 都携带完整 `channel_ids`；`FLASHDUTY_POLL_INTEGRATION_IDS` 仅用于在这些空间内进一步
收窄集成来源，不能替代协作空间列表。新增空间前确认：

1. 当前 `FLASHDUTY_APP_KEY` 能读取该空间；
2. 回看窗口能覆盖轮询间隔；
3. 告警量增加后数据库、调度器和模型并发仍有容量；
4. `/health/ready` 无配置问题，并可用管理员接口手动执行一次轮询验证。

同一个 `alert_id` 在重叠窗口中重复返回不会创建第二个分析任务。完整轮询语义和排障见
[FlashDuty Open API 轮询接入](docs/flashduty-polling/README.md)。

## 声明式扩展 MCP

MCP 目录位于 `config/mcp/settings.json`。URL、Header 和 Key 只写环境变量引用，真实值放在 `.env`
或部署环境。应用连接层负责认证、工具发现、协议解析、单次调用超时、持久化、artifact、checkpoint
和来源追溯，并原样转发模型按远端 Schema 生成的调用。MCP 权限在服务端分发 Key 时确定。

每个 MCP 可通过 `transport` 选择 `sse` 或 `streamable_http`；省略时默认
`streamable_http`。当前 checked-in 的 Archery 与 Prometheus 配置都显式选择
`streamable_http`。

新增 MCP：

1. 在 `mcpServers` 中与 `archery`、`prometheus` 同级追加 JSON 配置，并将
   `transport` 设为 `sse` 或 `streamable_http`；
2. 在 `config/mcp/prompts/<provider>/` 创建 `role.md`、`purpose.md`、`workflow.md`、`safety.md`；
3. 在 `.env` 提供 JSON 引用的 URL 和 Key；
4. 重启 API 与 Worker。主 Agent 会读取新的角色和作用并自主决定是否调用。

示例：

```json
{
  "mcpServers": {
    "new_provider": {
      "enabled": true,
      "url": "${NEW_PROVIDER_MCP_URL}",
      "headers": {
        "Authorization": "${NEW_PROVIDER_MCP_API_KEY}"
      },
      "prompts": {
        "role": "prompts/new_provider/role.md",
        "purpose": "prompts/new_provider/purpose.md",
        "workflow": "prompts/new_provider/workflow.md",
        "safety": "prompts/new_provider/safety.md"
      },
      "transport": "streamable_http",
      "toolTimeoutSeconds": 120
    }
  }
}
```

```dotenv
NEW_PROVIDER_MCP_URL=https://mcp.example.internal/mcp
NEW_PROVIDER_MCP_API_KEY=replace-me
```

`safety.md` 中声明 `read_only: true` 是给 Agent 的行为指令。远端工具权限由 MCP 服务为该 Key
配置；专用 provider adapter 还可以在 transport 前执行更严格的确定性门禁。不要把明文秘密或固定
业务参数写入 JSON 和提示词。

通用 MCP 无需新增 provider 专用 Python 选择分支。其原始响应由确定性通用投影处理；当某类结构需要
更精确的领域聚合时，在程序投影层新增结构化处理器和测试，结果处理阶段不调用模型。

FlashDuty 告警详情与相似告警都属于 `FLASHDUTY_API`，不是 MCP。相似告警查询随 FlashDuty API
正常注册，不增加独立的默认关闭开关；它可进入主 Agent 上下文，但只提供历史线索，机械上没有本次
告警的根因证据资格。只有按明确 MCP provider 契约识别的响应才会进入 generic MCP 投影，未知原生
工具不会再被兜底描述成“通用 MCP”。

## Archery MCP

Archery 的作用是查询慢查询日志，提示词位于 `config/mcp/prompts/archery/`。主 Agent 只有在当前
告警需要慢查询事实时才调用它。工作流使用 `/alert/info` 的 `alarm_host`、`alarm_port` 和
`occurred_at`，通过真实元数据链定位 `mysql_slow_query_review_history`，查询
`[occurred_at - 5 分钟, occurred_at]`。

认证、实例枚举、`t_instance_member` 和 `sql_instance` 等导航响应仅保存为内部审计 artifact。
最终 `mysql_slow_query_review_history` 结果只做 JSON 格式转换和既有秘密净化后完整透传，不过滤、
聚合、重排、截断、压缩 SQL 或设置最终结果大小上限。History 行中的 `raw`、`request_id`、`usage`、
`hash` 等同名键属于业务字段，必须保留；请求信封、调用 ID、usage 和 artifact hash 通过类型化字段与
结构位置隔离，不靠递归键名猜测删除。

确定性 Host 先发现 history 表全部真实字段，再进行固定快照下的排名扫描和“全部非 sample 字段”扫描；
排名只决定内部恢复顺序，最终行仍按 `id DESC`。每行 `sample` 使用直接查询或 Host 生成的
`SUBSTRING` 分片精确重组，并按 `LENGTH(sample)` 的 UTF-8 字节长度核验。只有字段、行集合和每个
sample 全部恢复后，History 才能成功并获得根因资格；任一分页、快照、字段、预算或分片失败都保留
已收到 artifact，但 History 显式不完整且不运行 supplemental。完整 History 超出模型上下文能力时必须
显式失败或返回 inconclusive，不能静默缩短。

动态 MCP Schema 负责普通 required、类型和额外参数校验；专用 Host 保留只读边界、单语句和数据
范围等安全门禁。单 id history 恢复使用 MySQL AST 做语义校验，允许大小写、空白、反引号、别名、
`ORDER BY id ASC|DESC` 和任意普通顶层 `LIMIT`；该 `LIMIT` 的存在与数值不参与 SQL 身份或本地拒绝
判定，`OFFSET` 仍保持独立语义。JOIN、子查询、额外谓词、错误目标表及未授权 id 仍在 transport 前拒绝。

完整恢复所有 History 行后，Archery adapter 才将 sample 与真实 history 行、allowlist 实例和 `db_max`
严格绑定并运行 supplemental。实例发现工具的结构化 allowlist 行可以在同一调查中保留并复用；真实
MCP 无筛选返回的编号文本只作目录，必须通过精确 `instance_ref` 定向查询成功后才能授权数据库发现。
任何 sample 都不能直接执行，但与完整 sample 绑定的普通 `EXPLAIN` 可以包裹 SELECT、WITH 以及目标
引擎支持的 DML；`EXPLAIN ANALYZE` 始终禁止。目标及实际执行 SQL 核对成功的 EXPLAIN、表结构和索引
结果形成独立 supplemental 单元。History 已完整但 supplemental 未完成时，完整 History 内容和资格不变，
仅 supplemental 标记为 `PARTIAL` 或 `FAILED`。新 Archery 父 evidence 只关联调用和原始 artifact，根因
必须引用具备资格的具体子单元 ID。

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
ARCHERY_MCP_URL=https://archery.example.internal/mcp
ARCHERY_MCP_TOKEN=replace-me
ARCHERY_SLOW_LOG_WINDOW_SECONDS=300
ARCHERY_MCP_TIMEOUT_SECONDS=60
ARCHERY_INVESTIGATION_BUDGET_SECONDS=150
ARCHERY_MCP_TOOL_TIMEOUT_SECONDS=180
```

## Prometheus MCP

Prometheus 的作用是查询数据库监控指标，提示词位于 `config/mcp/prompts/prometheus/`：

1. 将主 Agent 的调查目标和候选指标作为待验证意图传入子 Agent；
2. 先按告警数据库目标发现序列，从同一条序列动态取得物理指标名、语义指标标签、目标标签和作用域标签；`target`/`endpoint` 等数据库端点标签优先于 exporter 的 `instance`，复用物理指标可由 `metric` 等标签区分；
3. 对严格匹配告警数据库的指标查询 `[occurred_at - 5 分钟, occurred_at]` 完整时序；
4. 目标目录不可用时切换到其它只读发现能力。模型声明的 `out_of_scope` 仅供审计，不直接成为程序事实；只有 Host 基于完整、未裁剪的覆盖证据排除目标后才返回 `SKIPPED`；
5. 成功执行且明确返回零序列的范围查询返回 `NO_DATA`，空结果不证明目标未被监控；业务错误、超时、协议和传输失败保留各自失败状态。

Prometheus MCP 的地址通过 `PROMETHEUS_MCP_URL` 配置，连接方式通过
`config/mcp/settings.json` 中对应服务的 `transport` 配置；支持 `sse` 和 `streamable_http`，URL 应指向
所选连接方式对应的 endpoint。

目标发现、指标目录、元数据、动态目标绑定和模型范围声明只保存为内部审计 artifact。程序侧仅对
Host 已验证目标与时间窗匹配的时序计算样本数、最小值、最大值、均值、最新值、变化量、缺口和异常排序，
再把可追溯 observation 交给主 Agent。

```dotenv
PROMETHEUS_MCP_URL=https://prometheus-mcp.example.internal/mcp
PROMETHEUS_MCP_API_KEY_HEADER=
PROMETHEUS_MCP_API_KEY=
PROMETHEUS_MCP_TIMEOUT_SECONDS=60
PROMETHEUS_INVESTIGATION_BUDGET_SECONDS=180
PROMETHEUS_MCP_TOOL_TIMEOUT_SECONDS=780
```

## 知识来源

### 外部 KnowledgePack

KnowledgePack 独立部署；`EXTERNAL_KNOWLEDGE_BASE_URL` 必须能从 API 和 Worker 所在环境访问。
检索失败或空响应只表示该知识来源缺失，分析继续。

```dotenv
EXTERNAL_KNOWLEDGE_BASE_URL=https://knowledge.example.internal
EXTERNAL_KNOWLEDGE_API_KEY=replace-me
EXTERNAL_KNOWLEDGE_TIMEOUT_SECONDS=30
EXTERNAL_KNOWLEDGE_LIMIT=5
EXTERNAL_KNOWLEDGE_MIN_RELEVANCE=0.60
KNOWLEDGE_SOURCES=["external_knowledge"]
```

每个知识来源独立执行并记录 `matched`、`no_match` 或 `unavailable` 状态、命中数和耗时。
单个来源超过墙钟时限或有限重试仍失败时会被跳过，不占用整次分析剩余时间，也不会否决其它实时
证据。设置页修改外部知识开关时会保留 `KNOWLEDGE_SOURCES` 中其它已配置的扩展来源。

## FlashDuty 轮询

```dotenv
FLASHDUTY_ENABLED=true
FLASHDUTY_BASE_URL=https://api.flashcat.cloud
FLASHDUTY_APP_KEY=replace-me
FLASHDUTY_POLLING_ENABLED=true
FLASHDUTY_POLL_INTERVAL_SECONDS=300
FLASHDUTY_POLL_LOOKBACK_SECONDS=900
FLASHDUTY_POLL_CHANNEL_IDS=[123456789]
FLASHDUTY_POLL_INTEGRATION_IDS=[]
```

`FLASHDUTY_POLLING_ENABLED=false` 时不启动自动轮询，手动轮询和重新分析不受该开关影响。轮询器先
读取完整游标分页再入库，不设置影子模式；手动和后台轮询接入的新告警都执行相同的等级准入策略。

## 运行配置

关键分析配置：

```dotenv
# 可选：openai_compatible（默认，Chat Completions 兼容协议）或
# openai_responses（OpenAI Responses 协议）
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=replace-me
AI_MODEL=replace-me
AI_MAX_TOKENS=16384
AI_TIMEOUT_SECONDS=300
REACT_MAX_ROUNDS=8
ANALYSIS_TIMEOUT_SECONDS=1800
SCHEDULER_WORKERS=1
ALERT_ANALYSIS_FILTER_ENABLED=false
ALERT_ANALYSIS_FILTER_SEVERITIES=["INFO"]
# 必填部署基线；可在 Agent 设置页运行时覆盖。
STREAM_MAIN_AGENT_REASONING=false
```

`AI_PROVIDER` 默认保持为 `openai_compatible`，通过 OpenAI SDK 的 Chat Completions 接口调用 OpenAI、
DeepSeek 或内部兼容网关。使用 OpenAI Responses API 时设置为 `openai_responses`。两种真实 provider
都要求配置 `AI_API_KEY` 和 `AI_MODEL`；`AI_BASE_URL` 始终填写 API 根地址（例如
`https://api.openai.com/v1`），不要追加 `/chat/completions` 或 `/responses`。

`REACT_MAX_ROUNDS` 范围 1–100，默认 8；`ANALYSIS_TIMEOUT_SECONDS` 范围 30–86400，默认 1800。
`AI_MAX_TOKENS` 应为 reasoning 和结构化输出预留足够空间。模型超时或结构化输出不可用时，保守降级
为 `现有结果无法得出根因`，不会虚构结果。

`ALERT_ANALYSIS_FILTER_ENABLED` 默认关闭。开启后，`ALERT_ANALYSIS_FILTER_SEVERITIES` 中明确选中的
等级只入库，未选中的等级自动分析。例如 `["CRITICAL", "INFO"]` 会过滤 CRITICAL 和 INFO，仅分析
WARNING。列表按 `CRITICAL`、`WARNING`、`INFO` 的固定顺序去重；也可用逗号分隔形式
`CRITICAL,INFO`。该决定在首次入库时持久化，不会取消已排队或正在分析的任务，也不会因之后修改配置
而自动补跑历史 `FILTERED` 告警；管理员仍可显式重新分析这类告警。

旧版 `ALERT_ANALYSIS_FILTER_MAX_SEVERITY` 仅用于升级兼容：`INFO`、`WARNING`、`CRITICAL` 分别迁移为
`["INFO"]`、`["WARNING", "INFO"]`、`["CRITICAL", "WARNING", "INFO"]`。新列表存在时优先使用新
配置；Agent 设置页下一次保存后，运行时覆盖文件只保留新字段。

`STREAM_MAIN_AGENT_REASONING` 没有代码默认值，部署时必须显式设置。Agent 设置页中的开关属于运行级
覆盖，只影响之后创建的分析运行；清空运行级覆盖后，API 和 Worker 会立即恢复环境变量中的部署基线，
无需再次重启。

### Redis 异步分析队列

多进程部署使用 Redis Streams；MySQL 继续保存告警、租约、checkpoint 和分析结果。API 只向
`REDIS_STREAM_NAME` 写入任务，独立 Worker 通过 consumer group 消费，并在业务事务完成后确认消息。

```dotenv
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379/0
REDIS_USERNAME=database-alert-agent
REDIS_PASSWORD=replace-with-a-long-random-secret
REDIS_STREAM_NAME={database-alert-agent}:jobs
REDIS_DLQ_STREAM_NAME={database-alert-agent}:dlq
REDIS_CONSUMER_GROUP=database-alert-agent
REDIS_CLAIM_IDLE_SECONDS=660
HTTP_SCHEDULER=redis
```

`REDIS_CLAIM_IDLE_SECONDS` 不得小于 `INVESTIGATION_LEASE_SECONDS`。主 stream 不自动裁剪 pending
消息；成功或成功写入脱敏 DLQ 后才从主 stream 删除。自托管 Redis 必须启用 AOF、使用
`appendfsync everysec` 和 `maxmemory-policy noeviction`。Compose 强制加载 `.env`，启动前先从
`.env.example` 复制并设置 Redis 密码及其它必填部署值。
Compose 启动时生成仅可访问 `{database-alert-agent}:*` 的 ACL 用户；托管 Redis 应授予等价的
Stream、`EVAL`、`PING` 和只读队列观测权限。

## 本地运行

需要 Python 3.12+，Node.js 20.19+ 或 22.12+。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
alembic upgrade head
uvicorn app.api.main:app --reload
```

本地未启动 Redis 时使用进程内调度器；`.env` 中应保持 `REDIS_ENABLED=false` 和
`HTTP_SCHEDULER=in_memory`。若当前终端加载了 Redis 部署配置，可在 PowerShell 中临时覆盖：

```powershell
$env:REDIS_ENABLED="false"
$env:HTTP_SCHEDULER="in_memory"
uvicorn app.api.main:app --reload
```

使用 `HTTP_SCHEDULER=redis` 时，API 会在启动阶段执行 Redis `PING` 并在连接失败时退出；此模式必须
先启动 Redis，并另外运行 `python -m app.workers.redis`。

### 使用项目 Compose 在本地启动 Redis

Docker 不是硬性依赖；API 和 Worker 只要求能访问支持 Streams、consumer group、`XAUTOCLAIM` 和
Lua `EVAL` 的 Redis 7.x。Windows 项目目录不包含原生 `redis-server`，可选择由 Docker Desktop 或
Rancher Desktop（Moby 引擎）提供的 Docker Compose、WSL 中的 Redis，或外部托管 Redis。使用项目
自带的 Redis 7.4、AOF 和 ACL 配置时，若根目录尚无 `.env`，先执行：

```powershell
Copy-Item .env.example .env
```

若已安装 Rancher Desktop 但 PowerShell 找不到 `docker`，可把其 bundled CLI 加到当前终端 PATH：

```powershell
$rdBin="C:\Program Files\Rancher Desktop\resources\resources\win32\bin"
$env:Path="$rdBin;$env:Path"
docker compose version
docker version
```

`docker version` 必须同时显示 Client 和 Server；只有 Client 或出现 backend 连接错误时，先重启
Rancher Desktop，等待 Moby 引擎就绪后再运行 Compose。

在 `.env` 中替换示例密码，并启用 Redis 调度器：

```dotenv
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379/0
REDIS_USERNAME=database-alert-agent
REDIS_PASSWORD=replace-with-a-long-random-secret
HTTP_SCHEDULER=redis
```

先只启动 Redis，并等待状态变为 `healthy`：

```powershell
docker compose up -d redis
docker compose ps redis
```

Redis 未变为健康状态时使用 `docker compose logs redis` 检查启动日志，不要先启动 API 或 Worker。
Redis 健康后，在两个 PowerShell 终端分别启动 Worker 和 API：

```powershell
# 终端 1
python -m app.workers.redis

# 终端 2
uvicorn app.api.main:app --reload
```

如果之前在 PowerShell 中临时覆盖过进程内调度配置，先执行
`Remove-Item Env:REDIS_ENABLED, Env:HTTP_SCHEDULER -ErrorAction SilentlyContinue`，否则终端环境会覆盖
`.env`。开发结束后可执行 `docker compose stop redis`；持久化 stream 数据仍保留在 `redis-data` volume。

### 不使用 Docker 运行 Redis

在 WSL 或其它本机服务中启动 Redis 7.x 后，保持 `REDIS_URL=redis://localhost:6379/0`。若该实例仅在
loopback 上提供无认证的本地开发服务，将 `.env` 中 `REDIS_USERNAME` 和 `REDIS_PASSWORD` 留空；若已
配置 ACL，则填写服务端创建的用户名和密码。外部 Redis 则把 `REDIS_URL` 改为其可达地址。用于故障恢复
验证的实例仍应启用 `appendonly yes`、`appendfsync everysec` 和 `maxmemory-policy noeviction`。

前端：

```bash
cd frontend
npm install
npm run dev
```

也可使用 Docker Compose 一次启动 Redis、数据库迁移、Worker、API 和前端：

```powershell
docker compose up -d --build
```


## 将内置 SQLite 数据迁移到 MySQL 8.0

项目通过 `mysql+asyncmy` 支持外部 MySQL。当前持久化数据包含超过 MySQL `TEXT` 64 KiB
上限的 checkpoint write 和 artifact 内容；迁移 `0017` 会在 MySQL 中把这两个字段升级为
`LONGTEXT`。

迁移 `0018` 将仅供历史审计的 `alerts.legacy_runbooks_json` 改为可空：旧行的审计内容保持不变，当前
ORM 插入的新告警使用 `NULL` 表示“不适用”，不依赖 MySQL 对 JSON 默认值的支持。已有 MySQL 部署
必须先停止 API 和 Worker、完成备份，再运行 `alembic upgrade head` 后重启；只重启应用不会修复
数据库约束。

目标必须满足：

- MySQL 8.0.13+（早期 8.0 版本不支持本项目使用的 JSON 表达式默认值）；
- 使用独立、空的数据库，默认字符集为 `utf8mb4`，默认排序规则为 `utf8mb4_bin`；
- 迁移账号可创建和修改表、创建索引并读写目标数据库；
- 启用 `STRICT_TRANS_TABLES` 或 `STRICT_ALL_TABLES`，防止迁移时静默截断数据；
- 保持 MySQL 默认的小数秒四舍五入行为；迁移工具不接受 `TIME_TRUNCATE_FRACTIONAL` 模式；
- `max_allowed_packet` 足以容纳最大单行。迁移工具会读取服务端值并在写入前校验；
- API 和 Worker 已停止，SQLite 文件已通过 SQLite backup API 或存储卷快照完成一致性备份。

先安装 MySQL extra，并在服务停止后把源 SQLite Schema 升到当前 head：

```bash
python -m pip install -e ".[dev,mysql]"
alembic upgrade head
```

通过进程环境（优先）或 Git 已忽略的本地 `.env` 安全提供目标 URL。不要把密码作为命令行参数；密码中的特殊字符必须进行 URL 编码：

```bash
export MIGRATION_TARGET_DATABASE_URL='mysql+asyncmy://user:password@mysql.example:3306/database_alert_agent?charset=utf8mb4'
python -m tools.migrate_sqlite_to_mysql --source data/alerts.db
```

PowerShell 使用：

```powershell
$env:MIGRATION_TARGET_DATABASE_URL = 'mysql+asyncmy://user:password@mysql.example:3306/database_alert_agent?charset=utf8mb4'
python -m tools.migrate_sqlite_to_mysql --source data/alerts.db
```

若执行进程无法继承当前 Shell 的环境变量，可只在本地 `.env` 追加：

```dotenv
MIGRATION_TARGET_DATABASE_URL=mysql+asyncmy://user:password@mysql.example:3306/database_alert_agent?charset=utf8mb4
```

工具会按外键顺序创建/升级目标 Schema，持有 SQLite 写锁取得一致快照，分批提交数据，并逐表比较
行数及规范化 SHA-256。当前 MySQL Schema 使用 `DATETIME(0)`，摘要按 MySQL 的秒级四舍五入结果比较；
MySQL binary JSON 往返可能让 `DOUBLE` 改变一个 ULP，摘要按 12 位有效数字比较浮点值。除此以外不忽略
字段差异。目标 URL 只以隐藏密码的形式输出。中断后保留目标中的已提交批次，使用相同源库和目标库继续：

```bash
python -m tools.migrate_sqlite_to_mysql --source data/alerts.db --resume
```

只重新校验、不写目标库：

```bash
python -m tools.migrate_sqlite_to_mysql --source data/alerts.db --verify-only
```

校验成功后，将部署环境中的 `DATABASE_URL` 改为同一个 `mysql+asyncmy` URL，确保 API、Worker 和
Alembic 使用完全一致的值，再启动服务并检查 `/health/ready`。回滚时停止服务，把 `DATABASE_URL`
恢复为原 SQLite URL；迁移工具不会修改或删除源 SQLite 数据。

## API

- `POST /api/v1/alerts/{source}/analyze`：接收非 FlashDuty 告警并异步分析；FlashDuty 仅由轮询器接入。
- `GET /api/v1/alerts`、`GET /api/v1/alerts/{alert_id}`：查询告警与指定运行结果。
- `GET /api/v1/alerts/{alert_id}/flashduty-handling`：读取 FlashDuty 关联故障的当前处理状态和已认领人员；当前快照不随历史分析运行回放。
- `GET /api/v1/alerts/{alert_id}/runs/{run_id}/trace`：增量读取 thought/action/observation。
- `POST /api/v1/alerts/{alert_id}/runs/{run_id}/cancel`：管理员 Bearer 认证，幂等取消运行，返回 202。
- `POST /api/v1/alerts/{alert_id}/reanalyze`：使用当前配置创建新的分析运行。
- `POST /api/v1/admin/flashduty/poll`：管理员手动执行一轮 FlashDuty 拉取、去重和调度。
- `GET|PATCH /api/v1/admin/settings`：查看或更新允许在线维护的运行配置。
- `GET /api/v1/admin/analysis-dispatch`：读取持久化调度状态、暂停原因、最近模型验证、FlashDuty 最近轮询状态和待执行数量。
- `POST /api/v1/admin/analysis-dispatch/validate-and-resume`：按调度版本和当前模型配置指纹验证模型；仅验证成功时恢复并补投待执行告警。
- `GET /health/live`、`GET /health/ready`：存活和就绪检查。

管理员接口使用：

```http
Authorization: Bearer <ADMIN_API_TOKEN>
```

## 验证

```bash
pytest -m "not live"
ruff check app tests migrations
python -m compileall -q app tests
cd frontend && npm run build
git diff --check
```

独立 Agent 场景报告的零容忍和故障族门槛使用：

```bash
python tools/evaluate_production_gates.py \
  --report evaluation/results/agent-harness-report.json \
  --enforce-gates
```

离线测试使用 fake client、Replay MCP 和临时数据库，不访问真实模型、FlashDuty、MCP 或企微。重点覆盖
ReAct 正常 `finish`、轮次上限、整次超时、主动取消、同 run checkpoint 恢复、模型故障分类、持久调度
暂停、显式验证恢复、确定性结果投影、通知补发、artifact 追溯及前端增量轨迹。

生产部署应把 `APP_CODE_VERSION` 设置为不可变镜像摘要或 Git revision，并让同一批 API 与 Worker 使用
一致值。数据库升级使用 Alembic；生产升级前停止服务并备份数据库。
