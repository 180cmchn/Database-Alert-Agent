# Database Alert Agent

本项目只负责一条告警分析链路：

1. 通过 FlashDuty 只读 Open API 定时轮询指定协作空间的告警并规范化；告警等级固定为 `CRITICAL`、`WARNING`、`INFO`。
2. 按运行时选择检索本地 PDF 和/或外部 KnowledgePack，完成精排、阈值过滤和拒识。
3. 先完成知识匹配和全部只读实时证据/MCP 日志采集，再由 AI Agent 一次性分析根因和只读建议。
4. 本地 PDF 与外部知识库同级作为知识依据，并统一列在 AI 分析之前。
5. 将每个等级的最终 AI 分析结果发送到企业微信群机器人。


## 架构

项目采用 **LangGraph** 框架构建告警调查工作流。调查图定义了清晰的节点和边，实现可观测、可调试的分析链路：

```text
START → fingerprint → runbook → strategy → execute_tools
      → advise → validate → report → END
```

**节点说明：**

| 节点 | 功能 |
| --- | --- |
| `fingerprint` | 生成稳定告警指纹，用于去重和调查关联 |
| `runbook` | 并行检索所选本地 PDF 与外部知识来源，并执行阈值拒识 |
| `strategy` | 根据告警目标、信号和时间窗生成只读采集计划，不生成根因假设 |
| `execute_tools` | 完整执行计划中的调查工具并保存原始证据 |
| `advise` | 所有采集终态后，AI 根据知识与实时证据一次性分析根因 |
| `validate` | 规则校验 + 独立结论验收 |
| `report` | 生成最终报告，更新状态 |

**状态管理：**

使用 `AgentState` (Pydantic BaseModel) 在节点间传递状态，支持：
- 告警信息、运行记录、证据列表
- 验证、影子分析、AI 降级等配置

`react_enabled` 与 `react_max_dynamic_turns` 暂时保留为旧配置兼容字段，新运行不再进入动态根因
规划循环。MCP 子 Harness 仍可在单个计划任务内部执行有界的目标发现、Schema 发现和多步只读查询，
但这些步骤只采集事实，不生成、评估或引用根因假设。

调查图使用 `state.error` 传播不可恢复错误。知识匹配、手册检索、策略选择、工具执行、建议生成和
验证等中间节点发现上游错误后会立即短路，不再继续发起后续调查或 AI 调用；`report` 节点统一将
运行和告警分析落为 `FAILED` 并保存失败进度，避免失败链路继续产生无效结果。

**持久化 Agent harness：**

- `RunManifest` 在创建运行时冻结代码、模型、提示词、工具 Schema、工具策略和有效配置；其摘要同时
  写入 checkpoint，恢复时若摘要不一致会拒绝加载，避免用另一套运行契约续跑旧状态。Manifest 已预留
  `knowledge_versions` 字段，但当前创建运行时尚未采集知识源版本，该字段保持空对象，因此当前恢复
  校验不承诺检测 PDF 或外部知识库内容漂移。
- LangGraph 主图使用 `agent` checkpoint namespace；外层每次逻辑派发的 MCP 子运行使用
  `mcp:<provider>:<dispatch_id>`。同一逻辑派发的首次执行与恢复尝试复用该 namespace，不同派发则相互
  隔离，避免串用 Archery、Prometheus 等 provider 的状态和预算快照。
- event 是按运行追加、带顺序号和版本的审计流；invocation 持久化工具名、有效参数指纹、尝试次数、
  生命周期、错误详情和 artifact 引用；artifact 保存经过脱敏的大结果，并记录大小和 SHA-256 摘要。
- 同一运行被重新领取后会从 checkpoint 恢复图状态、成功观测、预算、重试状态和已完成 invocation，
  不重新执行已经完成的节点或远程调用。显式“重新分析”仍创建新的运行，不复用旧运行的实时证据。
- 恢复前还会比较当前代码、模型、提示词、工具 Schema、工具策略和有效配置与 frozen manifest；如果
  这些已填充的运行契约发生漂移，则 fail closed 为失败终态，不加载旧图或调用 MCP，需要用当前配置
  创建新运行。
- 所有运行期持久化写都携带当前 `lease_owner` 和单调递增的 `fencing_token`。heartbeat 无法续租或
  owner/token 已变化时，旧 worker 会取消长操作并 fail closed；过期 worker 不能再写 event、
  checkpoint、invocation、artifact 或最终运行状态。

每个计划任务由外层 durable dispatcher 负责幂等执行；MCP 子 Harness 会在返回终态前按只读与重试
策略完成受控重试。Archery 和 Prometheus 的一个计划任务可包含内部多步调用，但外层 Agent 不会根据
中间结果追加根因驱动探针。下表列出对外证据状态和 durable invocation 的保守终态语义：

| 状态 | 语义 | 根因判定用途 |
| --- | --- | --- |
| `SUCCESS` | 调用完成并返回本次实时观测 | 仅完整、目标与时间窗匹配的实时记录可在采集后用于根因分析 |
| `NO_DATA` | 调用成功，但没有返回可用观测 | 缺失证据，不能得出根因 |
| `FAILED` | 调用执行失败 | 缺失证据，不能得出根因 |
| `TIMEOUT` | 调用未在截止期内完成 | 缺失证据，不能得出根因 |
| `SKIPPED` | 工具未注册、不可用或被 Host 策略拒绝，未发起远程调用 | 缺失证据，不能得出根因 |
| `UNKNOWN_OUTCOME` | 调用已越过远程边界，但恢复时无法确认是否完成 | 缺失证据，不能当作查询已执行或未执行的证明 |
| `CANCELLED` | 调用因租约丢失、运行终止或取消信号而停止 | 缺失证据，不能得出根因 |

`partial=true` 表示本次调查未完整结束；即使其中保留了部分成功观测，整条 partial 证据也只能用于
描述与审计，不能据此得出根因。未返回、被截断或失败的部分同样是证据缺口。计划调用沿用策略中
该工具的 `timeout_seconds` 和 `required`，不会把多步 MCP Host 重新压缩到固定 10 秒。

## 数据流

```text
FlashDuty /alert/list（定时轮询）
             ↓
按协作空间过滤、alert_id 去重、规范化与异步入队
                                  ↓
三等级规范化与脱敏
          ↓
所选知识来源并行检索：本地 PDF 结构化匹配 + 外部 KnowledgePack 向量检索
          ↓
LangGraph 调查图：fingerprint → runbook → strategy
          → execute_tools → advise → validate → report
          ↓
结构化原因与有序依据
          ↓
企业微信群机器人
```

企业微信群机器人 Webhook 是**出站发送地址**，只用于发送分析结果。FlashDuty 告警由本服务通过 Open API 主动轮询，不提供任何 FlashDuty 入站 Webhook。企微发送执行有界重试；服务不会查询是否送达，也不会因发送失败改写已经完成的分析状态。

## 告警手册

运行时手册按规范化告警类型存放：`runbooks/pdfs-typed/<alert_type>/*.pdf` 是不可变的审计原文，
同目录的 `index.json` 是该类型对应的结构化检索和诊断结果。索引记录知识类型、停用标志、
适用范围、告警别名、真实章节/页码、候选原因、支持证据、反证、只读核查动作、需要审批的
变更动作，以及图片中红框/高亮的关键报错、代码和界面字段。文件名（不含 `.pdf`）仍是稳定
手册 ID。同一 PDF 覆盖多个告警类型时，处理工具会把相同字节和等价注解复制到各类型目录；
运行时按稳定手册 ID 聚合为一份手册，并保留全部适用告警类型。

检索会读取所有类型目录，并用告警类型、告警名、指标名、原因和标题与手册的 `alert_type`、
告警名、指标名及别名做确定性的语义匹配。规范化同名保持最高权重；CPU、内存、磁盘、连接、
慢查询、复制延迟、锁等诊断信号按同义信号族召回，其余类型使用拆分后的高特异词项覆盖率匹配。
目录仍是处理和审计组织单元，不再是检索硬边界。候选随后按数据库适用范围和结构化条件过滤，
并组合图片关键报错、BM25/中文字符片段召回和分数排序；没有语义候选时返回“未命中”，不会因
缺少同名目录而抛出类型不存在异常。
每份 PDF 只返回得分最高的章节；低于分数或置信度阈值时明确返回“未命中”。投入运行的
PDF 和视觉证据不维护质量等级或审核状态，所有可检索手册按相同规则参与匹配。
`knowledge_type=incomplete` 或 `deprecated=true` 的资料不参与检索；`deprecated` 仅表示资料已停用。
`knowledge_type=incident_case` 表示手册内容本身是历史事故案例，仍属于部署提供的本地 PDF 知识，
与已删除的人工反馈衍生 `knowledge_cases` 数据库表无关。

PDF 必须未加密且带可提取文字层；纯扫描件需先 OCR。含图页面还必须在索引中记录带页码的
`visual_evidence`，避免只提取文字层而遗漏图片中的诊断信息。手册目录为只读运行数据，更新方式
是替换目录内 PDF 后重启 API 和 Worker，不支持通过管理 API 在线增删改。

真实手册 PDF 和各类型目录中的 `index.json` 属于部署数据，不提交到 Git。干净克隆后必须由
受控制品库提供完整的类型目录，或在容器启动时只读挂载到 `RUNBOOK_PDF_DIR`；缺少类型目录或
PDF 时，就绪检查不会把实例标记为可用。普通自动化测试使用自包含的小型 PDF fixture，不依赖
生产手册。

原始平铺 PDF 存放在 `runbooks/pdfs`；先处理到运行时类型目录
`runbooks/pdfs-typed`，再让 `RUNBOOK_PDF_DIR` 指向生成目录：

```bash
.venv/bin/python tools/process_pdf_runbooks.py \
  --source-pdf-dir /path/to/flat-pdfs \
  --output-dir /path/to/typed-pdfs
```

推荐使用 AI 自动摄取模式。它读取项目现有 `.env`/运行时 AI 配置，按 PDF 分页正文抽取一个或
多个告警类型、类型专属匹配字段、章节、正文明确列出的候选原因和动作，生成类型目录和索引，
随后同步自动回归数据并执行覆盖率准入。`--sync` 允许重复执行：内容哈希未变化的 PDF 直接复用
已有索引，只对新增或变更 PDF 调用模型。如果首轮严格抽取未识别类型，工具会自动复查
案件标题、触发条件和处置流程；明确标注的应急处置标题还有受限的原文回退，不需要人工补写索引。

```powershell
python .\tools\process_pdf_runbooks.py --source-pdf-dir .\runbooks\pdfs --output-dir .\runbooks\pdfs-typed --auto-index --sync --enforce-gates
```

自动模式不需要 `source-index.json`。`--source-index` 仅作为可选的显式覆盖；其中可分别使用
`alert_type` 或 `alert_types`。不使用 `--auto-index` 时，处理工具只能依赖索引、结构化字段或 PDF
文字层中的明确类型标签，不能从普通叙述中做语义推断。显式传入的索引路径必须真实存在。

```json
{
  "schema_version": 2,
  "runbooks": [
    {
      "runbook_id": "shared-database-guide",
      "alert_types": ["mysql_crash", "mysql_connections_high"]
    }
  ]
}
```

相关环境变量：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs-typed
RUNBOOK_LIMIT=5
RUNBOOK_PDF_MAX_FILE_BYTES=20000000
RUNBOOK_PDF_MAX_TEXT_CHARS=200000
RUNBOOK_MATCH_MIN_SCORE=12
RUNBOOK_MATCH_MIN_CONFIDENCE=0.35
```

网页抓取、内网域名白名单、Cookie/Bearer 登录和 Markdown 手册索引均已删除。

## 外部知识库

KnowledgePack 作为独立项目和独立镜像部署。它与 Agent 的 Compose 项目加入同一个预创建的
Docker 网络，并通过网络别名 `knowledge` 提供接口；不向宿主机发布端口。Agent 只调用
`POST /search`。Agent 的启动和就绪检查不探测知识库；知识库应由自身服务检查健康状态，
检索失败时 Agent 按可选知识来源缺失处理。配置启用的外部知识内容与本地 PDF 同级作为知识依据；
两者都不能代替本次事故的实时证据。

在同一 Docker Engine 上只需创建一次共享网络，两个项目可随后独立启动、停止和升级：

```bash
docker network create database-alert-knowledge
```

Agent 部署配置：

```dotenv
KNOWLEDGE_NETWORK_NAME=database-alert-knowledge
EXTERNAL_KNOWLEDGE_BASE_URL=http://knowledge:8000
EXTERNAL_KNOWLEDGE_API_KEY=replace-with-the-same-long-random-secret
EXTERNAL_KNOWLEDGE_LIMIT=5
EXTERNAL_KNOWLEDGE_MIN_RELEVANCE=0.60
KNOWLEDGE_SOURCES=["local_pdf","external_knowledge"]
```

Agent 的 API 和 Worker 都加入 `KNOWLEDGE_NETWORK_NAME` 指定的外部网络，并通过
`http://knowledge:8000` 访问 KnowledgePack。Base URL 和最低相关度均为部署级配置，不能通过管理
API 修改。管理页可选择 `local_pdf`、`external_knowledge` 或两者；“外部知识库”参考来源按钮就是
连接开关，选中并保存后创建外部知识客户端，取消并保存后停用连接。管理页还允许录入只写 API
Key。运行时录入的 Key 会绑定当前 Base URL；部署变更 URL 后旧 Key 不会发送，必须在管理页重新
输入。

本地 PDF 使用 `RUNBOOK_MATCH_MIN_SCORE` 和 `RUNBOOK_MATCH_MIN_CONFIDENCE` 拒绝低匹配候选；
外部知识先把 KnowledgePack 的 cosine distance 转成 `clamp(1-distance, 0, 1)`，再按
`EXTERNAL_KNOWLEDGE_MIN_RELEVANCE` 过滤。当所有已选来源均未达到阈值时，Agent 会明确记录
“拒绝匹配”，只基于告警、实时证据和通用推理生成低置信度结果。

## AI 与企微配置

复制环境变量模板并填写模型与企微机器人地址：

```bash
cp .env.example .env
chmod 600 .env
```

旧配置名 `RUNBOOK_DIR`、`MANAGEMENT_WEBHOOK_URL`、`NOTIFIER_MODE` 和通知重试/升级相关变量已不再
生效；升级部署时应以 `.env.example` 为准，分别改用 `RUNBOOK_PDF_DIR` 和官方
`WECOM_WEBHOOK_URL`，并为卡片操作配置 `WECOM_PAGE_BASE_URL`。FlashDuty 轮询还必须显式配置
APP Key 与协作空间 ID。

关键配置：

```dotenv
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=replace-me
AI_MODEL=replace-me
AI_MAX_TOKENS=16384
AI_TIMEOUT_SECONDS=300
AI_FALLBACK_ENABLED=true
SCHEDULER_WORKERS=1
SHADOW_ENABLED=true
PRODUCTION_GATE_APPROVED=false

WECOM_ENABLED=true
WECOM_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=replace-me
WECOM_PAGE_BASE_URL=https://alerts.intra.example.com
```

`AI_MAX_TOKENS` 会显式传给主分析和独立结论验收。对于默认启用 Thinking 的推理模型，
建议至少使用 `16384`，并配合足够的 `AI_TIMEOUT_SECONDS`；否则企业网关常见的 `4096` 默认上限
可能全部消耗在 `reasoning_content`，以 `finish_reason=length` 结束且没有最终 `content`。

`SCHEDULER_WORKERS` 控制每个进程同时分析的告警数，范围为 1–16，默认 1。该值属于运行时白名单，
可通过 Agent 设置页或 `PATCH /api/v1/admin/settings` 调整；In-Memory 调度器立即调整并行上限，
Kafka Worker 在下一批消息开始前读取并应用新值。

`AI_API_KEY` 和 `WECOM_WEBHOOK_URL` 都是秘密值。管理 API 只返回“是否已配置”，不会返回原值。
启用企微通知时还必须配置 `WECOM_PAGE_BASE_URL`，它应是企微客户端可访问的前端 HTTPS 地址；
开发环境未启用企微时仅写本地日志，便于测试。

当模型请求超时、网关不支持结构化输出或模型连续两次返回不符合 Schema 的结果时，`AI_FALLBACK_ENABLED=true` 会生成固定的“现有结果无法得出根因”结果，继续走完 `VALIDATING → REPORTING → INCONCLUSIVE`，不会在建议阶段直接跳到 `FAILED`。该结果的置信度为零，并在校验记录中保留降级原因类型。数据库、持久化等不可恢复的系统错误仍会正确进入 `FAILED`。

如果 `AI_FALLBACK_ENABLED=false` 或没有可用的降级 Advisor，建议生成失败会写入 `state.error`，
后续中间节点短路并由 `report` 统一结束失败链路。服务同时记录包含异常类型和脱敏错误摘要的
`advise_failed_no_fallback` 告警日志，便于定位模型网关或响应格式问题。

## FlashDuty 只读接入

项目仅通过 [FlashDuty Open API](https://docs.flashduty.com/zh/openapi) 轮询和查询告警。客户端采用显式只读白名单；虽然 FlashDuty 的查询与诊断接口多数使用 `POST`，项目不会调用创建、更新、删除、认领、恢复等写接口。

```dotenv
FLASHDUTY_ENABLED=true
FLASHDUTY_BASE_URL=https://api.flashcat.cloud
FLASHDUTY_APP_KEY=replace-me
FLASHDUTY_TIMEOUT_SECONDS=40
FLASHDUTY_MAX_RETRIES=2
FLASHDUTY_CONTEXT_ITEM_LIMIT=20
FLASHDUTY_POLLING_ENABLED=true
FLASHDUTY_POLL_INTERVAL_SECONDS=300
FLASHDUTY_POLL_LOOKBACK_SECONDS=900
# 必填：仅轮询这些协作空间
FLASHDUTY_POLL_CHANNEL_IDS=[123456789]
FLASHDUTY_POLL_INTEGRATION_IDS=[]
FLASHDUTY_CHANGES_ENABLED=false
FLASHDUTY_MONITORS_ENABLED=false
FLASHDUTY_METRICS_DS_NAME=
FLASHDUTY_LOGS_DS_NAME=
FLASHDUTY_LOGS_DS_TYPE=loki
```

`FLASHDUTY_APP_KEY` 是部署级秘密值，不可通过管理 API 修改或读取。Base URL 固定为官方 HTTPS Endpoint，客户端禁止跟随重定向，错误和证据中不会保留 APP Key。建议在 FlashDuty 中为此项目创建最小权限的独立只读 APP Key。

### FlashDuty API 轮询配置

完整的配置、去重语义、排障和安全检查见 [FlashDuty Open API 轮询接入](docs/flashduty-polling/README.md)。

1. 在 `.env` 设置 `FLASHDUTY_ENABLED=true`、最小权限的 `FLASHDUTY_APP_KEY` 和 `FLASHDUTY_POLLING_ENABLED=true`。
2. 设置 `FLASHDUTY_POLL_CHANNEL_IDS=[<协作空间数字 ID>]`；此项在启用轮询时必填，避免拉取 APP Key 可访问的全部空间。
3. 使用 `FLASHDUTY_POLL_INTERVAL_SECONDS` 配置轮询间隔（当前最小 300 秒），使用 `FLASHDUTY_POLL_LOOKBACK_SECONDS` 配置重叠回看窗口；启用轮询时，回看窗口不得小于轮询间隔。
4. 每轮以开始轮询的当前时间为窗口终点，按 `start_time` 回看完整配置窗口；轮询器先穷尽 `/alert/list` 游标分页，再以 `source + alert_id` 幂等入库。重复的 `alert_id` 不会创建第二个分析任务，系统也不会因同一告警后续状态更新而重复分析。
5. 服务只需出站访问 FlashDuty HTTPS API，不需要 Endpoint、Nginx 入站反代、回调证书或 Webhook Token。

启用后：

- `alert_context` 读取告警详情、原始事件、告警动态，以及关联故障的详情、时间线和告警；
- 有 `incident_id` 时，默认追加 `query_similar_incidents`；历史故障只作为调查线索，不会单独支撑“已验证根因”；
- `query_changes` 不再作为基础采集项；只有显式设置 `FLASHDUTY_CHANGES_ENABLED=true` 后才注册该适配器，且必须由告警目标、信号和时间窗明确选择；
- 所有 `/monit/*` 工具默认关闭。只有只读能力审计确认存在数据源或监控对象工具后，才设置 `FLASHDUTY_MONITORS_ENABLED=true`；`query_database_diagnostics` 不再由基础工作流自动调用；
- 外部调用成功但业务记录为空时保存为 `NO_DATA`，未注册、未配置或目标未暴露能力时保存为 `SKIPPED`，两者都不能作为 `SUCCESS` 实时证据。

项目使用的上游接口均已按官方 OpenAPI 重新核对：

| 用途 | FlashDuty 上游只读接口 |
| --- | --- |
| 漏送补偿 | `/alert/list`（必填创建时间窗，`by_updated_at=false`，游标分页） |
| 告警详情与现场事件 | `/alert/info`、`/alert/event/list`、`/alert/feed` |
| 关联故障上下文 | `/incident/info`、`/incident/alert/list`、`/incident/feed` |
| 历史相似故障 | `/incident/past/list` |
| 同时间窗变更 | `/change/list` |
| 指标/日志诊断 | `/monit/query/diagnose` |
| 原始只读查询 | `/monit/query/rows` |
| 数据库监控对象 | `/monit/targets`、`/monit/tools/catalog`、`/monit/tools/invoke`（额外限制只读工具名） |

核心告警详情成功、部分事件流或故障时间线失败时，`alert_context` 会保存已取得的数据及失败类型并继续分析，避免单个辅助接口暂时不可用导致整条 AI 流程失败。

`FLASHDUTY_POLL_CHANNEL_IDS` 只约束告警和变更的协作空间范围；FlashDuty 的 Monitors 数据源、监控对象与工具目录是账户级能力，不能仅凭协作空间 ID 推定存在。启用 Monitors 前必须先确认 `/monit/datasource/list` 或 `/monit/targets` 有对象，并对目标调用 `/monit/tools/catalog` 验证实际工具目录；接口存在不等于目标 Agent 已暴露工具。

数据源查询需要真实存在的 `ds_name` 和查询表达式。指标查询可在告警中提供合法的 `metric_name`，
也可由已配置的告警属性提供 `expr`；数据库诊断需要可解析的 `target_locator` 和非空工具目录。缺少
必要绑定时不会注册相应能力，也不会猜测查询或降级到写操作。SQL 类查询只接受单条 `SELECT`、
`SHOW`、`DESCRIBE` 或 `EXPLAIN`，同时仍应确保 FlashDuty 数据源自身使用数据库只读账户。

FlashDuty 告警详情、事件、动态和故障上下文主要描述“发生了什么”，不能单独证明数据库根因。
只有 Monitors 指标、日志、原始只读查询或 monit-agent 数据库诊断等非告警平台的本次完整
`SUCCESS` 证据，才可在全部采集结束后参与根因分析。

影子模式仍执行完整检索、调查、建议和校验链路，但最终状态固定为 `INCONCLUSIVE`，建议
标记为 `analysis_mode=shadow`。生产准入验证完成前，建议保持开启。
生产环境只有在部署侧显式设置 `PRODUCTION_GATE_APPROVED=true` 后才允许关闭影子模式；该开关
不属于管理 API 可在线修改的配置。

企微消息使用 `template_card`，主体展示告警标题、级别、主机、数据库、环境、服务和外部 ID，
底部固定两项操作：

- “告警根因分析”：在企微客户端内打开 `/wecom/alerts/{id}/root-cause` 轻量页面，只展示已封装的
  摘要、采证后仍可能的根因、证据引用和置信度；`next_probe` 保留在结构化结果中，不在该页重复
  展示；
- “告警恢复建议”：在企微客户端内打开 `/wecom/alerts/{id}/recovery-advice` 轻量页面，只展示已
  封装的建议步骤、预期结果、注意事项和风险。

群机器人 Webhook 只负责出站通知，不具备按钮事件回调和原卡片更新能力。若需要完全原生的卡片
内联交互，需切换到企业自建应用消息并增加回调验签与卡片更新接口。

## Archery 慢查询实时证据

慢查询告警的计数口径来自“在五分钟内统计慢查询、超过 500 个触发”：它定义统计窗口和阈值，
例如 646 个是本次告警提供的观测值。“（已排除 N 个数据库管理平台采集数据用 SQL）”只是附带的
SQL 过滤说明，不是计数口径或候选根因，也不用于把观测值重新计算成其它数值。系统会在知识匹配、
调查规划和 AI 分析前递归删除该注释；原始 `raw_payload` 仍完整保存用于审计。历史告警重新分析时
也会执行同样的预处理，避免旧记录再次把过滤说明带入根因判断。

当规范化后的告警标题包含独立的 `slow_query` 标识符时（忽略大小写，但不匹配
`slow_queryable` 等更长标识符），调查策略会新增一个必需的
`query_archery_slow_logs` 取证任务。项目自身作为 MCP Host，加载
[`config/mcp/settings.json`](config/mcp/settings.json) 中的 Archery 连接配置，在同一个
Streamable HTTP 会话中完成初始化、工具发现和确定性登录，再把项目批准的只读工具及其 MCP
Schema 以 function tools 交给当前 AI 模型。模型每轮自主选择一个下一步只读探针。慢查询取证
由 Host 独占调用 `ensure_login_gymJPA`；模型可见的受控工具集为：

- `list_resource_groups_gymJPA`；
- `list_instances_gymJPA`；
- `list_instance_databases_gymJPA`；
- `list_db_tables_gymJPA`；
- `list_table_columns_gymJPA`；
- `sql_query_gymJPA`。

Host 给模型的用户提示包含 MCP 地址、规范化告警中的实例名、主机、端口、数据库名等目标线索、
告警时间窗、推荐的实例映射链路和最多返回行数。部署配置不再固定查询实例和数据库。模型根据
告警上下文、工具实时 Schema 与资源发现结果自主确定目标，并决定是否查询资源组、实例、数据库、
表和字段。
每个 MCP 结果经脱敏和长度限制后回传给下一轮模型调用；SQL 语法和只读元数据探针等非鉴权错误
也会以脱敏、截断后的诊断回填，模型可据此调整参数或改走其它只读路径。认证、权限和安全错误仍
立即终止。Archery 登录由 Host 在模型调查前确定性执行，登录工具不进入模型可见工具集，登录结果
以 Host 控制事件而不是伪造的 `assistant tool_call` 写入上下文，因此不占远端 MCP 调用预算。每轮
结果会分别明确远端调用和模型决策的已用、剩余数。模型选择失败时 Host 会把脱敏错误、剩余预算和
严格单工具调用要求作为 repair feedback，再做一次有限重试。若兼容 API 仍返回纯文本而非工具
调用，诊断会保留脱敏后的 `finish_reason`、文本长度和截断预览。每条告警的一次分析运行最多向
Archery MCP 发送 `ARCHERY_MCP_MAX_AGENT_STEPS` 个模型选择的工具调用；首次会话、重连、checkpoint
恢复和受控重试共享该总预算。默认值为 12，给元数据链路后的样例探针和只读重试保留空间。MCP
返回的工具中可能包含
`apply_query_permission_gymJPA` 等会产生外部状态变更的
工具；这些工具不会进入模型可见的工具列表。

MCP 服务端仍是工具 Schema 和业务错误的来源；Host 只额外负责不能交给模型自律的控制面：认证、
只读工具范围、单条 `SELECT/WITH` 安全检查、精确告警窗口和结果上限。写 SQL 或多语句在网络请求前
被拒绝并回填模型；其它只读参数由 MCP 服务端验证，真实错误会回填模型以便修正。成功执行慢日志
表查询后，Host 判断它是否已形成告警窗口证据：最终查询必须精确使用 Host 给出的两个时间边界，
支持 Unix 秒/毫秒、UTC ISO、`FROM_UNIXTIME` 和 `to_timestamp` 等受控表达形式，并显式包含不超过
20 的 `LIMIT`；对于 `mysql_slow_query_review_history`，还必须包含 `hostname_max` 等值条件，并允许
用 `ts_min < window_end AND ts_max >= window_start` 表达聚合慢查询记录与告警窗口重叠。
无 `WHERE` 的 `LIMIT 1` 样例、仅字段探测、仅端点条件或仅时间条件都作为成功的辅助探针回传模型，
不会被提前当成最终证据。完成判断发生在只读 MCP 调用返回之后；模型仍可在剩余预算内基于真实
结果继续调用或重试。提示词要求模型仅使用本次
慢查询取证需要的只读工具，并优先按 `alert_host/alert_port → t_instance_member.f_instance_id →
sql_instance.host:port → mysql_slow_query_review_history.hostname_max` 的链路查询。表和字段发现是
可选的恢复手段，不再是 Host 侧前置条件。提示词中的目标时间窗由规范化告警的 `occurred_at` 和
部署窗口计算，默认是告警发生前 5 分钟。调用 `sql_query_gymJPA` 会直接向后端提交查询，不存在
预览确认步骤。

Host 会记录已经完成的 `t_instance_member` 和 `sql_instance` 元数据阶段，后续重复查询会在发送到
MCP 前被拒绝且不消耗远端预算。目标端点解析完成并进入最后 4 次远端额度后，剩余调用只允许用于
慢日志字段、`information_schema.statistics` 索引探针和完整的最终窗口查询；资源枚举、目标漂移和
重复实例归属查询都会被拒绝。最终 history 查询若包含 `ORDER BY`，只能按真实 `ts_min` 排序，不能
按 `Query_time`、`Rows_examined` 等诊断值触发大范围 filesort。

最终慢日志查询成功并返回日志内容后，结果直接作为当前告警窗口的实时证据，不再对告警端点和
`hostname_max` 结果端点追加 `t_instance_member.f_instance_id` 查询，也不生成 `MATCHED`、
`MISMATCHED`、`UNVERIFIED` 或 `analysis_usable` 等归属状态。AI 分析和独立验收提示词明确禁止
比较告警标题端点与 `hostname_max` 的 IP/端口字面值，不能因二者不同而弃用证据，也不能在结论中
提出或描述额外的实例归属核验。查询成功但明确返回 0 行或无法解析行数时记录为 `NO_DATA`，保留
查询事实，但不能用于支持具体根因。

查询结果以 `source_system=archery_mcp` 的实时 `EvidenceRecord` 保存并传给 Agent。若 Archery
以“SQL 查询已执行 / 执行的SQL / 结果”文本包裹返回数据，Host 会拆出其中的实际 SQL 和结果
JSON，核对实际 SQL 是否与模型提交内容一致，并记录查询使用的实例 ID、时间字段和返回行数。
若 Archery 的内层包裹 JSON 因字符上限不完整，Host 会逐项恢复截断点之前完整闭合的日志行，
丢弃最后一条不完整行，并同时保留文本中明确报告的总行数；位置数组没有列名时，只有 Archery
回显 SQL 与请求完全一致才会从已核对 SQL 投影恢复列名。进入通用执行器前，Host 再把完整日志行
压缩为包含时间、库/用户、`checksum`、SQL 样本和诊断数值的小型 JSON，并按字符预算只移除完整的
尾部行；因此正常路径不会触发通用执行器盲切。只有摘要中仍完整可解析的日志行才能支持具体根因。
空结果会明确显示为 0 行且不会误报为可能截断。证据会记录由告警上下文与 MCP 资源发现共同
确定的实例 ID 和数据库名；结果可用于当前告警排查，但慢查询记录本身不能单独证明根因。
提示词要求最终查询和 `sql_query` 的 `limit_num` 都不得超过 20；即使 MCP 返回更多已解析行，
Host 也只保留前 20 行。回传给模型的单次结果文本最多保留 24,000 字符。
若 `mysql_slow_query_review_history` 查询被 Archery 超时 KILL，或返回 MySQL 的
`Query execution was interrupted, maximum statement execution time exceeded`，Host 将其作为缺失证据回传模型，
明确禁止原样重试或盲目添加 `FORCE INDEX`。模型可通过只读 `SELECT` 查询
`information_schema.statistics`；`SHOW INDEX` 仍不在 Host 的 `SELECT/WITH` 安全边界内。若真实
联合索引以 `hostname_max, ts_min` 开头，恢复查询优先同时使用 `hostname_max = ...`、
`ts_min >= window_start` 和 `ts_min < window_end` 的半开窗口，并减少投影字段。Host 不会自动改写
模型 SQL。若超时后只剩一次远端额度，该额度直接保留给有界 history 恢复查询，不再允许索引探针。
history 字段已经发现但查询未完成时，诊断返回“等待 history 查询成功”；若轨迹中存在 history
超时，则返回更具体的“等待优化后的 history 查询”，不再误报“等待 history 表字段”。

传输失败、登录确认失败、鉴权失败、超时、MCP 标准错误或不可恢复的 Archery 业务错误形成失败
证据；模型连续选择失败、预算耗尽或未形成最终窗口查询时形成带调用轨迹的 `NO_DATA` 证据。SQL
工具错误的脱敏类型和详情会写入对应 `query_trace`，便于区分字段错误、语法错误和权限错误。首次
协议或传输失败时，统一 Harness 可在策略允许时新建会话并重新登录。所有重连会话共享同一个
运行状态、成功观测、调用轨迹、checkpoint、重试状态和远端调用预算；实际发送到 MCP 的调查调用
总数不会超过 `ARCHERY_MCP_MAX_AGENT_STEPS`。若结束时只有 partial 结果，证据会设置
`allow_followup_dispatch=false`，外层 Agent 不会再创建一个满额预算的 Archery 调查。Host bootstrap
与被 Host 拒绝的调用会单独记账，但不占用远端工具调用预算。传输中断导致调用结果未知时，只有
Host 仍能证明工具只读且 `RetryPolicy` 明确允许时才会重试；否则保留
`UNKNOWN_OUTCOME`/缺失证据并停止自动重放。显式重新分析会创建新 run，并按新 run 重新分配预算。

项目级 MCP 配置只保存环境变量引用，不保存秘密：

```json
{
  "mcpServers": {
    "archery": {
      "url": "${ARCHERY_MCP_URL}",
      "headers": {
        "X-Archery-Token": "${ARCHERY_MCP_TOKEN}"
      }
    }
  }
}
```

在 `.env` 配置该文件路径、完整 MCP Endpoint、Token 和查询窗口：

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
ARCHERY_MCP_URL=https://archery.mcdchina.net/mcp
ARCHERY_MCP_TOKEN=archery_replace-with-your-token
ARCHERY_SLOW_LOG_WINDOW_SECONDS=300
ARCHERY_MCP_MAX_AGENT_STEPS=12
ARCHERY_MCP_TIMEOUT_SECONDS=60
ARCHERY_MCP_TOOL_TIMEOUT_SECONDS=780
```

URL、Token 和窗口都是部署级配置，不能通过管理 API 修改；Agent 最大步骤数以环境变量为部署
默认值，也可通过 Runtime Settings 动态调整。启用 Archery MCP 时必须提供 URL
和 Token，`MCP_SETTINGS_PATH` 指向的文件也必须存在。实例和数据库目标从每条规范化告警中提取，
再由模型调用 MCP 资源发现工具解析，不读取固定目标配置。当前认证方式是
`X-Archery-Token`，不要配置 `Authorization: Bearer`，也不要使用旧版的
`X-Archery-Username` 和 `X-Archery-Password`。Token 只通过每个 MCP HTTP 请求的
`X-Archery-Token` 请求头发送，不写入工具参数、证据或日志；客户端不跟随 HTTP 重定向。生产
环境要求 HTTPS。为兼容现有 Archery MCP 部署，Token 也可从 `ARCHERY_MCP_HTTP_API_KEY` 或
`ARCHERY_TOKEN` 读取；新配置建议使用 `ARCHERY_MCP_TOKEN`。所配置的
`openai_compatible` 模型和网关必须支持 Chat Completions function/tool calling；仅把
`settings.json` 放进仓库不会让远端模型自动获得 MCP，实际加载配置和转发工具调用的是本服务的
MCP Host。

## Prometheus SSE MCP 监控证据

配置 Prometheus MCP 后，`strategy` 节点会把必需的 `query_prometheus_metrics` 加入每条告警的
调查计划，结果按普通实时证据经过 `execute_tools → advise → validate` 处理。服务以 SSE transport
连接 [`config/mcp/settings.json`](config/mcp/settings.json) 的 `prometheus` 条目并动态读取远端
`tools/list` Schema。只有同时出现在本地 `toolPolicies` 和远端工具清单、且未声明为破坏性或非只读
的工具会暴露给 AI Agent；调用前还会再次校验授权。模型负责选择指标和查询语义，Host 负责只读
工具边界、固定参数和时间窗，不依赖提示词自律。

`toolPolicies` 的 `target_discovery` 能力用于发现当前 Prometheus 配置的数据库监控目标，`catalog`
只用于目录、标签和辅助探针；`range_query` 必须声明同一对象中的 `startArgument`、`endArgument` 及
`rfc3339`、`unix_seconds` 或 `unix_millis` 编码。Host 在发网前覆盖这两个参数为
`occurred_at - 5 分钟` 到 `occurred_at`，并将模型参数和实际参数分别留痕。
只有本地授权的 `range_query` 返回真实观测后才有根因支持资格；样本时间戳可因越界否决资格，但
即时查询中偶然落入窗口的单点时间戳不能把未知工具升级为范围证据。策略配置的参数路径必须存在于
实时 Schema；可选 `schemaSha256` 不匹配时整个工具 fail closed。

配置 `target_discovery` 后，每次调查首轮只向模型开放该能力；当前配置将 `get_targets` 用作目标发现
工具。首轮返回后，Agent 可按实际 Schema 继续调用 `get_targets`、`list_metrics`、
`get_metric_metadata` 等本地授权的只读发现工具，综合目标标签、服务发现 URL、抓取路径、job、指标名
和元数据判断数据库归属。例如 `ocp_sd` 名称本身不是结论，但 OCP 服务发现、`/metrics/ob/*` 与
`obproxy` 等多项返回可以共同支持 OceanBase 归属。筛选后的空目标页不能单独证明数据库未受监控。
Agent 判断 `in_scope` 后，在首个 `range_query` 中一并提交范围理由、识别出的数据库类型和有界目标
标识；判断 `out_of_scope` 或 `unknown` 时则通过结构化结束动作提交结论及理由。`out_of_scope` 返回
`SKIPPED`，`unknown` 返回 `NO_DATA`。Host 仍负责只读授权、调用预算、Schema 校验和范围查询时间窗，
不用硬编码字符串规则替代 Agent 的语义判断。范围发现结果只是覆盖上下文，不能支持或反驳本次告警
根因。

SSE 空闲读取期限使用外层 Prometheus 工具期限，避免模型规划期间沿用单次 MCP 读取的 60 秒期限而
提前断流。模型看到的每个工具说明会附加 Host 审核后的 `target_discovery`、`catalog` 或
`range_query` 能力；首轮和每轮结果都包含远端调用的已用、上限与剩余次数。取得合格范围观测后
模型可主动结束调查；尚无可用观测时由 Host 根据监控覆盖范围、目录相关性、空查询次数和目标归属
决定是否继续，模型不能靠提前结束掩盖缺失证据。

当尚无合格范围观测且远端预算只剩两次时，Host 会暂时隐藏 `catalog` 工具，为 `range_query` 保留两次
探针机会；在此之前不限制真实 MCP 所需的指标、标签或标签值发现链路。
同一工具和参数只要已经完成远端执行，即使返回目录或空结果，也不会再次请求远端；同一失败调用
最多允许重试一次。工具错误、空结果和目录结果会分别给出下一步提示，避免模型反复枚举或原样重试。
Host 不会把只共享数据库引擎前缀的目录指标视为告警信号相关指标。例如慢查询告警的目录中只有
`mysql_output_*` 而没有同时表达 `slow/query` 语义的指标时，在已有一次空范围查询且两次目录额度用尽后，
调查以 `NO_DISCRIMINATING_EVIDENCE` 提前结束。三次不同范围查询均无样本，或两次修正后的范围查询仍
明确返回其它目标，也使用相同的提前停止语义，不再消耗完默认八次远端预算。
工具选择失败时，第二次模型请求会带上脱敏的错误类型、错误详情、可用工具及剩余预算；连续两次
仍未形成工具调用时返回带两次安全诊断的 `NO_DATA`，而不是丢失调查轨迹。
统一 Harness 中每条告警的一次分析运行，其远端调用总数由
`PROMETHEUS_MCP_MAX_AGENT_STEPS` 控制（默认 `8`，范围 `1–100`）；首次会话、重连、checkpoint 恢复
和受控重试共享该总预算。模型决策另有有限上限以避免反复提前结束或重复选择。达到远端调用上限时：

- 已取得至少一条包含样本、序列或数值的可解析监控返回：保留为 `SUCCESS` 观测并以
  `call_limit_reached=true` 标示调用已截断；Harness 同时将未正常结束的调查标记为
  `partial=true`，该条 partial 记录只表示采集结果不完整。
- 没有可用监控返回：记录 `NO_DATA`，摘要为“Prometheus MCP 调用次数达到上限，实时证据不足”，
  后续分析以 `INCONCLUSIVE` 结束。

指标目录、状态对象和空序列会保留给后续模型调用及审计，但只作为采集上下文。若已取得
可用观测后模型、MCP 调用或 SSE 会话发生错误，当前运行保留已有结果并记录 `partial`、
`termination_reason` 和错误类型，不再因后续单点故障丢弃整轮审计信息；该 partial 记录只表示
采集结果不完整。普通、可修正的工具业务错误只记录在 `tool_attempts`，不会把已成功结束的调查标为
`partial`。标准 MCP `content[].text` 中完整的
JSON 或 JSON 代码块会先解包再识别观测与样本时间戳，避免已经返回的 Prometheus 数据被文本外壳
误判为空。每条审计响应最多保留 24,000 字符，回传模型的视图最多 8,000 字符。无可用样本时，外层
证据会在进入通用 `ToolExecutor` 前压缩为完整 JSON：保留查询选择、结果状态、时间窗与目标校验、目录
指标和调用计数，删除重复的有效参数及 Prometheus UI 链接，并保证低于 `TOOL_MAX_RESULT_CHARS`。

结果存在不代表根因已被证明；只有完整、非 partial 的成功实时证据与知识内容共同建立具体因果机制
时，最终原因才可标为 `SUPPORT`。否则根因列表为空并返回“现有结果无法得出根因”。MCP 返回内容
一律视为不可信数据，不会执行其中的指令。

项目配置文件只保存环境变量占位符。请在你自己的部署环境中填写端点、认证请求头名和值：

仓库中的 `toolPolicies` 按当前部署使用的工具名配置，但本机无法连接公司内网验证实时 Schema。
配置了 Prometheus URL 但未配置至少一个本地策略时，Host 会在启动构建阶段明确失败，不会猜测远端
工具是否只读。部署前仍应在内网受控环境抓取并审核真实 `tools/list`，确保工具名和 Schema 一致，
核心配置形态如下：

```json
{
  "mcpServers": {
    "prometheus": {
      "url": "${PROMETHEUS_MCP_SSE_URL}",
      "headers": {
        "${PROMETHEUS_MCP_API_KEY_HEADER}": "${PROMETHEUS_MCP_API_KEY}"
      },
      "toolPolicies": {
        "get_targets": {
          "capability": "target_discovery",
          "fixedArguments": {}
        },
        "execute_range_query": {
          "capability": "range_query",
          "startArgument": "start",
          "endArgument": "end",
          "timestampEncoding": "rfc3339",
          "fixedArguments": {}
        }
      }
    }
  }
}
```

嵌套参数路径使用字符串数组，例如 `["range", "start"]`。确认 Schema 稳定后建议填写其规范化 JSON
的 `schemaSha256`，使服务端升级造成的契约漂移在发网前失败。

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
PROMETHEUS_MCP_SSE_URL=https://prometheus-mcp.example.internal/sse
# Optional. Leave PROMETHEUS_MCP_API_KEY empty for an unauthenticated SSE server.
PROMETHEUS_MCP_API_KEY_HEADER=Authorization
PROMETHEUS_MCP_API_KEY=Bearer replace-with-your-token
PROMETHEUS_MCP_MAX_AGENT_STEPS=8
PROMETHEUS_MCP_TIMEOUT_SECONDS=60
PROMETHEUS_MCP_TOOL_TIMEOUT_SECONDS=780
```

端点、请求头名与密钥均为部署级配置，不会由管理 API 返回或修改；最大调用次数可经 Runtime
Settings 调整。生产环境必须使用 HTTPS。密钥只在本服务到 MCP 的请求头中使用，不会写入 MCP
配置文件、工具参数、证据或日志。Prometheus 和 Archery 都只有统一 Harness 执行路径；不存在运行时
legacy/canary 分支。Harness 在所有重连和恢复尝试之间保留成功观测、调用轨迹、checkpoint 与同一个
远端调用预算，因此每条告警的一次分析运行总调用数不会超过各 Provider 的 `MCP_MAX_AGENT_STEPS`。
Harness 返回 partial 结果时会设置
`allow_followup_dispatch=false`，外层 Agent 不会通过新的逻辑派发重置预算。传输中断造成结果未知时，
只有本地策略仍确认工具只读、场景显式授权且 `RetryPolicy` 尚有额度，才会在新会话中重试原查询；
写工具和未授权工具不会使用该例外。

当前开发机未连接公司内网，Archery MCP 和 Prometheus MCP 均未做真实 Host 连通、鉴权、Schema 或
超时行为测试。发布时应先在受控 worker 审核 Prometheus 的真实 `tools/list` 与本地 `toolPolicies`
是否一致，并验证两套 Host 的 timeout、reconnect、no-data、预算消耗和 checkpoint 恢复事件，再通过
部署批次逐步扩大范围。回滚应回退应用版本；已产生的 run、checkpoint 和审计事件继续保留。

## 本地运行

需要 Python 3.12+，以及 Node.js 20.19+ 或 22.12+。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
alembic upgrade head
uvicorn app.api.main:app --reload
```

拉取新代码后，如果 `pyproject.toml` 有依赖变更，需要在启动服务前重新执行
`pip install -e '.[dev]'`，以同步当前虚拟环境和可编辑安装元数据。

前端：

```bash
cd frontend
npm install
npm run dev
```

也可以使用 Docker Compose 启动 API、Kafka Worker 和前端：

```bash
docker network inspect database-alert-knowledge >/dev/null 2>&1 \
  || docker network create database-alert-knowledge
docker compose up -d --build
```

共享网络存在即可先启动 Agent；如果 KnowledgePack 尚未运行，本次外部检索会作为缺失知识依据
降级处理。KnowledgePack 启动后，后续告警无需重启 Agent 即可恢复外部检索。

Compose 中 API 和 Worker 默认设置 `RESET_RUNTIME_SETTINGS_ON_START=true`，并通过容器入口脚本在
应用进程启动前检查 `RUNTIME_SETTINGS_PATH`（当前为 `/app/data/runtime-settings.json`）。如果文件
存在，入口脚本会将其重置为 `{}`，再使用 `exec` 启动 API 或 Worker。因此每次相关容器启动时，
管理页或 `PATCH /api/v1/admin/settings` 保存的运行时覆盖都会被清除，`.env` 会重新成为可在线编辑
配置的启动基线。这也确保执行 `docker compose up -d --build` 重建服务后采用最新 `.env` 配置。

如果部署需要让管理 API 保存的运行时覆盖跨容器启动保留，请在自有 Compose 覆盖文件中将 API
和 Worker 的 `RESET_RUNTIME_SETTINGS_ON_START` 都设为 `false`；普通非容器运行默认不会自动重置。
无论是否启用自动重置，`runtime-settings.json` 中已有的可编辑项在正常加载后仍优先于 `.env`。

Compose 默认只把前端、API 和 Kafka 外部端口绑定到本机。内置 SQLite 与单节点 Kafka 适合本地
联调；生产部署应使用外部 PostgreSQL/MySQL、耐久 Kafka 和带身份认证的网关。

## API

- `POST /api/v1/alerts/canonical/analyze`：接收告警并异步开始分析。
- `GET /api/v1/alerts/{id}`：查看手册匹配、分析进度、可能原因和有序依据；传入
  `run_id` 查询参数可读取指定运行独立保存的 PDF 命中、工具证据、AI 建议与校验记录。
- `GET /api/v1/alerts`：分页查询告警。
- `GET /api/v1/dashboard/summary`：查看分析概览。
- `GET /api/v1/admin/runbooks`、`GET /api/v1/admin/runbooks/{id}`：只读查看本地 PDF 手册及提取正文。
- `GET|PATCH /api/v1/admin/settings`：维护模型与企微机器人运行配置。
- `POST /api/v1/admin/flashduty/poll`：立即轮询、去重、持久化并调度 FlashDuty 告警。
- `GET /health/live`、`GET /health/ready`：存活与就绪检查。

告警示例：

```bash
curl -X POST http://localhost:8000/api/v1/alerts/canonical/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "external_id": "mysql-replica-delay-001",
    "severity": "CRITICAL",
    "title": "MySQL 从库延迟",
    "reason": "replication_delay",
    "environment": "production",
    "service_name": "orders-db",
    "database": {"engine": "mysql", "instance": "orders-replica"},
    "features": {"replication_delay_seconds": 180}
  }'
```

## 结果结构

`recommendation.analysis_bases` 是唯一的判断依据字段：

```json
[
  {
    "source": "RUNBOOK",
    "statement": "手册中的匹配结论",
    "source_ref": {"runbook_id": "mysql-replication-delay", "section": "diagnosis"}
  },
  {
    "source": "EXTERNAL_KNOWLEDGE",
    "statement": "外部知识中的排查依据",
    "source_ref": {
      "knowledge_id": "external-example",
      "title": "replication troubleshooting",
      "source_uri": "file://replication.md"
    }
  },
  {
    "source": "AI",
    "statement": "AI 根据告警字段作出的补充推断",
    "source_ref": null
  }
]
```

`RUNBOOK` 与 `EXTERNAL_KNOWLEDGE` 均须列在 `AI` 之前；两类知识的展示顺序不代表优先级。
所有引用必须对应本次实际召回结果。所选知识来源均未达到阈值时，结果必须明确说明拒绝匹配，
并将置信度限制在 `0.45`。

Agent 必须先完成知识匹配和全部实时证据/MCP 日志采集，采集期间不得创建、评估、存储或引用根因
假设，也不得因为某个原因看似成立而提前结束采集。所有计划任务终态后只做一次根因分析：

- 能由知识与合格实时证据建立因果机制时，返回根因，状态固定为 `SUPPORT`，设置
  `verified=true` 并引用实时证据 ID；
- 不能建立根因时，`root_causes=[]`、`likely_causes=[]`，`summary` 固定为
  `现有结果无法得出根因`，最终状态为 `INCONCLUSIVE`。

新运行不得使用 `SUPPORTED`、`UNKNOWN` 或 `CONTRADICTED`，不得输出暂定原因、被排除原因或
`next_probe`。这些旧枚举仅用于读取历史持久化结果。手册中的原因和历史事故案例只用于解释采集
结果，不能在采集前转成本次告警的候选根因。

校验记录把两个维度分开保存：`passed` 只表示分析契约诚实、可追溯且安全，
`evidence_sufficient` 表示实时证据是否足以完成根因判断。固定的空根因结果可以通过诚实性和安全
契约，但 `evidence_sufficient=false`，最终状态仍为 `INCONCLUSIVE`。只有每个根因均为
`SUPPORT`、引用合格实时证据，且规则校验和 Agent 校验均通过时，才允许进入 `COMPLETED`。

## 离线评测与生产准入

从当前本地 PDF 和每个类型目录的 `index.json` 单独同步自动回归数据：

```bash
.venv/bin/python tools/generate_evaluation_datasets.py --sync
```

生成器实际读取 PDF 文字层；每个有效的“手册 × 告警类型”自动生成正向召回样本，每个告警类型
生成同目录拒识样本，每个已抽取 `cause_id` 生成诊断覆盖样本。`--sync` 只替换
`source.kind=pdf_runbook` 的自动样本，独立的历史事故样本会保留。

运行当前检索与诊断知识覆盖基准：

```bash
.venv/bin/python tools/audit_runbook_visuals.py
.venv/bin/python tools/evaluate_runbooks.py
```

在 CI 或发布流程中强制生产门槛：

```bash
.venv/bin/python tools/evaluate_runbooks.py --enforce-gates
```

数据集位于 `evaluation/datasets/`，门槛位于 `policies/production-gates.json`。准入不再要求两个
数据集各凑 100 条或逐条修改审核状态，而是要求当前所有有效“手册 × 告警类型”、所有已抽取原因
都被最新自动样本覆盖，且召回、拒识、章节和原因指标达到阈值。自动样本只证明摄取与检索回归，
不会被描述成独立的真实效果验证；真实准确率仍通过影子运行和按时间隔离的历史样本统计。

## 验证

```bash
pytest -m "not live"
ruff check app tests migrations
cd frontend && npm run build
```

Agent/MCP harness 的核心 replay 与故障注入测试可单独运行：

```bash
.venv/bin/pytest -q \
  tests/unit/test_mcp_runtime.py \
  tests/unit/test_archery_harness.py \
  tests/unit/test_prometheus_harness.py

.venv/bin/pytest -q \
  tests/unit/test_langgraph_checkpoint.py \
  tests/unit/test_persistence_harness.py \
  tests/unit/test_run_lease_guard.py \
  tests/unit/test_service_run_lease.py
```

这些用例使用 `ReplayMCPConnector`、fake client 和临时 SQLite，不访问 Archery 或 Prometheus 内网
Host。覆盖模型未生成 tool call 后的一次 repair、Host 拒绝、timeout/disconnect/unknown outcome、
重连后保留部分结果与预算、预算耗尽、checkpoint resume、终态 artifact 回填、过期 fencing 拒写，
以及已完成运行恢复时不重放远程调用。它们验证本地状态机与持久化契约，不能替代公司内网中的真实
MCP Schema、鉴权、SSE 行为和超时兼容性验证。

生产部署还必须把 `APP_CODE_VERSION` 设置为不可变镜像摘要或 Git revision，并确保同一批 API 与
worker 使用相同值。该值写入每次运行的 frozen manifest；恢复时不一致会 fail closed，避免新代码
继续执行旧 checkpoint。开发环境可使用默认值或 `.env.example` 中的 `dev`。

普通测试使用临时数据库、Fake AI 和模拟 FlashDuty 响应，不读取工作区 `.env`，用于稳定验证
状态机、鉴权、重试、只读边界和数据转换。真实部署配置由显式启用的 `live` 测试验证；它会产生
真实模型调用，并仅调用 FlashDuty 只读接口。Windows PowerShell：

```powershell
$env:RUN_LIVE_TESTS = "1"
$env:FLASHDUTY_TEST_CHANNEL_IDS = "替换为协作空间数字ID，多个用逗号分隔"
$Py = (Resolve-Path ".\.venv\Scripts\python.exe").Path
& $Py -m pytest -m live -vv
Remove-Item Env:RUN_LIVE_TESTS
Remove-Item Env:FLASHDUTY_TEST_CHANNEL_IDS
```

未设置 `RUN_LIVE_TESTS=1` 时不会访问外部服务。Live 测试读取真实 `.env`，验证模型结构化响应
和请求 ID；FlashDuty 测试使用 `channel_ids` 将 `/alert/list` 限定到指定协作空间，从最近 30 天
告警中自动选择最新一条，再验证告警/事件/动态/关联故障的请求 ID 及完整影子分析链路。端到端
用例会强制使用日志通知器，不会向企业微信发送消息。AI 客户端保持 TLS 证书校验并使用操作系统信任库，
因此 Windows `CurrentUser`/`LocalMachine` 证书库中已受信任的内部 CA 可用于模型网关；HTTPX 仍会读取
`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` 等进程环境变量。

数据库升级使用 Alembic。服务会在启动和就绪检查中核对 Alembic 版本及关键列，不再用
`create_all` 静默修补已有数据库。`0009_validation_evidence_sufficiency` 为校验记录增加独立的
证据充分度字段。`0013_remove_feedback_review_status` 将历史 `REVIEW_REQUIRED` 状态迁移为
`INCONCLUSIVE`，并删除 `alert_feedback` 及其衍生的 `knowledge_cases` 表。升级会永久删除原始反馈
记录和已生成的数据库案例；降级只能重建两张空表，不能恢复已删除的数据。仓储使用 MySQL 时要求
8.0.13 或更高版本，以支持 JSON 表达式默认值；
MySQL 的 DDL 非事务性，生产升级前必须停服并完成数据库备份。

早期版本可能留下“已有业务表但 `alembic_version` 为空”的 SQLite。不要直接或盲目 stamp：
先停止进程并备份数据库，核对其表结构确实对应 `0002`，再执行
`alembic stamp 0002 && alembic upgrade head`；结构不一致时应从备份恢复并单独制定迁移。
