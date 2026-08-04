# Database Alert Agent

本项目只负责一条告警分析链路：

1. 通过 FlashDuty 只读 Open API 定时轮询指定协作空间的告警并规范化；告警等级固定为 `CRITICAL`、`WARNING`、`INFO`。
2. 按运行时选择检索本地 PDF 和/或外部 KnowledgePack，完成精排、阈值过滤和拒识。
3. 由 AI Agent 按诊断图结合告警与实时证据，生成三态原因判断和只读核查建议。
4. 本地 PDF 与外部知识库同级作为知识依据，并统一列在 AI 分析之前。
5. 将每个等级的最终 AI 分析结果发送到企业微信群机器人。


## 架构

项目采用 **LangGraph** 框架构建告警调查工作流。调查图定义了清晰的节点和边，实现可观测、可调试的分析链路：

```text
START → fingerprint → knowledge → runbook → strategy
     → execute_tools → dynamic_investigation ──(循环)──→ execute_tools
                            ↓
                          advise → validate → report → END
```

**节点说明：**

| 节点 | 功能 |
| --- | --- |
| `fingerprint` | 生成告警指纹，用于历史案例匹配 |
| `knowledge` | 匹配已确认的历史案例 |
| `runbook` | 并行检索所选本地 PDF 与外部知识来源，并执行阈值拒识 |
| `strategy` | 选择调查策略，生成工具执行计划 |
| `execute_tools` | 执行调查工具，收集证据 |
| `dynamic_investigation` | React 模式动态工具选择（可选） |
| `advise` | AI 生成结构化建议 |
| `validate` | 规则校验 + 独立结论验收 |
| `report` | 生成最终报告，更新状态 |

**状态管理：**

使用 `AgentState` (Pydantic BaseModel) 在节点间传递状态，支持：
- 告警信息、运行记录、证据列表
- 动态工具选择循环（React 模式）
- 验证、影子分析、AI 降级等配置

调查图使用 `state.error` 传播不可恢复错误。知识匹配、手册检索、策略选择、工具执行、建议生成和
验证等中间节点发现上游错误后会立即短路，不再继续发起后续调查或 AI 调用；`report` 节点统一将
运行和告警分析落为 `FAILED` 并保存失败进度，避免失败链路继续产生无效结果。

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
LangGraph 调查图：fingerprint → knowledge → runbook → strategy
          → execute_tools → dynamic_investigation → advise → validate → report
          ↓
结构化原因与有序依据
          ↓
企业微信群机器人
```

企业微信群机器人 Webhook 是**出站发送地址**，只用于发送分析结果。FlashDuty 告警由本服务通过 Open API 主动轮询，不提供任何 FlashDuty 入站 Webhook。企微发送执行有界重试；服务不会查询是否送达，也不会因发送失败改写已经完成的分析状态。

## 告警手册

`runbooks/pdfs/*.pdf` 是不可变的审计原文，`runbooks/index.json` 是对应的结构化检索和诊断
索引。索引记录知识类型、质量状态、适用范围、告警别名、真实章节/页码、候选原因、支持证据、
反证、只读核查动作、需要审批的变更动作，以及图片中红框/高亮的关键报错、代码和界面字段。
文件名（不含 `.pdf`）仍是稳定手册 ID。

检索先按数据库适用范围过滤，再组合结构化字段、图片关键报错/关键词精确召回、BM25/中文字符
片段召回和质量重排。
每份 PDF 只返回得分最高的章节；低于分数或置信度阈值时明确返回“未命中”。投入运行的
PDF 由部署流程统一审批，Agent 不再按质量标签区分操作指导优先级。

PDF 必须未加密且带可提取文字层；纯扫描件需先 OCR。OCR 文字不能替代图片视觉审核：含图页面
必须在索引中记录带页码的 `visual_evidence`。含图页面未覆盖或视觉证据未批准时，手册不能标为
`approved`。手册目录为只读运行数据，更新方式是替换目录内 PDF 后重启 API 和 Worker，不支持
通过管理 API 在线增删改。

真实手册 PDF 和 `runbooks/index.json` 属于部署数据，不提交到 Git。干净克隆后必须由受控制品库
提供这两类文件，或在容器启动时只读挂载到 `RUNBOOK_PDF_DIR`；缺少目录、PDF 或索引时，就绪检查
不会把实例标记为可用。普通自动化测试使用自包含的小型 PDF fixture，不依赖生产手册。

相关环境变量：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs
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
检索失败时 Agent 按可选知识来源缺失处理。生产索引内容应在入库前完成审批，因此它与本地 PDF
同级作为知识依据；两者都不能代替本次事故的实时证据。

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
# Optional; leave empty to use /alerts/{alert_id}#feedback in this frontend.
WECOM_FEEDBACK_FORM_URL=
```

`AI_MAX_TOKENS` 会显式传给主分析、动态规划和独立结论验收。对于默认启用 Thinking 的推理模型，
建议至少使用 `16384`，并配合足够的 `AI_TIMEOUT_SECONDS`；否则企业网关常见的 `4096` 默认上限
可能全部消耗在 `reasoning_content`，以 `finish_reason=length` 结束且没有最终 `content`。

`SCHEDULER_WORKERS` 控制每个进程同时分析的告警数，范围为 1–16，默认 1。该值属于运行时白名单，
可通过 Agent 设置页或 `PATCH /api/v1/admin/settings` 调整；In-Memory 调度器立即调整并行上限，
Kafka Worker 在下一批消息开始前读取并应用新值。

`AI_API_KEY` 和 `WECOM_WEBHOOK_URL` 都是秘密值。管理 API 只返回“是否已配置”，不会返回原值。
启用企微通知时还必须配置 `WECOM_PAGE_BASE_URL`，它应是企微客户端可访问的前端 HTTPS 地址；
开发环境未启用企微时仅写本地日志，便于测试。

当模型请求超时、网关不支持结构化输出或模型连续两次返回不符合 Schema 的结果时，`AI_FALLBACK_ENABLED=true` 会生成严格受限的保守候选建议，继续走完 `VALIDATING → REPORTING → REVIEW_REQUIRED`，不会在建议阶段直接跳到 `FAILED`。该候选结果会降低置信度、标记必须人工复核，并在校验记录中保留降级原因类型。数据库、持久化等不可恢复的系统错误仍会正确进入 `FAILED`。

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
- `query_changes` 不再作为基础探针；只有显式设置 `FLASHDUTY_CHANGES_ENABLED=true` 后才注册该适配器，且仍需由手册或受限动态规划明确选择；
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

数据源查询需要真实存在的 `ds_name` 和查询表达式。指标查询可在告警中提供合法的 `metric_name`，也可由告警属性或动态调查参数显式提供 `expr`；数据库诊断需要可解析的 `target_locator` 和非空工具目录。缺少必要绑定时不会注册相应能力，也不会猜测查询或降级到写操作。SQL 类查询只接受单条 `SELECT`、`SHOW`、`DESCRIBE` 或 `EXPLAIN`，同时仍应确保 FlashDuty 数据源自身使用数据库只读账户。

FlashDuty 告警详情、事件、动态和故障上下文主要描述“发生了什么”，不能单独证明数据库根因。只有 Monitors 指标、日志、原始只读查询或 monit-agent 数据库诊断等非告警平台的本次 `SUCCESS` 证据，才能把候选原因提升为 `SUPPORTED`。

影子模式仍执行完整检索、调查、建议和校验链路，但最终状态固定为 `REVIEW_REQUIRED`，建议
标记为 `analysis_mode=shadow`。收集到足够专家反馈且生产门槛通过前，建议保持开启。
生产环境只有在部署侧显式设置 `PRODUCTION_GATE_APPROVED=true` 后才允许关闭影子模式；该开关
不属于管理 API 可在线修改的配置。

企微消息使用 `template_card`，主体展示告警标题、级别、主机、数据库、环境、服务和外部 ID，
底部固定三项操作：

- “告警根因分析”：在企微客户端内打开 `/wecom/alerts/{id}/root-cause` 轻量页面，只展示已封装的
  摘要、根因三态、证据引用和置信度；`next_probe` 保留在结构化结果中，不在该页重复展示；
- “告警恢复建议”：在企微客户端内打开 `/wecom/alerts/{id}/recovery-advice` 轻量页面，只展示已
  封装的建议步骤、预期结果、注意事项和风险；
- “人工反馈”：默认打开本系统详情页的反馈表；配置 `WECOM_FEEDBACK_FORM_URL` 后改为外部问卷，
  并自动附加 `alert_id`、`run_id`、`source=wecom` 查询参数。

群机器人 Webhook 只负责出站通知，不具备按钮事件回调和原卡片更新能力。若需要完全原生的卡片
内联交互，需切换到企业自建应用消息并增加回调验签与卡片更新接口。

## Archery 慢查询实时证据

当规范化后的告警标题包含独立的 `slow_query` 标识符时（忽略大小写，但不匹配
`slow_queryable` 等更长标识符），调查策略会新增一个必需的
`query_archery_slow_logs` 取证任务。项目自身作为 MCP Host，加载
[`config/mcp/settings.json`](config/mcp/settings.json) 中的 Archery 连接配置，在同一个
Streamable HTTP 会话中完成初始化和工具发现，再把 MCP 返回的工具以 function tools
交给当前 AI 模型。
模型每轮都能看到 MCP 实际发现到的工具及其输入 Schema，并自主选择一个下一步调用。慢查询
取证通常会使用：

- `ensure_login_gymJPA`；
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
每个 MCP 结果经脱敏和长度限制后回传给下一轮模型调用；SQL 语法等可重试错误也会原样回传，
模型可据此调整只读查询继续执行。模型最多执行 `ARCHERY_MCP_MAX_AGENT_STEPS` 个工具调用步骤，
默认值为 10。MCP 返回的工具中可能包含 `apply_query_permission_gymJPA` 等会产生外部状态变更的
工具，系统提示明确禁止模型调用它们。

Host 不再重复实现 MCP 工具 Schema、工具名、调用参数、SQL 形态、表发现前置条件或
`hostname_max` 来源链路的校验。模型生成的调用参数会原样发送给 MCP，由 MCP 服务端返回真实的
成功或错误结果；Host 再把结果回传模型，使其可以修正只读查询并重试。提示词要求模型仅使用本次
慢查询取证需要的只读工具，并优先按 `alert_host/alert_port → t_instance_member.f_instance_id →
sql_instance.host:port → mysql_slow_query_review_history.hostname_max` 的链路查询。表和字段发现是
可选的恢复手段，不再是 Host 侧前置条件。提示词中的目标时间窗由规范化告警的 `occurred_at` 和
部署窗口计算，默认是告警发生前 5 分钟。调用 `sql_query_gymJPA` 会直接向后端提交查询，不存在
预览确认步骤。

查询结果以 `source_system=archery_mcp` 的实时 `EvidenceRecord` 保存并传给 Agent。若 Archery
以“SQL 查询已执行 / 执行的SQL / 结果”文本包裹返回数据，Host 会拆出其中的实际 SQL 和结果
JSON，核对实际 SQL 是否与模型提交内容一致，并记录查询使用的实例 ID、时间字段和返回行数。
空结果会明确显示为 0 行且不会误报为可能截断。证据会记录由告警上下文与 MCP 资源发现共同
确定的实例 ID 和数据库名；结果可用于当前告警排查，但慢查询记录本身不能单独证明根因。
提示词要求最终查询使用 `LIMIT 100` 以内的范围，回传给模型的单次结果文本最多保留 24,000 字符。
传输失败、登录确认失败、鉴权失败、缺少查询范围、超时、MCP 标准错误或 Archery 业务错误只会
形成失败证据。

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
ARCHERY_MCP_MAX_AGENT_STEPS=10
ARCHERY_MCP_TIMEOUT_SECONDS=60
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
- `GET /api/v1/alerts/{id}`：查看手册匹配、分析进度、可能原因和有序依据。
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

根因使用三态输出：

- `SUPPORTED`：存在非告警平台的实时 `SUCCESS` 证据；
- `CONTRADICTED`：实时证据与候选原因冲突；
- `UNKNOWN`：证据不足，同时给出 `next_probe`。

只有 `SUPPORTED` 可以设置 `verified=true`。手册诊断图中的候选原因不是本次事故已经成立的
事实，历史确认案例也只能作为线索。

校验记录把两个维度分开保存：`passed` 只表示分析契约诚实、可追溯且安全，
`evidence_sufficient` 表示实时证据是否足以完成根因判断。一个正确声明为 `UNKNOWN`、
设置 `verified=false`、提供具体 `next_probe` 且要求人工复核的结论可以通过分析契约，
但 `evidence_sufficient=false`，最终状态仍为 `REVIEW_REQUIRED`。只有规则校验和 Agent
校验的契约均通过且证据充分时，才允许进入 `COMPLETED`。

## 人工反馈与训练闭环

`POST /api/v1/alerts/{id}/feedback` 除最终根因和实际恢复动作外，还支持：

- `runbook_match_verdict`：`CORRECT`、`INCORRECT`、`MISSED`、`NOT_APPLICABLE`；
- 正确手册 ID/章节和漏召回手册列表；
- 支持结论的本次调查证据 ID；
- Agent 的错误声明和被采纳步骤。

确认或纠正且恢复成功的反馈会成为同问题指纹的候选历史案例，但新事件仍必须重新采集实时证据。

内置反馈页会直接调用该接口。使用外部问卷时，应由问卷平台的服务端 Webhook 或受控内网中转服务
读取卡片链接携带的 `alert_id`/`run_id`，把字段映射为上述请求结构后提交：

```http
POST /api/v1/alerts/{alert_id}/feedback
Authorization: Bearer ${ADMIN_API_TOKEN}
Content-Type: application/json
```

不要把 `ADMIN_API_TOKEN` 放入问卷链接或浏览器端脚本。接口会校验反馈所引用的 run、成功证据和
建议步骤，并以 `idempotency_key` 防止问卷平台重试造成重复记录。

## 离线评测与生产准入

运行当前检索与诊断知识覆盖基准：

```bash
.venv/bin/python tools/audit_runbook_visuals.py
.venv/bin/python tools/evaluate_runbooks.py
```

在 CI 或发布流程中强制生产门槛：

```bash
.venv/bin/python tools/evaluate_runbooks.py --enforce-gates
```

数据集位于 `evaluation/datasets/`，门槛位于 `policies/production-gates.json`。当前仓库中的样本和
手册标签均为保守初标，因此准入检查预期失败；必须由数据库专家审核，并用真实、按事故/时间
隔离的历史样本扩充到门槛要求后才能批准上线。

## 验证

```bash
pytest -m "not live"
ruff check app tests migrations
cd frontend && npm run build
```

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
`create_all` 静默修补已有数据库。`0006_training_feedback` 增加手册匹配、证据引用和步骤采纳等
训练反馈字段；`0009_validation_evidence_sufficiency` 为校验记录增加独立的证据充分度字段。

早期版本可能留下“已有业务表但 `alembic_version` 为空”的 SQLite。不要直接或盲目 stamp：
先停止进程并备份数据库，核对其表结构确实对应 `0002`，再执行
`alembic stamp 0002 && alembic upgrade head`；结构不一致时应从备份恢复并单独制定迁移。
