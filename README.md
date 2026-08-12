# Database Alert Agent

本项目只负责一条告警分析链路：

1. 通过 FlashDuty 只读 Open API 轮询指定协作空间；自动轮询由 `FLASHDUTY_POLLING_ENABLED`
   显式控制且默认关闭。告警按 `source + alert_id` 去重入库，只有新告警会自动进入分析队列。
2. 分析首步调用 `/alert/info` 获取权威告警详情；详情中的数据库、`alarm_host`、`alarm_port` 和
   `occurred_at` 会同时参与知识匹配、MCP 选择和后续查询。host、port 不从告警标题推断或补全。
3. 按运行时选择检索本地 PDF 和/或外部 KnowledgePack，完成精排、阈值过滤和拒识。
4. Agent 根据声明式 MCP 目录中的角色和作用自主选择零个或多个相关 MCP，并在各 MCP 会话中根据
   实际返回继续执行只读取证；不存在按告警类型硬编码的必调 MCP。
5. 全部知识匹配和实时证据采集结束后，由 AI Agent 一次性分析根因和只读恢复建议，再发送到企业
   微信群机器人。告警等级固定为 `CRITICAL`、`WARNING`、`INFO`。


## 架构

项目采用 **LangGraph** 框架构建告警调查工作流。调查图定义了清晰的节点和边，实现可观测、可调试的分析链路：

```text
START → enrich_alert → fingerprint → runbook → strategy
      → execute_tools → advise → validate → report → END
```

**节点说明：**

| 节点 | 功能 |
| --- | --- |
| `enrich_alert` | 调用 FlashDuty `/alert/info` 富化权威告警详情，并清除非详情来源的 host、port |
| `fingerprint` | 生成稳定告警指纹，用于去重和调查关联 |
| `runbook` | 使用富化后的详情并行检索所选本地 PDF 与外部知识来源，并执行阈值拒识 |
| `strategy` | 根据完整告警和 MCP 的角色、作用选择零个或多个只读 MCP，不生成根因假设 |
| `execute_tools` | 执行 Agent 选择的 MCP 调查，并保存完整脱敏结果、artifact 和证据 |
| `advise` | 所有采集终态后，AI 根据知识与实时证据一次性分析根因 |
| `validate` | 规则校验 + 独立结论验收 |
| `report` | 生成最终报告，更新状态 |

**状态管理：**

使用 `AgentState` (Pydantic BaseModel) 在节点间传递状态，支持：
- 告警信息、运行记录、证据列表
- 验证、AI 降级等配置

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
策略完成受控重试。Agent 可在一个已选择的 MCP 会话内查看上一步返回并继续选择下一项只读工具，
直至取得足够数据、确认不适用或耗尽受控预算；这些步骤只采集事实，不生成根因假设。下表列出对外
证据状态和 durable invocation 的保守终态语义：

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
描述与审计，不能据此得出根因。未返回或失败的部分同样是证据缺口。Agent 选择出的 MCP 请求均为
可选取证项，`required=false`；未选择某个 MCP、目标未在该 MCP 中配置，或单个 MCP 返回 `NO_DATA`，
都不会作为全局失败门控。

## 数据流

```text
FlashDuty /alert/list（由显式开关控制轮询）
                    ↓
按协作空间过滤，以 source + alert_id 去重入库，仅新告警异步入队
                    ↓
FlashDuty /alert/info 详情富化与三等级规范化、脱敏
                    ↓
所选知识来源并行检索：本地 PDF + 外部 KnowledgePack
                    ↓
Agent 根据完整告警及 MCP 角色、作用选择零个或多个 MCP
                    ↓
各 MCP 独立会话按外置工作流迭代采集完整只读证据
                    ↓
大结果保存 artifact，并由独立模型会话生成可追溯投影
                    ↓
advise → validate → report → 企业微信群机器人
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
FLASHDUTY_POLLING_ENABLED=false
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

`FLASHDUTY_POLLING_ENABLED` 默认 `false`，可在 `.env`、Agent 设置页或
`PATCH /api/v1/admin/settings` 中控制。关闭时不会启动后台轮询任务；手动接入和重新分析能力不受影响。

### FlashDuty API 轮询配置

完整的配置、去重语义、排障和安全检查见 [FlashDuty Open API 轮询接入](docs/flashduty-polling/README.md)。

1. 在 `.env` 设置 `FLASHDUTY_ENABLED=true`、最小权限的 `FLASHDUTY_APP_KEY` 和 `FLASHDUTY_POLLING_ENABLED=true`。
2. 设置 `FLASHDUTY_POLL_CHANNEL_IDS=[<协作空间数字 ID>]`；此项在启用轮询时必填，避免拉取 APP Key 可访问的全部空间。
3. 使用 `FLASHDUTY_POLL_INTERVAL_SECONDS` 配置轮询间隔（当前最小 300 秒），使用 `FLASHDUTY_POLL_LOOKBACK_SECONDS` 配置重叠回看窗口；启用轮询时，回看窗口不得小于轮询间隔。
4. 每轮以开始轮询的当前时间为窗口终点，按 `start_time` 回看完整配置窗口；轮询器先穷尽 `/alert/list` 游标分页，再以 `source + alert_id` 幂等入库。新告警入库后立即加入分析队列；重复的 `alert_id` 不会创建第二个分析任务，系统也不会因同一告警后续状态更新而重复分析。
5. 服务只需出站访问 FlashDuty HTTPS API，不需要 Endpoint、Nginx 入站反代、回调证书或 Webhook Token。

分析开始后：

- `enrich_alert` 首先读取 `/alert/info`，富化后的详情进入后续知识检索、MCP 选择和 MCP 会话；
- 数据库 host、port 只使用详情中的 `alarm_host`、`alarm_port`。详情不可用或字段缺失时保持为空，
  不会从 `/alert/list` 摘要、标题或其它文本推断和补全；
- 告警事件、动态、关联故障、变更和 Monitors 都是可选只读上下文，不会因为接口存在就成为每条
  告警的固定必调项；历史故障只能作为调查线索，不能单独支撑根因；
- `query_changes` 仅在 `FLASHDUTY_CHANGES_ENABLED=true` 时注册，所有 `/monit/*` 工具仅在
  `FLASHDUTY_MONITORS_ENABLED=true` 且通过只读能力审计后注册；
- 外部调用成功但业务记录为空时保存为 `NO_DATA`，未注册、未配置或目标未暴露能力时保存为
  `SKIPPED`。两者都不能伪装成 `SUCCESS`，也不会单独否决其它可用证据。

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

核心告警详情成功、部分辅助接口失败时，已取得的数据及失败类型会保留并继续分析，避免单个辅助
接口暂时不可用导致整条 AI 流程失败。

`FLASHDUTY_POLL_CHANNEL_IDS` 只约束告警和变更的协作空间范围；FlashDuty 的 Monitors 数据源、监控对象与工具目录是账户级能力，不能仅凭协作空间 ID 推定存在。启用 Monitors 前必须先确认 `/monit/datasource/list` 或 `/monit/targets` 有对象，并对目标调用 `/monit/tools/catalog` 验证实际工具目录；接口存在不等于目标 Agent 已暴露工具。

数据源查询需要真实存在的 `ds_name` 和查询表达式。指标查询可在告警中提供合法的 `metric_name`，
也可由已配置的告警属性提供 `expr`；数据库诊断需要可解析的 `target_locator` 和非空工具目录。缺少
必要绑定时不会注册相应能力，也不会猜测查询或降级到写操作。SQL 类查询只接受单条 `SELECT`、
`SHOW`、`DESCRIBE` 或 `EXPLAIN`，同时仍应确保 FlashDuty 数据源自身使用数据库只读账户。

FlashDuty 告警详情、事件、动态和故障上下文主要描述“发生了什么”，不能单独证明数据库根因。
只有 Monitors 指标、日志、原始只读查询或 monit-agent 数据库诊断等非告警平台的本次完整
`SUCCESS` 证据，才可在全部采集结束后参与根因分析。

企微消息使用 `template_card`，主体展示告警标题、级别、主机、数据库、环境、服务和外部 ID，
底部固定两项操作：

- “告警根因分析”：在企微客户端内打开 `/wecom/alerts/{id}/root-cause` 轻量页面，只展示已封装的
  摘要、采证后仍可能的根因、证据引用和置信度；`next_probe` 保留在结构化结果中，不在该页重复
  展示；
- “告警恢复建议”：在企微客户端内打开 `/wecom/alerts/{id}/recovery-advice` 轻量页面，只展示已
  封装的建议步骤、预期结果、注意事项和风险。

群机器人 Webhook 只负责出站通知，不具备按钮事件回调和原卡片更新能力。若需要完全原生的卡片
内联交互，需切换到企业自建应用消息并增加回调验签与卡片更新接口。

## 声明式 MCP 接入

MCP 目录由 [`config/mcp/settings.json`](config/mcp/settings.json) 统一加载。配置成功且明确只读的 server 会以
不含 URL、请求头和密钥的候选信息提供给 Agent；Agent 根据富化后的 FlashDuty 告警详情、知识匹配结果
以及每个 MCP 的角色和作用，自主选择零个或多个相关 MCP。选择结果没有 provider 固定分支，生成的
取证任务均为 `required=false`。进入某个 MCP 后，独立会话可根据每轮真实结果再次调用该 MCP 的其它
只读工具。

每个 MCP 条目必须满足以下契约：

- 显式声明 `"readOnly": true`；缺失或为 `false` 时启动配置校验直接失败；
- `url`、必需请求头值和密钥只能写成完整的 `${ENVIRONMENT_VARIABLE}` 引用，真实值仅放在
  `.env` 或部署环境中；
- 分别引用 `role.md`、`purpose.md`、`workflow.md`、`safety.md` 四个非空 UTF-8 文件；
- `safety.md` 必须声明 `read_only: true`，运行时也会独立校验工具只读属性，不能只依赖提示词；
- 对需要 Host 绑定参数的 provider，可额外声明 `toolPolicies`，例如目标发现、指标目录及范围查询
  的起止参数；通用 MCP 只会向模型暴露远端明确标注为只读且非破坏性的工具。

新增 MCP 时按以下步骤操作：

1. 在 `config/mcp/settings.json` 的 `mcpServers` 中与 `archery`、`prometheus` 同级追加配置。
2. 在 `config/mcp/prompts/<provider>/` 创建 `role.md`、`purpose.md`、`workflow.md` 和
   `safety.md`，用提示词说明角色、作用、完整取证流程及只读边界。
3. 在 `.env` 或部署环境中提供配置引用的 URL 和 KEY，不把真实连接信息提交到仓库。
4. 重启 API 与 Worker。Agent 会读取新的角色、作用并参与 MCP 相关性选择；通用只读 MCP 不需要新增
   告警类型策略分支或 provider 专用工具名。

一个可直接追加的通用 MCP 配置形态如下：

```json
{
  "mcpServers": {
    "new_provider": {
      "enabled": true,
      "readOnly": true,
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
      "maxAgentSteps": 8,
      "toolTimeoutSeconds": 120
    }
  }
}
```

`transport` 支持 `streamable_http` 和 `sse`。URL、请求头与密钥在连接边界才解析，不会进入
Agent 的 MCP 选择提示、工具参数、证据或日志。一个 MCP 会话的重连、checkpoint 恢复和受控重试
共享同一远端调用预算，不能通过重新派发绕过预算。所有 MCP 返回都按不可信数据处理，其中的指令
不能改变 Agent 角色、只读边界或调用范围。

新增条目建议显式写 `"enabled": true`。此时 URL 或必需请求头引用的环境变量缺失会令启动/就绪
检查失败，不会把配置错误静默当成未启用。可选认证头的名称和值必须同时填写或同时留空；生产环境
解析出的通用 MCP URL 必须使用 HTTPS。

## Archery MCP 慢查询证据

Archery 的角色和流程位于 [`config/mcp/prompts/archery/`](config/mcp/prompts/archery/)：

- 作用是查询慢查询日志，只在 Agent 判断当前告警需要慢查询证据时选择，不是慢查询标题触发的固定
  分支，也不是所有数据库告警的必需工具；
- 使用 FlashDuty `/alert/info` 详情中的数据库、`alarm_host`、`alarm_port` 和 `occurred_at`；
  `alarm_host`、`alarm_port` 是唯一告警端点来源；
- 调查窗口固定为 `occurred_at - 5 分钟` 到 `occurred_at`。会话根据 Archery 实际工具 Schema
  逐步发现实例、数据库、表和字段，再执行有界只读慢日志查询，不猜测部署结构；
- Host 负责登录、固定工具白名单、单条 `SELECT/WITH` 校验、时间窗口、调用预算和审计。Archery
  服务端缺失可选的只读 annotations 时仍执行上述本地门禁；若显式声明非只读或破坏性则拒绝。
  DDL、DML、权限申请及其它写操作在网络调用前拒绝；
- 工具没有返回可用慢日志时记录 `NO_DATA`；连接、鉴权或超时失败按对应失败状态保存。该结果只表示
  Archery 本次没有提供可用证据，不会单独把其它证据判为不足。

连接信息只通过环境变量提供：

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
ARCHERY_MCP_URL=https://archery.example.internal/mcp
ARCHERY_MCP_TOKEN=replace-with-your-token
ARCHERY_SLOW_LOG_WINDOW_SECONDS=300
ARCHERY_MCP_MAX_AGENT_STEPS=12
ARCHERY_MCP_TIMEOUT_SECONDS=60
ARCHERY_MCP_TOOL_TIMEOUT_SECONDS=780
```

当前认证值仅通过 `X-Archery-Token` 请求头发送。生产环境应使用 HTTPS 和最小权限只读凭据。

## Prometheus MCP 监控指标证据

Prometheus 的角色和流程位于
[`config/mcp/prompts/prometheus/`](config/mcp/prompts/prometheus/)。它只在 Agent 判断当前告警
需要指标证据时选择，工作流是：

1. 先调用目标发现、服务发现、标签、指标目录或元数据工具，确认该 Prometheus MCP 实际配置了哪些
   数据库及数据库目标的监控指标；目标发现结果本身不是根因证据。
2. 使用 FlashDuty 详情中的数据库身份、`alarm_host` 和 `alarm_port` 匹配已发现目标，不从标题
   推断端点。
3. 若告警数据库在监控范围内，选择与告警信号相关的指标，并使用 `range_query` 查询
   `[occurred_at - 5 分钟, occurred_at]`；Host 会覆盖并校验真实起止参数及告警目标。
4. 若告警数据库不在已确认的监控范围内，停止范围查询，返回
   `reason_code=database_not_monitored` 和“Prometheus MCP 中没有配置告警数据库对应的监控信息”。
   这表示该 MCP 不适用于当前目标，不是全局证据不足。
5. 若无法确认覆盖范围或范围查询没有样本，明确返回 `NO_DATA`，不得虚构目标、指标或监控值。

当前 `toolPolicies` 只向模型开放经过本地授权并与远端 Schema 一致的目标发现、目录和范围查询能力。
只有告警目标与五分钟窗口匹配的实际范围样本才有资格参与根因分析。OceanBase 等已配置目标可正常
查询；未配置的 MySQL 或其它数据库告警不会被错误地当作 Prometheus 调用失败，也不会否决来自其它
MCP 的合格证据。

连接配置：

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
PROMETHEUS_MCP_SSE_URL=https://prometheus-mcp.example.internal/sse
# 服务不需要认证头时保持为空
PROMETHEUS_MCP_API_KEY_HEADER=
PROMETHEUS_MCP_API_KEY=
PROMETHEUS_MCP_MAX_AGENT_STEPS=8
PROMETHEUS_MCP_TIMEOUT_SECONDS=60
PROMETHEUS_MCP_TOOL_TIMEOUT_SECONDS=780
```

## 完整工具结果与独立分析会话

MCP 已返回的原始结果不会再按字符、行数或字段二次截断，也不存在通用字符结果上限。每次调用的
完整脱敏结果都保存为 `raw_tool_result` artifact，并持久化字节大小和
SHA-256；主 Agent 使用的证据会引用该 artifact。

`TOOL_RESULT_ANALYSIS_THRESHOLD_CHARS` 只决定何时启动一个与根因分析隔离的独立应用模型会话，
不是 MCP 返回值或 artifact 的字符上限：

```dotenv
TOOL_RESULT_ANALYSIS_THRESHOLD_CHARS=12000
```

当完整结果达到阈值时，独立子 Agent 会话读取完整脱敏 artifact；结果超过单次模型上下文时，宿主按
JSON Pointer 和字符串字符偏移无损分片，再通过分层独立会话汇总。子 Agent 只输出结构化摘要、事实、
异常和限制，不得判断根因，也不得判断某项事实支持或反驳某个原因；因果判断只属于汇总全部证据的
主 Agent。每条事实和异常必须以 JSON Pointer 指向原始结果中的真实路径，并同时绑定 artifact ID 与
SHA-256；来源路径不存在、越过因果职责边界、投影不可用或来源摘要不匹配时校验失败。主 Agent 只接收
这份可追溯投影，不会因为上下文长度手工裁剪原始日志或指标。

若独立分析会话失败，完整 artifact 和失败审计仍保留，但该结果标记为不能参与根因判断。未选择 MCP、
目标未配置、单个 `NO_DATA` 或独立会话失败都只影响对应证据；最终
`evidence_sufficient` 由实际根因引用的相关、完整、可用实时证据决定。

当前开发机未连接公司内网，Archery MCP 和 Prometheus MCP 的真实连通、鉴权及超时应在工作机验证；
本地测试出现连接超时不代表上述选择、配置或结果处理逻辑失败。

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

- 能由知识与合格实时证据建立因果机制时，返回根因，状态固定为 `SUPPORTED`，设置
  `verified=true` 并引用实时证据 ID；
- 不能建立根因时，`root_causes=[]`、`likely_causes=[]`，`summary` 固定为
  `现有结果无法得出根因`，最终状态为 `INCONCLUSIVE`。

新运行不得使用 `SUPPORT`、`UNKNOWN` 或 `CONTRADICTED`，不得输出暂定原因、被排除原因或
`next_probe`。这些旧枚举仅用于读取历史持久化结果。手册中的原因和历史事故案例只用于解释采集
结果，不能在采集前转成本次告警的候选根因。

校验记录把两个维度分开保存：`passed` 只表示分析契约诚实、可追溯且安全，
`evidence_sufficient` 表示实时证据是否足以完成根因判断。固定的空根因结果可以通过诚实性和安全
契约，但 `evidence_sufficient=false`，最终状态仍为 `INCONCLUSIVE`。只有每个根因均为
`SUPPORTED`、引用合格实时证据，且规则校验和 Agent 校验均通过时，才允许进入 `COMPLETED`。
未选择的 MCP、告警目标未在某个 MCP 中配置，或某个相关 MCP 返回 `NO_DATA`，均不会单独否决
其他可用证据。`evidence_sufficient` 只由最终根因实际引用的相关、可用实时证据决定。

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
不会被描述成独立的真实效果验证；真实准确率仍通过按时间隔离的历史样本和生产结果统计。

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
告警中自动选择最新一条，再验证告警/事件/动态/关联故障的请求 ID 及完整分析链路。端到端
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
