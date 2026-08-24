# Database Alert Agent

Database Alert Agent 轮询 FlashDuty 协作空间中的数据库告警，去重入库，并让单一主 Agent 结合告警详情、
所选知识来源和按需查询的 MCP 证据分析根因。系统只输出两种根因结论：证据建立因果机制时返回
`SUPPORTED`；否则返回 `现有结果无法得出根因`。

项目介绍、全局组件关系、Agent 运行机制、MCP 接入和提示词维护方式见
[项目思维导图与运行机制](docs/project-architecture.md)。

## 分析流程

1. 后台轮询由 `FLASHDUTY_POLLING_ENABLED` 控制，默认关闭。轮询器按
   `FLASHDUTY_POLL_CHANNEL_IDS` 查询协作空间，以 `source + alert_id` 去重，只有新告警自动入队。
2. 分析首先调用 FlashDuty `/alert/info`。详情中的数据库、`alarm_host`、`alarm_port` 和
   `occurred_at` 同时参与知识匹配、MCP 选择和查询；host、port 不从标题推断或补全。
3. 系统检索本次选择的知识来源，保留实际命中的来源、知识 ID、标题和 URI。
4. 主 Agent 进入 ReAct 循环。每轮按 `thought -> action -> observation` 执行一个外层工具，或输出
   `finish`；它根据 MCP 的角色和作用判断是否需要调用，不存在按告警类型硬编码的必调 MCP。
5. MCP 完整原始响应保存为内部审计 artifact。程序侧确定性过滤、聚合、排序并产生可追溯
   observation；原始响应和辅助调用结果不发送给主 Agent，结果处理阶段不调用模型。
6. 主 Agent 是唯一可以结合不同证据判断根因的组件。达到 `finish` 或 `REACT_MAX_ROUNDS` 后正常结束
   调查并生成结论；程序随后只校验输出结构、证据引用与来源资格，不调用第二个模型判断或否决根因。
   整次分析还受 `ANALYSIS_TIMEOUT_SECONDS` 和主动取消控制。

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
每条 observation 必须能追溯到原始 artifact 及真实数据路径。完整原始结果不设通用字符上限，不因
主 Agent 上下文大小而删除；主 Agent 只接收有界投影。

某个 MCP 未被选择、目标未被该 MCP 覆盖、返回 `NO_DATA`、超时或失败，都不会单独把全局
`evidence_sufficient` 置为 false。充分性只取决于主 Agent 最终引用的相关、完整、可用实时证据是否
真正建立因果机制。结果契约固定为：

- 已建立根因：状态 `SUPPORTED`、`verified=true`，并引用合格实时证据 ID；
- 未建立根因：`root_causes=[]`、最终状态 `INCONCLUSIVE`、摘要 `现有结果无法得出根因`。

新分析不输出 `SUPPORT`、`UNKNOWN`、`CONTRADICTED`、暂定原因或被排除原因。所有恢复建议仍以只读
验证和排查为主；需要变更的动作只能列为风险或待审批事项。

结论后的 `validate` 节点是纯程序契约校验：它不读取原始 MCP artifact，不综合证据形成新根因，也不
调用独立模型重新判断 `evidence_sufficient`。历史运行中的 `AGENT` 校验记录仍可读取，但新运行只写入
`RULE` 校验记录。

## 维护入口

重构后的日常维护入口如下：

| 维护内容 | 入口 |
| --- | --- |
| FlashDuty 协作空间 | `.env` 中 `FLASHDUTY_POLL_CHANNEL_IDS`，修改后重启 |
| FlashDuty 轮询开关和间隔 | `.env` / Agent 设置页；模板见 `.env.example` |
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

新增 MCP：

1. 在 `mcpServers` 中与 `archery`、`prometheus` 同级追加 JSON 配置；
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
最终 `mysql_slow_query_review_history` 结果只做 JSON 格式转换后完整透传，不过滤、聚合、排序或
截断。上游 MCP 目前只返回文本，Archery 内部模型必须通过本地结果评估动作，根据原始响应显式报告
`complete`、`content_too_long` 或 `uncertain`；Host 不猜测或伪造上游截断字段。命中恢复状态后，
Host 按稳定 directive ID 将 `workflow.md` 中对应的原文片段追加到下一轮上下文：先查完整 id 清单，
再逐 id 查询，提高单条结果上限后仍不完整时，最后使用带 `sample_full_length` 的 sample 前缀投影。

动态 MCP Schema 负责普通 required、类型和额外参数校验；专用 Host 只保留只读边界、单语句和数据
范围等安全门禁。单 id history 恢复使用 MySQL AST 做语义校验，允许大小写、空白、反引号、别名、
`ORDER BY id ASC|DESC` 和 `LIMIT 1` 等安全等价写法，但仍在 transport 前拒绝 JOIN、子查询、额外
谓词、错误目标表及未授权 id。所有本地拒绝都会把结构化 reason code、详情和下一步动作返回模型。

完整恢复 history 后，Archery adapter 将 sample 与真实 history 行、allowlist 实例和 `db_max` 严格
绑定；任何 sample 都不能直接执行，但与完整 sample 绑定的普通 `EXPLAIN` 可以包裹 SELECT、WITH
以及目标引擎支持的 DML。`EXPLAIN ANALYZE` 和截断 sample 前缀始终禁止。目标及实际执行 SQL 核对
成功的 EXPLAIN、表结构和索引结果分别形成独立 supplemental 证据单元；失败单元只形成证据缺口，
不修改或降级完整 history 单元。只要仍有 history id 或适用的 supplemental 阶段处于 `PENDING`，
内部 `finish` 就会被拒绝；全部工作项进入成功、失败、不适用或不可用等终态后即可结束，不要求全部
成功。新 Archery 父 evidence 只关联调用和原始 artifact，根因必须引用具备资格的具体子单元 ID。

```dotenv
MCP_SETTINGS_PATH=./config/mcp/settings.json
ARCHERY_MCP_URL=https://archery.example.internal/mcp
ARCHERY_MCP_TOKEN=replace-me
ARCHERY_SLOW_LOG_WINDOW_SECONDS=300
ARCHERY_MCP_TIMEOUT_SECONDS=60
ARCHERY_MCP_TOOL_TIMEOUT_SECONDS=780
```

## Prometheus MCP

Prometheus 的作用是查询数据库监控指标，提示词位于 `config/mcp/prompts/prometheus/`：

1. 先发现 MCP 实际配置了哪些数据库、目标、标签和指标；
2. 用 FlashDuty 详情中的数据库、`alarm_host`、`alarm_port` 匹配目标；
3. 告警数据库在覆盖范围内时，查询与告警相关的指标在
   `[occurred_at - 5 分钟, occurred_at]` 的时序；
4. 不在覆盖范围内时返回 `Prometheus MCP 中没有配置告警数据库对应的监控信息`，该结果表示工具
   不适用，不否决其它证据。

目标发现、指标目录和元数据只保存为内部审计 artifact。程序侧对目标与时间窗匹配的时序计算样本数、
最小值、最大值、均值、最新值、变化量、缺口和异常排序，再把可追溯 observation 交给主 Agent。

```dotenv
PROMETHEUS_MCP_SSE_URL=https://prometheus-mcp.example.internal/sse
PROMETHEUS_MCP_API_KEY_HEADER=
PROMETHEUS_MCP_API_KEY=
PROMETHEUS_MCP_TIMEOUT_SECONDS=60
PROMETHEUS_MCP_TOOL_TIMEOUT_SECONDS=780
```

## 知识来源

### 外部 KnowledgePack

KnowledgePack 独立部署，通过共享 Docker 网络向 Agent 提供 `POST /search`。检索失败或空响应只表示
该知识来源缺失，分析继续。

```dotenv
KNOWLEDGE_NETWORK_NAME=database-alert-knowledge
EXTERNAL_KNOWLEDGE_BASE_URL=http://knowledge:8000
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
读取完整游标分页再入库，不设置影子模式。

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

`STREAM_MAIN_AGENT_REASONING` 没有代码默认值，部署时必须显式设置。Agent 设置页中的开关属于运行级
覆盖，只影响之后创建的分析运行；清空运行级覆盖后，API 和 Worker 会立即恢复环境变量中的部署基线，
无需再次重启。

## 本地运行

需要 Python 3.12+，Node.js 20.19+ 或 22.12+。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
alembic upgrade head
uvicorn app.api.main:app --reload
```

前端：

```bash
cd frontend
npm install
npm run dev
```

也可使用 Docker Compose：

```bash
docker network inspect database-alert-knowledge >/dev/null 2>&1 \
  || docker network create database-alert-knowledge
docker compose up -d --build
```

本机通常无法连接公司内网中的 Archery 和 Prometheus MCP。开发机测试出现连接超时可以忽略；真实
Schema、鉴权和返回结果在内网工作机验证。

## API

- `POST /api/v1/alerts/{source}/analyze`：接收非 FlashDuty 告警并异步分析；FlashDuty 仅由轮询器接入。
- `GET /api/v1/alerts`、`GET /api/v1/alerts/{alert_id}`：查询告警与指定运行结果。
- `GET /api/v1/alerts/{alert_id}/runs/{run_id}/trace`：增量读取 thought/action/observation。
- `POST /api/v1/alerts/{alert_id}/runs/{run_id}/cancel`：管理员 Bearer 认证，幂等取消运行，返回 202。
- `POST /api/v1/alerts/{alert_id}/reanalyze`：使用当前配置创建新的分析运行。
- `POST /api/v1/admin/flashduty/poll`：管理员手动执行一轮 FlashDuty 拉取、去重和调度。
- `GET|PATCH /api/v1/admin/settings`：查看或更新允许在线维护的运行配置。
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

离线测试使用 fake client、Replay MCP 和临时数据库，不访问内网 MCP。重点覆盖 ReAct 正常 `finish`、
轮次上限、整次超时、主动取消、checkpoint 恢复、确定性结果投影、artifact 追溯及前端增量轨迹。

生产部署应把 `APP_CODE_VERSION` 设置为不可变镜像摘要或 Git revision，并让同一批 API 与 Worker 使用
一致值。数据库升级使用 Alembic；生产升级前停止服务并备份数据库。
