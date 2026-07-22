# Database Alert Agent

本项目只负责一条告警分析链路：

1. 通过 FlashDuty 告警 Webhook 实时接收并规范化数据库告警，并用只读 `/alert/list` 轮询补偿漏送；告警等级固定为 `CRITICAL`、`WARNING`、`INFO`。
2. 读取本地 PDF 文字层、图片视觉证据及结构化索引，完成章节级混合检索、精排和拒识。
3. 由 AI Agent 按诊断图结合告警与实时证据，生成三态原因判断和只读核查建议。
4. 判断依据严格按“命中手册在前、AI 分析在后”输出。
5. 将每个等级的最终 AI 分析结果发送到企业微信群机器人。

值班人员查询、企微卡片确认、电话、群组分派、通知升级、等待窗口、送达确认和通知重试均不属于本项目。

## 数据流

```text
FlashDuty 告警 Webhook（实时）──────┐
                                  ├→ 去重、规范化与异步入队
FlashDuty /alert/list（5 分钟补偿）─┘
                                  ↓
三等级规范化与脱敏
          ↓
结构化字段 + 图片关键报错/关键词 + BM25/中文片段的章节级手册匹配（首要依据）
          ↓
AI 分析（次要依据）+ 规则校验
          ↓
结构化原因与有序依据
          ↓
企业微信群机器人
```

企业微信群机器人 Webhook 是**出站发送地址**，不是本服务的告警接收地址。企微发送只尝试一次；服务不会查询是否送达，也不会因发送失败改写已经完成的分析状态。实时入站应使用 FlashDuty 官方的[告警 Webhook](https://docs.flashduty.com/zh/on-call/integration/webhooks/alert-webhook)，而不是 `qyapi.weixin.qq.com/cgi-bin/webhook/send`。

## 告警手册

`runbooks/pdfs/*.pdf` 是不可变的审计原文，`runbooks/index.json` 是对应的结构化检索和诊断
索引。索引记录知识类型、质量状态、适用范围、告警别名、真实章节/页码、候选原因、支持证据、
反证、只读核查动作、需要审批的变更动作，以及图片中红框/高亮的关键报错、代码和界面字段。
文件名（不含 `.pdf`）仍是稳定手册 ID。

检索先按数据库适用范围过滤，再组合结构化字段、图片关键报错/关键词精确召回、BM25/中文字符
片段召回和质量重排。
每份 PDF 只返回得分最高的章节；低于分数或置信度阈值时明确返回“未命中”。`incomplete` 和
`deprecated` 资料不会参与召回，`draft`/`review_required` 命中后强制进入人工复核。

PDF 必须未加密且带可提取文字层；纯扫描件需先 OCR。OCR 文字不能替代图片视觉审核：含图页面
必须在索引中记录带页码的 `visual_evidence`。含图页面未覆盖或视觉证据未批准时，手册不能标为
`approved`。手册目录为只读运行数据，更新方式是替换目录内 PDF 后重启 API 和 Worker，不支持
通过管理 API 在线增删改。

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

## AI 与企微配置

复制环境变量模板并填写模型与企微机器人地址：

```bash
cp .env.example .env
```

关键配置：

```dotenv
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=replace-me
AI_MODEL=replace-me
AI_TIMEOUT_SECONDS=60
AI_FALLBACK_ENABLED=true
SHADOW_ENABLED=true
PRODUCTION_GATE_APPROVED=false

WECOM_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=replace-me
```

`AI_API_KEY` 和 `WECOM_WEBHOOK_URL` 都是秘密值。管理 API 只返回“是否已配置”，不会返回原值。生产环境必须配置企微机器人地址；开发环境未配置时仅写本地日志，便于测试。

当模型请求超时、网关不支持结构化输出或模型连续两次返回不符合 Schema 的结果时，`AI_FALLBACK_ENABLED=true` 会生成严格受限的保守候选建议，继续走完 `VALIDATING → REPORTING → REVIEW_REQUIRED`，不会在建议阶段直接跳到 `FAILED`。该候选结果会降低置信度、标记必须人工复核，并在校验记录中保留降级原因类型。数据库、持久化等不可恢复的系统错误仍会正确进入 `FAILED`。

## FlashDuty 只读接入

项目接入 [FlashDuty Open API](https://docs.flashduty.com/zh/openapi) 和[告警 Webhook](https://docs.flashduty.com/zh/on-call/integration/webhooks/alert-webhook)。客户端采用显式只读白名单；虽然 FlashDuty 的查询与诊断接口多数使用 `POST`，项目不会调用创建、更新、删除、认领、恢复等写接口。

```dotenv
FLASHDUTY_ENABLED=true
FLASHDUTY_BASE_URL=https://api.flashcat.cloud
FLASHDUTY_APP_KEY=replace-me
FLASHDUTY_TIMEOUT_SECONDS=40
FLASHDUTY_MAX_RETRIES=2
FLASHDUTY_CONTEXT_ITEM_LIMIT=20
FLASHDUTY_WEBHOOK_ENABLED=true
FLASHDUTY_WEBHOOK_TOKEN=replace-with-a-long-random-value
FLASHDUTY_POLLING_ENABLED=true
FLASHDUTY_POLL_INTERVAL_SECONDS=300
FLASHDUTY_POLL_LOOKBACK_SECONDS=900
FLASHDUTY_POLL_CHANNEL_IDS=[123456789]
FLASHDUTY_POLL_INTEGRATION_IDS=[]
FLASHDUTY_METRICS_DS_NAME=prod-prometheus
FLASHDUTY_LOGS_DS_NAME=prod-loki
FLASHDUTY_LOGS_DS_TYPE=loki
```

`FLASHDUTY_APP_KEY` 与 `FLASHDUTY_WEBHOOK_TOKEN` 是部署级秘密值，不可通过管理 API 修改或读取。Base URL 固定为官方 HTTPS Endpoint，客户端禁止跟随重定向，错误和证据中不会保留 APP Key。建议在 FlashDuty 中为此项目创建最小权限的独立 APP Key。

### FlashDuty 告警 Webhook 配置

完整的接收协议、Nginx 公网 HTTPS 反代、请求/响应示例、内部处理阶段、轮询补偿和排障步骤见 [FlashDuty 告警 Webhook 接收与后续分析](docs/flashduty-webhook/README.md)。

1. 在 FlashDuty 进入“集成中心 → Webhook → 告警 Webhook”，新增集成。
2. Endpoint 填写公网可达的 `https://<本服务域名>/api/v1/webhooks/flashduty/alerts`。
3. 自定义 Header 添加 `X-FlashDuty-Token: <FLASHDUTY_WEBHOOK_TOKEN>`。
4. 选择需要接收的协作空间，并订阅 `a_new`、`a_update`、`a_merge`；`a_close` 会快速确认但不会重复发起根因分析。
5. 保持 TLS 校验开启。接口只做鉴权、规范化、幂等落库和异步入队，以满足 FlashDuty 要求的 2 秒内 HTTP 200 响应。

FlashDuty 可能重试或乱序推送。项目以 `source + alert_id` 保证分析任务幂等；首次接收的 `event_id/event_type` 会随脱敏后的原始事件保存，后续重复投递不会创建第二个分析任务。轮询器按 `updated_at` 升序调用 `/alert/list`，每轮窗口与上一轮重叠；只有整轮成功后才推进内存水位。`FLASHDUTY_POLL_INTERVAL_SECONDS` 最小为 300 秒，默认每 5 分钟一轮；`FLASHDUTY_POLL_LOOKBACK_SECONDS=900` 用于覆盖延迟、短时中断和进程重启后的近期告警。若 `/alert/info` 暂时失败，轮询器会使用官方定义为完整对象的 `AlertItem` 继续补偿入站。

若已知的地址是 `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...`，请只把它配置为 `WECOM_WEBHOOK_URL`。它负责把分析结果发进企业微信群，不能填到 FlashDuty 的 Endpoint，也不能被本服务用来读取群消息。

启用后：

- `alert_context` 读取告警详情、原始事件、告警动态，以及关联故障的详情、时间线和告警；
- `query_changes` 与 `query_similar_incidents` 分别读取时间窗内变更和历史相似故障，这两类历史/平台上下文不会单独支撑“已验证根因”；
- `query_metrics`、`query_logs` 使用 Monitors 诊断接口，`query_trace`、`query_endpoint_errors` 使用原始行查询接口；
- `query_database_diagnostics` 先读取目标工具清单，再调用其中匹配的只读 monit-agent 工具，单次最多 8 个。

项目使用的上游接口均已按官方 OpenAPI 重新核对：

| 用途 | FlashDuty 上游只读接口 |
| --- | --- |
| 漏送补偿 | `/alert/list`（必填时间窗，`by_updated_at=true`，游标分页） |
| 告警详情与现场事件 | `/alert/info`、`/alert/event/list`、`/alert/feed` |
| 关联故障上下文 | `/incident/info`、`/incident/alert/list`、`/incident/feed` |
| 历史相似故障 | `/incident/past/list` |
| 同时间窗变更 | `/change/list` |
| 指标/日志诊断 | `/monit/query/diagnose` |
| 原始只读查询 | `/monit/query/rows` |
| 数据库监控对象 | `/monit/targets`、`/monit/tools/catalog`、`/monit/tools/invoke`（额外限制只读工具名） |

核心告警详情成功、部分事件流或故障时间线失败时，`alert_context` 会保存已取得的数据及失败类型并继续分析，避免单个辅助接口暂时不可用导致整条 AI 流程失败。

数据源查询需要 `ds_name` 和查询表达式。指标查询可在告警中提供合法的 `metric_name`，也可由手册探针/动态调查参数显式提供 `expr`；缺少必要绑定时工具会失败并让结论进入人工复核，不会猜测查询或降级到写操作。SQL 类查询只接受单条 `SELECT`、`SHOW`、`DESCRIBE` 或 `EXPLAIN`，同时仍应确保 FlashDuty 数据源自身使用数据库只读账户。

影子模式仍执行完整检索、调查、建议和校验链路，但最终状态固定为 `REVIEW_REQUIRED`，建议
标记为 `analysis_mode=shadow`。收集到足够专家反馈且生产门槛通过前，建议保持开启。
生产环境只有在部署侧显式设置 `PRODUCTION_GATE_APPROVED=true` 后才允许关闭影子模式；该开关
不属于管理 API 可在线修改的配置。

企微消息包含：

- 告警基本信息与三等级状态；
- AI 分析摘要和可能原因；
- 有序判断依据，每条明确标记为“手册”或“AI”；
- 命中的手册 ID/章节；
- 前三条只读核查建议。

## 本地运行

需要 Python 3.12+ 和 Node.js。

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

也可以使用 Docker Compose 启动 API、Kafka Worker 和前端：

```bash
docker compose up --build
```

## API

- `POST /api/v1/alerts/canonical/analyze`：接收告警并异步开始分析。
- `POST /api/v1/alerts/flashduty/analyze`：接收 FlashDuty `/alert/info` 的 `data` 对象或完整成功响应并异步开始分析。
- `POST /api/v1/webhooks/flashduty/alerts`：接收 FlashDuty 官方告警 Webhook；需 `X-FlashDuty-Token`，成功时在 2 秒内返回 HTTP 200。
- `GET /api/v1/alerts/{id}`：查看手册匹配、分析进度、可能原因和有序依据。
- `GET /api/v1/alerts`：分页查询告警。
- `GET /api/v1/dashboard/summary`：查看分析概览。
- `GET /api/v1/admin/runbooks`、`GET /api/v1/admin/runbooks/{id}`：只读查看本地 PDF 手册及提取正文。
- `GET|PATCH /api/v1/admin/settings`：维护模型与企微机器人运行配置。
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
    "source": "AI",
    "statement": "AI 根据告警字段作出的补充推断",
    "source_ref": null
  }
]
```

当命中手册时，所有 `RUNBOOK` 项必须先于 `AI` 项；手册引用必须对应本次实际召回的 PDF。没有命中手册时，只允许输出明确标注的 AI 依据，并降低置信度。

根因使用三态输出：

- `SUPPORTED`：存在非告警平台的实时 `SUCCESS` 证据；
- `CONTRADICTED`：实时证据与候选原因冲突；
- `UNKNOWN`：证据不足，同时给出 `next_probe`。

只有 `SUPPORTED` 可以设置 `verified=true`。手册诊断图中的候选原因不是本次事故已经成立的
事实，历史确认案例也只能作为线索。

## 人工反馈与训练闭环

`POST /api/v1/alerts/{id}/feedback` 除最终根因和实际恢复动作外，还支持：

- `runbook_match_verdict`：`CORRECT`、`INCORRECT`、`MISSED`、`NOT_APPLICABLE`；
- 正确手册 ID/章节和漏召回手册列表；
- 支持结论的本次调查证据 ID；
- Agent 的错误声明和被采纳步骤。

确认或纠正且恢复成功的反馈会成为同问题指纹的候选历史案例，但新事件仍必须重新采集实时证据。

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

数据库升级使用 Alembic。`0006_training_feedback` 增加手册匹配、证据引用和步骤采纳等训练反馈字段。
