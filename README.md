# Database Alert AI Agent

一个可插拔、可审计的数据库告警调查框架。它通过 HTTP 或 Kafka 接收告警，异步执行“问题指纹、历史案例、处理手册、只读调查工具、AI 建议、双层验收”流程；CRITICAL 告警会先通知管理人员，调查完成后再补发建议。

该项目**不会执行 SQL、重启实例、终止会话或修改数据库配置**。

## 架构

```text
HTTP / Kafka 接入
     │
标准化、环境映射、脱敏、持久化、CRITICAL 即时通知
     │
返回 202 ──→ In-memory / Kafka 调查调度器
                         │
             问题指纹与人工确认案例匹配
                         │
             手册检索与动态调查策略
                         │
         只读工具（告警上下文/日志/指标/Trace/数据库诊断）
                         │
                AI 结构化候选建议
                         │
             规则验收 + 独立 Validation Agent
                         │
                审计、通知、人工反馈
```

核心扩展点位于 `app/domain/ports.py`：

- `AlertSourceAdapter`：接入真实告警平台。
- `RunbookProvider`：接入文档库、内部 API 或向量检索。
- `RunbookStore`：管理与 `RunbookProvider` 相同语料库中的手册；自定义实现必须成对注入。
- `InvestigationTool`：接入日志、指标、Trace 和数据库管控平台的只读查询。
- `InvestigationStrategyProvider`：按服务、环境和告警类型选择调查策略。
- `AIAdvisor`：切换模型供应商或企业模型网关。
- `ConclusionValidator`：替换规则或独立模型验收器。
- `ManagementNotifier`：接入企业微信、钉钉、邮件或内部通知系统。
- `AlertRepository`：替换审计存储。

## 启动方式

项目提供两种启动方式。它们都会使用宿主机端口 `8000`，因此默认是**二选一**，不要在 Compose 运行时再次执行默认端口的 Uvicorn。

| 使用场景 | 启动方式 | 包含组件 | 访问地址 |
| --- | --- | --- | --- |
| 正常使用、完整体验 | Docker Compose（推荐） | Kafka、API、Worker、Web 管理台 | Web `http://localhost:3000`，API `http://localhost:8000` |
| 修改代码、断点调试、热更新 | 本地开发 | Uvicorn、Vite；默认使用进程内调度器 | Web `http://localhost:5173`，API `http://localhost:8000` |

第一次运行前复制配置文件（已有 `.env` 时不要覆盖）：

```bash
cp .env.example .env
```

真实模型模式需要在 `.env` 中填写：

```dotenv
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://your-compatible-endpoint/v1
AI_API_KEY=your-key
AI_MODEL=your-model
```

管理手册和 Agent 设置还需要独立的管理员令牌，不要与模型 API Key 复用：

```dotenv
ADMIN_API_TOKEN=replace-with-a-long-random-token
```

仅在本地开发或自动化测试时，可以显式使用确定性的 Fake 模型：

```dotenv
AI_PROVIDER=fake
```

### 正常使用：Docker Compose（推荐）

这种方式用于正常运行和体验完整系统，不需要手动启动 Uvicorn 或 Vite：

```bash
docker compose up -d --build
```

启动后访问：

- Web 管理台：`http://localhost:3000`
- API：`http://localhost:8000`
- OpenAPI 文档：`http://localhost:8000/docs`

查看状态和日志：

```bash
docker compose ps
docker compose logs -f api worker
```

停止完整系统：

```bash
docker compose down
```

### 本地开发：Uvicorn + Vite

这种方式用于修改代码和热更新调试。先停止占用 `8000` 端口的 Compose 服务：

```bash
docker compose down
```

需要 Python 3.12+。在项目根目录安装并启动后端：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.api.main:app --reload
```

另开一个终端启动前端：

```bash
cd frontend
npm install
npm run dev
```

本地开发地址为 Web `http://localhost:5173`、API `http://localhost:8000`。Vite 会把 `/api` 和 `/health` 代理到本地 Uvicorn。

如果确实需要保留 Docker，同时启动另一份本地后端，必须改用不同端口，并让 Vite 指向该端口：

```bash
uvicorn app.api.main:app --reload --port 8001

cd frontend
VITE_DEV_API_TARGET=http://localhost:8001 npm run dev
```

## Web 管理台

项目在 `frontend/` 提供独立的 React + TypeScript 管理台，后端仍由 FastAPI 单独运行。管理台包含：

- 告警总览、状态/等级筛选和自动刷新；
- 异步调查时间线、命中手册、工具证据、根因、建议步骤、风险、验收与通知结果；
- Canonical 示例告警接入表单；
- Markdown 手册查询、创建、编辑和删除；
- Agent 模型、API Key、独立验收、ReAct 和管理通知等运行时配置。

进入手册或设置页面时输入 `ADMIN_API_TOKEN`。令牌只保存在当前浏览器标签页会话中。Compose 默认只把 API 绑定到 `127.0.0.1`；远程告警平台应通过带认证的反向代理或 API 网关接入。

### 管理配置的安全语义

管理台不会直接编辑进程环境或把任意环境变量写入 `.env`。它只允许修改经过校验的白名单配置，并以权限 `0600` 原子保存到 `data/runtime-settings.json`。这些覆盖值优先于启动时的同名模型/通知配置；API 立即应用，Kafka Worker 在领取下一条任务前检查配置版本。

配置更新携带当前 `revision` 并在跨进程文件锁内比较；其他管理员已经修改配置时会返回 `409`，前端自动加载最新版本，避免旧页面静默覆盖新值。切换真实模型时必须同时具备 API Key 和 Model，切换 Webhook 时必须提供有效 URL；不可运行的组合不会显示为“已应用”。`Fake` Provider 只允许开发/测试环境使用。

`AI_API_KEY` 和 `MANAGEMENT_WEBHOOK_BEARER_TOKEN` 是只写字段：查询接口只返回“是否已配置”，不会返回原值。`DATABASE_URL`、Kafka 地址、管理员令牌、手册目录等基础设施配置不能从网页修改，仍需通过部署环境设置并重启服务。生产环境应把 `data/` 放在受控的加密磁盘或 Secret 管理系统中，并在网关接入企业 SSO/RBAC；内置静态 Bearer Token 只保护管理接口，不替代企业身份系统。告警接入、列表和详情接口在首版默认由部署网络边界保护，生产环境不得把 8000 端口直接暴露到不可信网络。

## HTTP 示例

```bash
curl -X POST http://localhost:8000/api/v1/alerts/canonical/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "external_id": "demo-001",
    "severity": "CRITICAL",
    "title": "数据库连接数接近上限",
    "reason": "connection_exhausted",
    "description": "连接使用率达到 98%",
    "environment": "production",
    "service_name": "orders-api",
    "alert_type": "connection_exhausted",
    "metric_name": "connection_usage_percent",
    "database": {"engine": "postgresql", "instance": "orders-primary"},
    "features": {"connection_usage_percent": 98},
    "labels": {"team": "database"}
  }'
```

接口立即返回：

```json
{
  "alert_id": "...",
  "event_id": "demo-001",
  "status": "QUEUED",
  "detail_url": "/api/v1/alerts/...",
  "deduplicated": false
}
```

查询审计结果：

```bash
curl http://localhost:8000/api/v1/alerts/{alert_id}
```

`external_id` 是告警平台事件幂等键；生产接入应始终提供。系统另行生成不含发生时间的 `incident_fingerprint`，用于匹配同类已确认案例，二者语义不可混用。

查询结果会包含当前 `latest_run`、有序 `progress`、`evidence_records` 和 `validations`。必需调查工具未接入、超时或验收拒绝时，状态为 `REVIEW_REQUIRED`，而不是伪装为已确认根因。

## Kafka

“正常使用：Docker Compose”模式会自动启动 Kafka、API 和 Worker，无需额外执行命令。本地开发模式默认使用进程内调度器，不要求启动 Kafka；只有调试 Kafka 链路时才需要单独调整 `.env` 并启动相关服务。

Worker 同时接受外部告警信封和 API 发布的内部调查任务。外部告警格式为：

```json
{
  "source": "canonical",
  "payload": {
    "external_id": "demo-kafka-001",
    "severity": "HIGH",
    "title": "慢查询数量增加",
    "reason": "slow_query_spike"
  }
}
```

无法处理的消息在重试后写入 `database-alerts.dlq`，死信中的原始数据会先脱敏。

## 接入真实系统

### 告警平台

复制 `app/adapters/alert_sources.py` 中的 `ExamplePlatformAdapter`，把平台载荷映射为 `NormalizedAlert`，再在应用工厂中注册。HTTP 路径和 Kafka `source` 使用该适配器名称，核心工作流无需修改。

### 告警处理手册

当前实现读取 `runbooks/` 下带 YAML front matter 的 Markdown。格式见 `runbooks/README.md`。获得真实手册系统后，需要同时实现 `RunbookProvider.search()` 与 `RunbookStore` CRUD，并成对传给应用工厂；这样前端修改的语料与 Agent 实际检索的语料始终一致。

命中手册时，每条 AI 建议步骤必须引用实际命中的手册 ID/章节；引用缺失或虚构时会自动请求模型修复一次，仍不合规则分析失败。未命中手册时置信度最多为 `0.45`。

### 调查工具

框架默认注册以下工具名：

- `alert_context`：可运行，只读取告警平台随事件提供的数据。
- `query_logs`
- `query_metrics`
- `query_trace`
- `query_endpoint_errors`
- `query_database_diagnostics`

除 `alert_context` 外，其余都是明确失败的占位适配器。获得真实平台后实现 `InvestigationTool.execute()` 并在工厂注册。工具结果会经过超时隔离、大小限制和二次脱敏，再以 `EvidenceRecord` 落库。失败或超时结果不能支持“已验证根因”。

`connection_exhausted` 已有内置策略，要求连接数当前值/上限/趋势，以及连接来源和长会话诊断；这些工具未接入时结果会进入人工复核。

只有在真实只读工具接入后才建议启用受限动态调查：

```dotenv
REACT_ENABLED=true
REACT_MAX_DYNAMIC_TURNS=2
```

### 管理通知

设置以下配置启用通用 Webhook：

```dotenv
NOTIFIER_MODE=webhook
MANAGEMENT_WEBHOOK_URL=https://management.example/alerts
MANAGEMENT_WEBHOOK_BEARER_TOKEN=optional-token
```

Webhook 接收 `NotificationEvent` JSON。阶段包括 `INITIAL_ALERT`、`ADVICE_READY` 和 `ANALYSIS_FAILED`。通知失败会按配置重试并写入审计记录，但不会丢弃已经生成的分析结果。

### 人工反馈与案例知识库

完成或待复核的调查可提交反馈：

```bash
curl -X POST http://localhost:8000/api/v1/alerts/{alert_id}/feedback \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer your-admin-token' \
  -d '{
    "idempotency_key": "ticket-123-feedback-v1",
    "verdict": "CONFIRMED",
    "reviewer": "dba-oncall",
    "final_root_cause": "应用连接池未释放连接",
    "actual_resolution": "修复连接池配置后恢复",
    "recovered": true
  }'
```

只有 `CONFIRMED/CORRECTED + recovered=true` 的反馈会生成案例。历史案例只作为候选上下文，后续同指纹告警仍执行本次实时工具验证和最终验收。反馈接口要求管理员令牌，审计记录中的 reviewer 由服务端认证结果填写，不信任请求体中的伪造身份。

## Web/API 管理接口

以下接口都要求 `Authorization: Bearer <ADMIN_API_TOKEN>`：

- `GET/POST /api/v1/admin/runbooks`：列出或新增手册；
- `GET/PUT/DELETE /api/v1/admin/runbooks/{id}`：查看、按版本更新或删除手册；
- `GET/PATCH /api/v1/admin/settings`：读取安全摘要或更新运行时白名单配置；
- `POST /api/v1/alerts/{id}/feedback`：提交可信人工结论并生成可复用案例。

手册更新使用 `expected_version`，配置更新使用 `expected_revision` 做乐观锁；多人同时编辑时，过期版本会返回 `409`，避免静默覆盖。管理修改只把操作者、目标、字段名和时间写入 `data/runtime-settings.audit.jsonl`，不会写入密钥内容。

## 数据库与迁移

默认使用 `sqlite+aiosqlite:///./data/alerts.db`。仓储基于 SQLAlchemy 异步接口，可通过 `DATABASE_URL` 和相应驱动切换数据库。

```bash
alembic upgrade head
```

应用启动时也会创建缺失表，便于空仓库首次运行；它不会修改既有表。升级现有环境时必须先执行 Alembic，正式环境建议切换 PostgreSQL 并使用 Kafka 调度：

如果 SQLite 是旧版应用通过 `create_all()` 创建的、还没有 `alembic_version` 表，请在首次启动 v2 前执行：

```bash
alembic stamp 0001
alembic upgrade head
```

全新数据库直接执行 `alembic upgrade head`。开发环境即使不执行迁移，启动时也会补建缺失的新表，但正式环境不要依赖这一行为。

```dotenv
HTTP_SCHEDULER=kafka
KAFKA_ENABLED=true
```

## 测试

```bash
pytest
ruff check .
npm --prefix frontend run build
docker compose config --quiet
```

默认测试不访问真实模型或外部 Webhook。设置 `RUN_KAFKA_TESTS=1` 和 `KAFKA_BOOTSTRAP_SERVERS` 可运行 Kafka Broker 集成测试。
