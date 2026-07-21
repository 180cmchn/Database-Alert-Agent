# Database Alert Agent

本项目只负责一条告警分析链路：

1. 接收并规范化数据库告警；告警等级固定为 `CRITICAL`、`WARNING`、`INFO`。
2. 读取项目内的本地 PDF 告警手册并完成全文匹配。
3. 由 AI Agent 结合告警信息生成可能原因、判断依据和只读核查建议。
4. 判断依据严格按“命中手册在前、AI 分析在后”输出。
5. 将每个等级的最终 AI 分析结果发送到企业微信群机器人。

值班人员查询、企微卡片确认、电话、群组分派、通知升级、等待窗口、送达确认和通知重试均不属于本项目。

## 数据流

```text
告警平台 / HTTP / Kafka
          ↓
三等级规范化与脱敏
          ↓
本地 PDF 告警手册匹配（首要依据）
          ↓
AI 分析（次要依据）+ 规则校验
          ↓
结构化原因与有序依据
          ↓
企业微信群机器人
```

企微发送只尝试一次。服务不会查询是否送达，也不会因发送失败改写已经完成的分析状态。

## 告警手册

`runbooks/pdfs/*.pdf` 是唯一手册数据源。当前目录包含随本项目提供的 10 份告警处理手册。
服务从 PDF 文字层提取标题与正文，并依次使用告警原因、告警名称、指标名、告警类型、故障
摘要、标题等字段进行匹配。文件名（不含 `.pdf`）作为手册 ID，引用章节统一为 `PDF`。

PDF 必须未加密且带可提取文字层；纯扫描件需先 OCR。手册目录为只读运行数据，更新方式是
替换目录内 PDF 后重启 API 和 Worker，不支持通过管理 API 在线增删改。

相关环境变量：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs
RUNBOOK_LIMIT=5
RUNBOOK_PDF_MAX_FILE_BYTES=20000000
RUNBOOK_PDF_MAX_TEXT_CHARS=200000
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

WECOM_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=replace-me
```

`AI_API_KEY` 和 `WECOM_WEBHOOK_URL` 都是秘密值。管理 API 只返回“是否已配置”，不会返回原值。生产环境必须配置企微机器人地址；开发环境未配置时仅写本地日志，便于测试。

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

## 验证

```bash
pytest
ruff check app tests migrations
cd frontend && npm run build
```

数据库升级使用 Alembic。`0005_reduce_analysis_scope` 会删除旧的路由、升级和通知送达表，并把历史建议中的旧 `evidence` 字段迁移为有来源标记的 `analysis_bases`。
