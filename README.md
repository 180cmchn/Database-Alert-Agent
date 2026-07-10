# Database Alert AI Agent

一个可插拔、可审计的数据库告警 AI 分析框架。它通过 HTTP 或 Kafka 接收告警，优先检索已经审批的处理手册，再调用 OpenAI 兼容模型生成结构化建议；CRITICAL 告警会先通知管理人员，分析完成后再补发建议。

该项目**不会执行 SQL、重启实例、终止会话或修改数据库配置**。

## 架构

```text
HTTP / Kafka
     │
AlertSourceAdapter（平台载荷标准化）
     │
脱敏、去重、SQLite 审计
     │
CRITICAL 原始告警通知
     │
RunbookProvider（手册为首要依据）
     │
AIAdvisor（结构化建议和引用校验）
     │
保存结果、CRITICAL 后续通知
```

核心扩展点位于 `app/domain/ports.py`：

- `AlertSourceAdapter`：接入真实告警平台。
- `RunbookProvider`：接入文档库、内部 API 或向量检索。
- `AIAdvisor`：切换模型供应商或企业模型网关。
- `ManagementNotifier`：接入企业微信、钉钉、邮件或内部通知系统。
- `AlertRepository`：替换审计存储。

## 本地启动

需要 Python 3.12+。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

真实模型模式需在 `.env` 中填写：

```dotenv
AI_PROVIDER=openai_compatible
AI_BASE_URL=https://your-compatible-endpoint/v1
AI_API_KEY=your-key
AI_MODEL=your-model
```

仅验证框架时可显式使用确定性的测试模型：

```dotenv
AI_PROVIDER=fake
```

启动 HTTP API：

```bash
uvicorn app.api.main:app --reload
```

访问 `http://localhost:8000/docs` 查看 OpenAPI 文档。

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
    "database": {"engine": "postgresql", "instance": "orders-primary"},
    "features": {"connection_usage_percent": 98},
    "labels": {"team": "database"}
  }'
```

查询审计结果：

```bash
curl http://localhost:8000/api/v1/alerts/{alert_id}
```

如果未提供 `external_id`，Canonical 适配器会根据告警来源、等级、标题、原因、时间和数据库目标生成稳定指纹。

## Kafka

使用 Docker Compose 同时启动 Kafka、API 和 Worker：

```bash
docker compose up --build
```

Worker 消费 `database-alerts`，消息格式为：

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

当前实现读取 `runbooks/` 下带 YAML front matter 的 Markdown。格式见 `runbooks/README.md`。获得真实手册系统后，实现 `RunbookProvider.search()` 并替换工厂中的 Provider。

命中手册时，每条 AI 建议步骤必须引用实际命中的手册 ID/章节；引用缺失或虚构时会自动请求模型修复一次，仍不合规则分析失败。未命中手册时置信度最多为 `0.45`。

### 管理通知

设置以下配置启用通用 Webhook：

```dotenv
NOTIFIER_MODE=webhook
MANAGEMENT_WEBHOOK_URL=https://management.example/alerts
MANAGEMENT_WEBHOOK_BEARER_TOKEN=optional-token
```

Webhook 接收 `NotificationEvent` JSON。阶段包括 `INITIAL_ALERT`、`ADVICE_READY` 和 `ANALYSIS_FAILED`。通知失败会按配置重试并写入审计记录，但不会丢弃已经生成的分析结果。

## 数据库与迁移

默认使用 `sqlite+aiosqlite:///./data/alerts.db`。仓储基于 SQLAlchemy 异步接口，可通过 `DATABASE_URL` 和相应驱动切换数据库。

```bash
alembic upgrade head
```

应用启动时也会创建缺失表，便于空仓库首次运行；正式环境应使用 Alembic 管理版本。

## 测试

```bash
pytest
ruff check .
```

默认测试不访问真实模型或外部 Webhook。设置 `RUN_KAFKA_TESTS=1` 和 `KAFKA_BOOTSTRAP_SERVERS` 可运行 Kafka Broker 集成测试。
