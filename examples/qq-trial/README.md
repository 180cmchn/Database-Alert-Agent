# QQ 邮箱试运行样例

这组材料用于验证“告警接收 → AI 调查与建议 → CRITICAL 两阶段邮件通知”的完整
链路，不会连接数据库或执行处置动作。邮件由仓库内 `tools/qq_mail_relay` 接收
`NotificationEvent`、转换为纯文本，再通过 QQ SMTP 授权码发送到固定 QQ 邮箱。

正式管理通知使用企业微信：`NOTIFIER_MODE=wecom` + 只写的 `WECOM_WEBHOOK_URL`。本试运行
临时改用 `NOTIFIER_MODE=webhook` 指向 QQ 邮件中转服务；两种模式互斥，不会同时发送企业微信
和邮件。中转服务的完整安全说明见
[`../../tools/qq_mail_relay/README.md`](../../tools/qq_mail_relay/README.md)。

## 样例组成

`alerts/` 包含四类不同等级的数据库告警，用于验证通知升级、幂等和无手册时的保守建议。
旧版仅供试运行的本地 Markdown 手册已经删除；所有样例都应返回空 `manual_matches`、
`manual_matched=false`，且建议置信度不超过 `0.45`。

如需验证手册命中，应按项目根目录 `runbooks/README.md` 配置可访问的公司内网网页手册；
本样例不再提供任何本地正文回退。

## 1. 配置 QQ 邮件中转

在项目根目录复制配置：

```bash
cp tools/qq_mail_relay/.env.example tools/qq_mail_relay/.env
```

生成至少 32 字符的随机 Token：

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

编辑 `tools/qq_mail_relay/.env`，先保持 dry-run：

```dotenv
QQ_MAIL_RELAY_DRY_RUN=true
QQ_MAIL_RELAY_BEARER_TOKEN=replace-with-the-random-token
QQ_MAIL_RELAY_MAIL_FROM=sender@qq.com
QQ_MAIL_RELAY_MAIL_TO=recipient@qq.com
```

dry-run 会完整验证鉴权、事件格式、脱敏、文本转换和幂等记录，但不会连接 QQ SMTP、也不会
产生真实邮件。先用它完成链路验证，再按中转服务 README 填入 QQ SMTP 授权码并设置
`QQ_MAIL_RELAY_DRY_RUN=false`。不要使用 QQ 登录密码。

## 2. 启动隔离测试环境

启用 `qq-mail-relay` Compose profile：

```bash
docker compose \
  --profile qq-mail-relay \
  up -d --build
```

这会启动 Kafka、API、Worker、Web 管理台和 QQ 邮件中转。确认服务就绪：

```bash
docker compose \
  --profile qq-mail-relay \
  ps

curl -sS http://127.0.0.1:8081/health/ready | python3 -m json.tool
curl -sS http://127.0.0.1:8000/health/ready | python3 -m json.tool
```

若要全部使用本地进程，可先停止 Compose，再分别启动：

```bash
uvicorn app.api.main:app --reload

uvicorn tools.qq_mail_relay.main:app \
  --host 127.0.0.1 \
  --port 8081 \
  --env-file tools/qq_mail_relay/.env
```

## 3. 在管理台配置 Agent

打开 `http://localhost:3000`，进入“设置 → 管理通知”，使用 `ADMIN_API_TOKEN` 解锁后填写：

- 通知模式：`通用 Webhook（兼容）`；
- Management Webhook URL：`http://qq-mail-relay:8080/api/v1/notifications`；
- Webhook Bearer Token：与 `QQ_MAIL_RELAY_BEARER_TOKEN` 完全相同；
- 触发管理通知的等级：保留 `CRITICAL`；
- 保存设置。

上面的服务名 URL 适用于 API 与中转都运行在同一个 Compose 网络。其他组合使用下表：

| Agent 位置 | 中转服务位置 | Management Webhook URL |
| --- | --- | --- |
| Compose | 同一 Compose profile | `http://qq-mail-relay:8080/api/v1/notifications` |
| Compose | macOS 本地进程 | `http://host.docker.internal:8081/api/v1/notifications` |
| 本地进程 | 本地进程或 Compose | `http://127.0.0.1:8081/api/v1/notifications` |

也可在 Agent 根目录 `.env` 中写入对应值并重启 API/Worker：

```dotenv
NOTIFIER_MODE=webhook
MANAGEMENT_WEBHOOK_URL=http://qq-mail-relay:8080/api/v1/notifications
MANAGEMENT_WEBHOOK_BEARER_TOKEN=与中转服务相同的随机值
ESCALATION_SEVERITIES=["CRITICAL"]
# 本试运行不配置手册索引；占位白名单仅用于通过启动就绪检查，不会发起访问。
RUNBOOK_WEB_ALLOWED_HOSTS=["unused.invalid"]
RUNBOOK_WEB_AUTH_MODE=none
```

如果以前通过管理台保存过设置，`data/runtime-settings.json` 优先于 `.env`，请继续在管理台
修改。容器内的 `localhost` 只指向当前容器，不能代替 `qq-mail-relay` 或
`host.docker.internal`。

## 4. 发送 CRITICAL 主测试信号

在项目根目录运行：

```bash
python3 examples/qq-trial/run_cases.py \
  --case critical-replication-lag \
  --require-webhook
```

`--require-webhook` 会通过管理接口确认当前运行时确实使用通用 Webhook，并确认 CRITICAL
位于升级等级中。它从 `ADMIN_API_TOKEN` 环境变量读取管理员令牌；未设置且有交互终端时会
安全提示输入，输入内容不会显示。

脚本为 `external_id` 添加唯一后缀，发送后轮询分析结果，并检查无手册策略、规则验收与
通知审计。成功时应满足：

1. `manual_matches` 为空，且建议使用无手册置信度上限；
2. 中转先接受 `INITIAL_ALERT`，AI 成功后再接受 `ADVICE_READY`；
3. `recommendation.manual_matched=false`，且不会伪造手册引用；
4. 规则验收通过，两个通知阶段的审计状态均为 `SENT`。

dry-run 下不会收到邮件，`SENT` 只表示中转服务成功完成模拟投递。关闭 dry-run 并正确配置
SMTP 后，一次成功调查应收到两封纯文本邮件：第一封是 `INITIAL_ALERT` 原始告警摘要，第二封
是 `ADVICE_READY` 处理建议；模型或调查失败时第二封改为 `ANALYSIS_FAILED`。仍需在目标 QQ
邮箱及垃圾邮件目录中人工确认实际到达。

显式验证重复事件不会重复分析和发信：

```bash
python3 examples/qq-trial/run_cases.py \
  --case critical-replication-lag \
  --require-webhook \
  --verify-idempotency
```

该模式会在一次运行中两次发送相同 `external_id`，并断言第二次
`deduplicated=true`、复用同一 `alert_id`，且通知阶段不增加。中转服务还会按
`alert.id + phase` 保存成功投递 ID，防止 Agent Webhook 重试造成重复邮件。

## 5. 验证其他告警等级

一次运行全部四种信号：

```bash
python3 examples/qq-trial/run_cases.py --case all --require-webhook
```

也可以只运行某个对照项：

```bash
python3 examples/qq-trial/run_cases.py --case high-connection-pool
python3 examples/qq-trial/run_cases.py --case medium-slow-query
python3 examples/qq-trial/run_cases.py --case medium-unmatched-deadlock
```

默认只有 CRITICAL 触发管理通知，因此后三条不应发送邮件。所有告警都应返回空
`manual_matches`、`manual_matched=false`，且建议置信度不超过 `0.45`。

不使用脚本时也可直接发送 JSON；固定 ID 的第二次请求会被去重：

```bash
curl -sS -X POST http://localhost:8000/api/v1/alerts/canonical/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/qq-trial/alerts/01-critical-replication-lag.json \
  | python3 -m json.tool
```

排查通知失败时查看告警详情中的 `notifications`，并观察日志：

```bash
docker compose \
  --profile qq-mail-relay \
  logs -f api worker qq-mail-relay
```

## 6. 结束试运行并切回企业微信

停止隔离环境：

```bash
docker compose \
  --profile qq-mail-relay \
  down
```

在管理台将通知模式切为“企业微信（推荐）”，填写只写的企业微信群机器人 Webhook URL，再用
网页手册配置启动正常环境：

```bash
docker compose up -d --build
```

确认 `.env` 或运行时设置中不再使用 QQ 中转 URL。试运行后若不再需要 SMTP，应撤销旧授权码
或从部署环境删除，并妥善清理 `tools/qq_mail_relay/.env` 和测试数据库。
