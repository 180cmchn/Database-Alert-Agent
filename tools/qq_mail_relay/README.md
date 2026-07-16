# QQ 邮件测试中转服务

该服务接收 Database Alert Agent 通用 Webhook 模式发送的 `NotificationEvent` JSON，将事件
二次脱敏并转换为纯文本邮件，再通过 QQ SMTP 发送到预先配置的固定 QQ 邮箱。它只用于个人
试运行，不是正式管理通知渠道；正常/正式通知应使用 `NOTIFIER_MODE=wecom`。

`wecom` 与 `webhook` 是互斥模式。本服务不会在企业微信通知之外再复制一封邮件；启用 QQ
邮箱试运行时，Agent 的管理通知会改由本服务接收。

## 安全模型

- Webhook 请求必须携带至少 32 字符的 Bearer Token；Agent 与中转服务配置相同值。
- 发件人和收件人均由中转服务环境变量固定，请求体不能覆盖，避免被当作开放邮件网关。
- 只使用 QQ 邮箱生成的 SMTP 授权码，绝不使用 QQ 登录密码。
- 事件在生成邮件前再次递归脱敏；SQLite 只记录 `alert.id + phase` 的成功投递 ID，不保存
  邮件正文、授权码或 Bearer Token。
- SMTP SSL/STARTTLS 会验证服务端证书，不支持明文 SMTP。
- Compose 只把中转端口绑定到宿主机 `127.0.0.1:8081`，不要直接暴露到公网。

QQ 邮箱的 SMTP 服务和授权码请按 [QQ 邮箱官方帮助](https://service.mail.qq.com/detail/0/75)
开通。授权码、Webhook Token 与企业微信机器人 URL 都应由 Secret 管理系统保存，不得提交到
Git；`tools/qq_mail_relay/.env` 已被忽略。

## 1. 准备配置

在项目根目录复制示例文件：

```bash
cp tools/qq_mail_relay/.env.example tools/qq_mail_relay/.env
```

先生成一段随机 Bearer Token，例如：

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

编辑 `tools/qq_mail_relay/.env`。首次联调保留 dry-run：

```dotenv
QQ_MAIL_RELAY_DRY_RUN=true
QQ_MAIL_RELAY_BEARER_TOKEN=replace-with-at-least-32-random-characters

QQ_MAIL_RELAY_MAIL_FROM=sender@qq.com
QQ_MAIL_RELAY_MAIL_TO=recipient@qq.com
QQ_MAIL_RELAY_DATABASE_PATH=./data/qq-mail-relay.db

QQ_MAIL_RELAY_SMTP_HOST=smtp.qq.com
QQ_MAIL_RELAY_SMTP_PORT=465
QQ_MAIL_RELAY_SMTP_SECURITY=ssl
QQ_MAIL_RELAY_SMTP_USERNAME=sender@qq.com
QQ_MAIL_RELAY_SMTP_AUTH_CODE=
```

dry-run 不建立 SMTP 连接，但会执行 Bearer 鉴权、请求校验、脱敏、纯文本格式化和 SQLite
成功去重。因为中转服务已经成功接受事件，Agent 侧通知审计会显示 `SENT`，但此时邮箱中
不会出现邮件。

## 2. 启动中转服务

### Docker Compose profile（推荐）

单独启动中转服务：

```bash
docker compose --profile qq-mail-relay up -d --build qq-mail-relay
docker compose --profile qq-mail-relay ps qq-mail-relay
```

与 Agent 全套服务一起启动：

```bash
docker compose --profile qq-mail-relay up -d --build
```

容器内监听 `8080`，宿主机仅可通过 `http://127.0.0.1:8081` 访问。查看状态和日志：

```bash
curl -sS http://127.0.0.1:8081/health/live
curl -sS http://127.0.0.1:8081/health/ready | python3 -m json.tool
docker compose --profile qq-mail-relay logs -f qq-mail-relay
```

`/health/ready` 只有在 Bearer Token、固定发件人与收件人、SQLite 均可用时才返回就绪；关闭
dry-run 后还会要求完整 SMTP 配置。

### 本地进程

在项目虚拟环境中让 Uvicorn 读取独立配置文件：

```bash
uvicorn tools.qq_mail_relay.main:app \
  --host 127.0.0.1 \
  --port 8081 \
  --env-file tools/qq_mail_relay/.env
```

不要让本地中转服务与 Compose 中转服务同时占用 `8081`。

## 3. 配置 Agent 的通用 Webhook

进入 Web 管理台“设置 → 管理通知”，选择“通用 Webhook（兼容）”，填写：

- Management Webhook URL：按下表选择；
- Webhook Bearer Token：与 `QQ_MAIL_RELAY_BEARER_TOKEN` 完全相同；
- 触发等级：保留 `CRITICAL`；
- 保存后检查 `/health/ready`。

也可在 Agent 根目录 `.env` 中设置同名变量并重启 API 与 Worker。若之前用管理台保存过运行
时配置，`data/runtime-settings.json` 的覆盖值优先于 `.env`，应继续在管理台修改。

| Agent 位置 | 中转服务位置 | `MANAGEMENT_WEBHOOK_URL` |
| --- | --- | --- |
| 本地进程 | 本地进程 | `http://127.0.0.1:8081/api/v1/notifications` |
| 本地进程 | Compose | `http://127.0.0.1:8081/api/v1/notifications` |
| Compose | 同一个 Compose profile | `http://qq-mail-relay:8080/api/v1/notifications` |
| Compose | macOS 宿主机进程 | `http://host.docker.internal:8081/api/v1/notifications` |

容器中的 `localhost` 指向容器自己，因此 Compose 中的 Agent 不能用
`http://127.0.0.1:8081` 访问另一个容器或宿主机。

Agent 的 `.env` 示例（Agent 与中转服务都在 Compose 中）：

```dotenv
NOTIFIER_MODE=webhook
MANAGEMENT_WEBHOOK_URL=http://qq-mail-relay:8080/api/v1/notifications
MANAGEMENT_WEBHOOK_BEARER_TOKEN=与中转服务相同的随机值
ESCALATION_SEVERITIES=["CRITICAL"]
```

## 4. 从 dry-run 切换为真实 QQ SMTP

先用 dry-run 发送一条 CRITICAL 样例并确认以下项目：

1. 中转服务 `/health/ready` 返回 `ready`；
2. Agent 告警详情中出现 `INITIAL_ALERT` 与最终阶段的 `SENT` 记录；
3. 中转日志没有输出凭据或未脱敏的敏感字段；
4. `QQ_MAIL_RELAY_MAIL_TO` 确认是你的测试邮箱。

然后在 `tools/qq_mail_relay/.env` 填写 QQ SMTP 授权码并关闭 dry-run：

```dotenv
QQ_MAIL_RELAY_DRY_RUN=false
QQ_MAIL_RELAY_SMTP_USERNAME=sender@qq.com
QQ_MAIL_RELAY_SMTP_AUTH_CODE=replace-with-qq-smtp-authorization-code
QQ_MAIL_RELAY_MAIL_FROM=sender@qq.com
QQ_MAIL_RELAY_MAIL_TO=recipient@qq.com
```

默认使用 `smtp.qq.com:465` 和 `QQ_MAIL_RELAY_SMTP_SECURITY=ssl`；也支持端口 `587` 与
`starttls`。改完后重建或重启中转服务，再确认就绪：

```bash
docker compose --profile qq-mail-relay up -d --force-recreate qq-mail-relay
curl -sS http://127.0.0.1:8081/health/ready | python3 -m json.tool
```

## 5. 发送与验收

使用 [`../../examples/qq-trial/README.md`](../../examples/qq-trial/README.md) 中的 CRITICAL
样例。一次成功调查预期收到两封纯文本邮件：

1. `INITIAL_ALERT`：模型调用前的原始告警摘要；
2. `ADVICE_READY`：调查完成后的处理建议。

如果模型或调查失败，第二封改为 `ANALYSIS_FAILED`，提示人工介入。相同
`alert.id + phase` 再次到达时，中转服务返回既有 `X-Delivery-Id`，不会重复发信。Agent 详情
中的 `SENT` 表示 SMTP 中转已接受该阶段；真实发送时仍应人工检查目标邮箱及垃圾邮件目录。

中转服务按单进程设计。SMTP 已接受邮件、但进程在写入 SQLite 前异常退出时，仍存在很小的
重复投递窗口；不要将它直接作为生产级邮件基础设施。

试运行结束后切回企业微信，在 Agent 管理台选择“企业微信（推荐）”并配置只写的
`WECOM_WEBHOOK_URL`，然后停掉测试中转：

```bash
docker compose --profile qq-mail-relay stop qq-mail-relay
```
