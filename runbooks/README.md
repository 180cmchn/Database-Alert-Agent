# 告警处理手册网页索引

本目录只保存网页手册的匹配索引和管理备注，不保存、匹配或向模型发送本地手册正文。
告警命中索引候选后，服务会在公司内网/VPN 环境中携带认证会话访问 `source_url`，提取网页
正文，再将该网页正文作为权威处置依据。没有 `source_url` 的旧 Markdown 条目会被忽略，不会
回退到本地正文。

每个索引文件使用以下格式：

```markdown
---
id: unique-runbook-id
title: 手册标题
section: main
reasons: [alert_reason_code]
keywords: [连接数, connection]
severities: [HIGH, CRITICAL]
labels:
  database_team: core
source_url: https://wiki.corp.example/runbooks/database/connection-limit
# 可选：只提取指定元素；支持标签名、#id 或 .class
content_selector: '#article-content'
---

索引管理备注：权威正文来自 source_url，本段内容不参与匹配，也不会发送给模型。
```

服务必须部署在可访问公司内网/VPN 的环境中，并通过启动配置明确允许手册域名：

```dotenv
RUNBOOK_WEB_ALLOWED_HOSTS=["wiki.corp.example"]
RUNBOOK_WEB_AUTH_MODE=cookie
RUNBOOK_WEB_AUTH_SECRET=company_session=替换为部署平台注入的会话值
```

使用非标准端口时，白名单写成 `wiki.corp.example:8443`。公司 SSO 已登录会话的 Cookie
（原始 `Cookie` 请求头值）放在 `RUNBOOK_WEB_AUTH_SECRET`；若手册系统提供服务账号 API
令牌，则优先设置 `RUNBOOK_WEB_AUTH_MODE=bearer` 并注入令牌。凭据不得写入索引、代码或 Git。

匹配过程如下：

1. 使用索引中的 `reasons` 和 `keywords` 筛选候选；
2. 携带认证会话拉取候选的 `source_url`；
3. 从实际网页正文、告警等级和标签计算最终排序；
4. 仅将命中的网页正文及其手册 ID/章节交给建议生成器。

建议为所有索引维护明确的 `reasons`/`keywords`，否则服务需要先拉取页面才能根据正文尝试
匹配。仅等级相同或仅标签相同不会构成命中。跨域跳转会被拒绝；Cookie 失效并跳转到 SSO
登录页时，调查会明确失败，不会把登录页误当作手册。

纯前端渲染、需要验证码或交互式登录的页面应改用手册系统的正文导出/API URL；适配器不会
执行网页 JavaScript。一份网页包含多种告警时，建议按可引用章节建立多个索引记录，并分别
设置 `content_selector`。
