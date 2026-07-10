# 告警处理手册接入位

当前适配器读取本目录中的 Markdown 文件。每个文件使用 YAML front matter 描述匹配条件，正文为权威处理步骤。

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
---

这里填写已经审批的处理步骤、风险和升级条件。
```

获得真实手册系统后，实现 `RunbookProvider.search()` 并在 `app/application/factory.py` 注册即可；核心工作流无需修改。
