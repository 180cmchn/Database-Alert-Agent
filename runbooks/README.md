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

本地匹配器先使用 `reasons`、`keywords` 或正文中的原因代码建立语义相关性，再用
`severities` 和 `labels` 加权排序。仅等级相同或仅标签相同不会被视为手册命中。

当前一个 Markdown 文件对应一个可引用的手册片段和一个 `section`。如果一份手册包含
多种告警，建议按告警类型拆成多个文件，并通过自定义元数据（例如 `manual_group`）标记为
同一手册集，避免模型收到无关处置步骤。

自定义元数据只用于标识，不会自动变成过滤条件。例如 `test_only: true` 本身不能阻止生产
告警命中该文件；测试手册应放在独立目录，并通过单独的 `RUNBOOK_DIR` 加载。
