---
id: example-connection-limit
title: 示例：数据库连接数耗尽处理手册
section: initial-triage
reasons: [connection_exhausted, too_many_connections]
keywords: [连接数, connection, too many connections]
severities: [HIGH, CRITICAL]
---

> 这是格式占位示例，不是生产处理手册。接入前必须由数据库负责人替换并审批。

1. 通过只读监控确认当前连接数、最大连接数、增长时间和受影响实例。
2. 核对连接来源分布、应用连接池配置，以及是否存在持续时间异常的会话。
3. 在采取终止会话、调整连接上限或重启等变更前，必须由值班 DBA 评估并审批。
4. 若业务已不可用或连接仍快速增长，立即升级给数据库负责人和业务负责人。
