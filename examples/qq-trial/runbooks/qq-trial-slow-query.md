---
id: qq-trial-slow-query
title: QQ 试运行数据库告警测试手册 · 慢查询突增
section: readonly-triage
reasons: [slow_query_spike, database_latency_high]
keywords: [慢查询, slow query, query latency]
severities: [MEDIUM, HIGH]
labels:
  trial_channel: qq
manual_group: qq-trial-database-alerts
test_only: true
---

> 仅用于 QQ 通知和手册匹配试运行，不是生产手册。只收集只读诊断证据，不执行数据库处置动作。

适用信号：`slow_query_spike`、`database_latency_high`。

1. 从监控确认慢查询数量、P95 查询延迟、阈值、持续时间和受影响数据库。
2. 按脱敏后的查询指纹汇总次数与总耗时，识别影响最大的查询类别，不在通知中传播原始参数。
3. 对比告警前后的发布、流量、数据量和执行计划快照，区分相关事实与待验证假设。
4. 核对数据库 CPU、磁盘延迟、锁等待和连接使用率，记录与慢查询时间窗口一致的证据。
5. 若错误率或业务延迟继续上升，通知值班 DBA 和业务负责人，由人工确定后续处置。

预期证据：慢查询趋势、脱敏查询指纹、执行计划快照、相关资源指标和业务影响记录。
