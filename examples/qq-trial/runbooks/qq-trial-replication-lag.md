---
id: qq-trial-replication-lag
title: QQ 试运行数据库告警测试手册 · PostgreSQL 复制延迟
section: readonly-triage
reasons: [replication_lag_high, replica_delay_seconds_high]
keywords: [复制延迟, replication lag, replay lag]
severities: [HIGH, CRITICAL]
labels:
  trial_channel: qq
manual_group: qq-trial-database-alerts
test_only: true
---

> 仅用于 QQ 通知和手册匹配试运行，不是生产手册。所有步骤仅允许读取监控、日志和已有配置记录；任何处置变更都必须由值班 DBA 审批。

适用信号：`replication_lag_high`、`replica_delay_seconds_high`。

1. 从只读监控确认复制延迟的当前值、阈值、持续时间和最近 30 分钟趋势，并记录受影响副本。
2. 对比主库日志生成速率和副本接收、回放速率，判断延迟发生在传输阶段还是回放阶段。
3. 核对同一时间窗口内的网络、磁盘和副本资源指标，以及近期发布和配置变更记录。
4. 确认业务是否读取该副本、数据时效要求和当前影响范围，不把告警指标直接等同于已确认根因。
5. 若延迟持续增长、超过业务时效要求或副本不可用，立即通知值班 DBA 和业务负责人，由人工决定后续处置。

预期证据：复制延迟曲线、日志生成与回放速率、相关资源指标、受影响业务清单和人工审批记录。
