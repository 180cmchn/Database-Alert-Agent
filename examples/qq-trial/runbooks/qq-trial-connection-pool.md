---
id: qq-trial-connection-pool
title: QQ 试运行数据库告警测试手册 · 应用连接池饱和
section: readonly-triage
reasons: [pool_saturation, pool_wait_queue_high]
keywords: [连接池饱和, connection pool, pool wait]
severities: [HIGH, CRITICAL]
labels:
  trial_channel: qq
manual_group: qq-trial-database-alerts
test_only: true
---

> 仅用于 QQ 通知和手册匹配试运行，不是生产手册。所有检查均为只读，任何配置或实例变更都必须由值班人员审批。

适用信号：`pool_saturation`、`pool_wait_queue_high`。

1. 核对连接池活跃连接数、池上限、等待队列、等待时长和异常持续时间。
2. 按应用实例和调用来源检查连接占用分布，确认异常是否集中在单一版本、机房或流量入口。
3. 对比同期请求量、错误率、超时率和最近的连接池配置变更记录，保留可复核证据。
4. 确认数据库服务端连接余量，区分应用连接池饱和与数据库连接上限告警。
5. 若等待队列持续增长或业务请求已经失败，通知应用负责人和值班 DBA，由人工评估处置方案。

预期证据：连接池指标、等待队列趋势、来源分布、服务端连接余量和近期变更记录。
