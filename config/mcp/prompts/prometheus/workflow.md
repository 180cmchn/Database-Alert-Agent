1. 使用 target discovery、服务发现目标、标签、抓取地址、job、指标目录或元数据，先确认 Prometheus MCP 中实际配置了哪些数据库及数据库目标的监控指标。不能仅凭 MCP 名称、经验或筛选后的空结果推断监控范围。
2. 使用 FlashDuty 告警详情中的数据库身份、alarm_host 和 alarm_port 与发现到的监控目标进行匹配；不得从告警标题推断 host 或 port。
3. 若告警数据库在已确认的监控范围内，选择与告警信号最相关的指标，查询 [occurred_at - 5 分钟, occurred_at] 时间窗口。范围查询的 start 和 end 必须由 Host 绑定到该精确窗口，不得改用即时查询或其它时间范围。
4. 若告警数据库不在已确认的监控范围内，不再执行范围查询，返回 reason_code=database_not_monitored，并明确说明“Prometheus MCP 中没有配置告警数据库对应的监控信息”。该结果表示工具不适用，不表示其它可用证据不足。
5. 若发现结果不足以确认范围，明确返回无法确认监控范围；不得虚构指标、目标或查询结果。

根据 MCP 动态发现的工具 Schema 自主选择调用，每轮只调用一个工具。target_discovery 和 catalog 结果只用于确认监控归属、指标、标签和元数据，本身不是告警窗口实时证据。若同时提供即时查询和范围查询，必须选择 capability=range_query；不得用当前时刻即时结果或其它时段数据作为本次告警证据。

范围查询必须使用 required_target 中来自 FlashDuty 告警详情的引擎、集群、alarm_host 和 alarm_port 约束 PromQL，不得用未限定目标的跨集群聚合结果或其它数据库、集群、引擎的数据替代。若 Host 标记 target_verification=mismatch，只允许修正指标或标签后在 Host 允许的次数内重试；仍不匹配时停止并报告未取得告警目标证据。

发现指标、标签或能力后，立即使用与告警信号最相关的范围查询。除非上一次调用报错、参数已改变或结果要求分页，不得重复同一工具和相同参数，也不得反复枚举完整指标目录。目录指标必须与告警信号语义相关，例如慢查询告警需要 slow/query 语义，不能把仅共享 mysql 前缀的采集链路指标当作替代证据。达到 Host contract 的空范围查询上限后停止，不得继续猜测指标。

调用预算有限，catalog 调用不得耗尽为 range_query 保留的额度；每轮以 Host 返回的已用和剩余数为准。取得足够监控返回后调用 Host contract 指定的 finish_tool 结束调查。
