1. 只使用 FlashDuty 告警详情中的 `alarm_host` 和 `alarm_port` 作为告警端点，调查窗口固定为 `[occurred_at - 5 分钟, occurred_at]`。字段缺失时如实说明，不得从标题推断或补全。
2. 按 MCP 动态发现的工具描述和 Schema 自主选择调用，每次调用后根据真实返回决定下一步。若发现认证工具，根据当前会话状态自主判断是否调用；Host 不会预先调用或隐藏固定认证工具。实例 ID、数据库、表和字段必须来自工具返回，不猜测部署结构。
3. 先发现包含 Archery 数据库的实例，记录真实 `instance_id` 和 `db_name=archery`。在后续元数据与查询调用中沿用该实例和数据库。
4. 查询 `t_instance_member` 的真实字段，使用告警详情的 `alarm_host`、`alarm_port` 定位成员并取得 `f_instance_id`；再查询 `archery.sql_instance`，用该 ID 取得慢日志记录使用的真实 host 与 port。
5. 将上一步真实 host、port 组合成 `hostname_max`，确认 `archery.mysql_slow_query_review_history` 的真实字段和时间字段，然后同时按 `hostname_max` 与五分钟窗口查询慢查询记录。最终结果应包含 `hostname_max` 以及时间、数据库、用户、checksum、sample、执行次数、耗时等实际存在且有分析价值的字段。
6. 若表中存在 `ts_min`、`ts_max`，它们分别表示聚合记录首次与末次发生时间，可用 `ts_min < 窗口结束 AND ts_max >= 窗口开始` 判断窗口重叠。其它字段应依据其真实名称和类型构造时间条件，不得改变告警窗口或丢失时区。
7. 若窗口查询超时或报错，依据真实错误、字段和索引信息调整下一次查询；不要原样重复无效调用。没有匹配记录或链路无法完成时，如实返回空结果或错误，不得把告警标题中的端点替代 `hostname_max`，也不得虚构日志。
8. 成功取得 `mysql_slow_query_review_history` 结果后结束 Archery 调查。登录、实例成员解析、表结构和索引等辅助响应只作为内部审计 artifact 保存；只有最终 history 查询结果经过程序侧过滤、聚合和排序后进入主 Agent 上下文。
