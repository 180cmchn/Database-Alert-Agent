1. 只使用 FlashDuty 告警详情中的 `alarm_host` 和 `alarm_port` 作为告警端点，调查窗口固定为告警发生前五分钟至告警发生时。字段缺失时如实说明。
2. 按 MCP 动态发现的工具描述和 Schema 自主选择调用，每次调用后根据真实返回决定下一步。若发现认证工具，根据当前会话状态自主判断是否调用；Host 不会预先调用或隐藏固定认证工具。实例 ID、数据库、表和字段必须来自工具返回，不猜测部署结构。
3. 先用 MCP 发现 allowlist 中的 Archery 实例及 Archery 数据库；记下其真实 MCP `instance_id`。在后续 Archery 元数据与 history 查询中必须使用该实例 `instance_id` 和 `db_name = archery`。
4. 查询 `t_instance_member` 的真实字段，查询条件使用告警详情的 `alarm_host`、`alarm_port` 等值于 `f_ip`、`f_port`，取得 `f_instance_id`；再查询 `sql_instance`，在 SQL 的 WHERE 条件中以 `f_instance_id` 的值等值于 `id` 查询真实 host 和 port。
5. 将 `sql_instance` 返回的真实 host 和 port 严格组合为 host:port，作为 `mysql_slow_query_review_history.hostname_max` 的等值条件；确认 history 表的 `hostname_max` 和时间字段，再在 Archery 实例和 `db_name=archery` 中用 `hostname_max` 等值条件和告警时间范围条件共同查询慢查询日志，排序条件用 `ORDER BY id DESC`，两类 WHERE 条件缺一不可。
6. 若 Archery MCP 返回结果因内容过长被截断，则先执行一次 `SELECT id FROM ...`（仍需包含第 8 条的完整时间范围条件和 `hostname_max` 等值条件），再按每个 id 分别执行 `SELECT * FROM mysql_slow_query_review_history WHERE id = X`，禁止多 id 合并为 IN 查询。若单 id 查询仍被截断，则用相同 SQL 重试一次并显式传 `max_result_chars = 24000`；若仍截断，按程序提示使用保留常规字段并将 sample 投影为 `LEFT(sample, '4000') AS sample` 的字段级查询。
7. 查询 `mysql_slow_query_review_history` 时，除只查 id 和程序提示的字段级截断恢复外，均使用 `SELECT * FROM ...`，避免遗漏字段。完整恢复所有 history 行后不要立即结束调查；history 始终是独立的基础慢日志证据。
8. 若表中存在 `ts_min`、`ts_max`，它们分别表示聚合记录首次与末次发生时间，可用 `ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'` 判断窗口重叠，且必须为 `ts_min` 补充下界。完整条件为 `ts_min >= '<ts_min_lower_bound_beijing>' AND ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'`。禁止只有 `ts_min < 窗口结束` 的开放范围；其它字段依据真实名称和类型构造时间条件，不得改变告警窗口，时区为北京时间。
9. history 成功后，从结果中选择可由普通 EXPLAIN 安全分析的单语句 sample。优先 `Query_time_max` 较高的记录，相同指标时优先较新的 id；相同 checksum 不重复分析。可分析类型包括 SELECT，以及目标 MySQL/TiDB 版本支持普通 EXPLAIN 的 INSERT、UPDATE、DELETE、REPLACE 和对应 WITH 形式。DDL、CALL、存储过程、事务/管理语句、已有 EXPLAIN、无法可靠识别的语句和多语句 SQL 不可分析。
10. 使用 history 行的 `hostname_max` 与 MCP 返回的真实 allowlist 实例 host:port 严格匹配，取得业务实例的真实 `instance_id`；使用该行的 `db_max` 作为业务数据库。实例或数据库不在 allowlist 时保留真实错误，不得改用 Archery 元数据库或猜测其它目标。
11. 在业务实例和 `db_max` 中先读取 sample 引用的真实表和字段。表结构优先使用 `information_schema.COLUMNS`；也可使用 MCP 的 `list_table_columns`。不得猜测表或字段。
12. 对每个选中的 sample 只执行 `EXPLAIN <sample>`。普通 EXPLAIN 可以包裹受支持的 DML，但绝不能执行 sample 本身。禁止 `EXPLAIN ANALYZE`，因为它会实际执行内层语句；也禁止 DML、DDL、存储过程、多语句 SQL 或任何其它有副作用的直接调用。
13. 索引优先查询 `information_schema.STATISTICS`，避免 `SHOW INDEX` 被 MCP 自动追加 LIMIT 后产生语法错误。结构和索引条件必须使用第 10、11 条得到的真实数据库及表名。
14. EXPLAIN、目标解析、表结构或索引调用失败时，不要丢弃、替换或修改已经取得的 history。继续尝试其它仍安全且有价值的补充阶段，并保留真实 `stage`、`target`、错误类型、reason code 和错误详情。权限、allowlist、表不存在、目标版本不支持 EXPLAIN 或 sample 解析失败都只是补充分析缺口。
15. 窗口查询超时或报错时，依据真实错误、字段和索引信息调整下一次 history 查询，不要原样重复无效调用。没有匹配 history 记录时如实返回空结果；不得把告警标题中的端点替代 `hostname_max`，不得虚构日志、执行计划、表结构或索引。完成所有可安全尝试的补充阶段后结束 Archery 调查。