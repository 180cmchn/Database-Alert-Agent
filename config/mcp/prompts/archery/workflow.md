<!-- directive:id=archery.alert.scope -->
1. 只使用 FlashDuty 告警详情中的 `alarm_host` 和 `alarm_port` 作为告警端点，调查窗口固定为告警发生前五分钟至告警发生时。字段缺失时如实说明。
<!-- /directive -->
<!-- directive:id=archery.tools.dynamic_contract -->
2. 按 MCP 动态发现的工具描述和 Schema 自主选择调用，每次调用后根据真实返回决定下一步。若发现认证工具，根据当前会话状态自主判断是否调用；Host 不会预先调用或隐藏固定认证工具。实例 ID、数据库、表和字段必须来自工具返回，不猜测部署结构。
<!-- /directive -->
<!-- directive:id=archery.metadata.archery_target -->
3. 先用 MCP 发现 allowlist 中的 Archery 实例及 Archery 数据库；记下其真实 MCP `instance_id`。在后续 Archery 元数据与 history 查询中必须使用该实例 `instance_id` 和 `db_name = archery`。
<!-- /directive -->
<!-- directive:id=archery.metadata.alert_endpoint_mapping -->
4. 查询 `t_instance_member` 的真实字段，查询条件使用告警详情的 `alarm_host`、`alarm_port` 等值于 `f_ip`、`f_port`，取得 `f_instance_id`；再查询 `sql_instance`，在 SQL 的 WHERE 条件中以 `f_instance_id` 的值等值于 `id` 查询真实 host 和 port。
<!-- /directive -->
<!-- directive:id=archery.history.window_query -->
5. 将 `sql_instance` 返回的真实 host 和 port 严格组合为 host:port，作为 `mysql_slow_query_review_history.hostname_max` 的等值条件；确认 history 表的 `hostname_max` 和时间字段，再在 Archery 实例和 `db_name=archery` 中用 `hostname_max` 等值条件和告警时间范围条件共同查询慢查询日志，排序条件用 `ORDER BY id DESC`，两类 WHERE 条件缺一不可。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.list_ids -->
6. 若 Archery MCP 返回的 history window 结果因内容过长被截断或无法确认完整性，则先执行一次 `SELECT id FROM ...`；该查询仍需包含第 8 条的完整时间范围条件和 `hostname_max` 等值条件。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.fetch_single_id -->
取得完整 id 清单后，按清单真实返回的每个 id 分别执行 `SELECT * FROM mysql_slow_query_review_history WHERE id = X`。禁止查询清单外 id，禁止多 id 合并为 IN 查询。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.retry_high_limit -->
若单 id 查询因内容过长被截断或无法确认完整性，则用相同 SQL 重试一次并显式传 `max_result_chars = 24000`。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.project_sample_prefix -->
若提高 `max_result_chars` 后单 id 结果仍被截断或无法确认完整性，按程序提供的字段清单保留常规字段，并将 sample 投影为 `LEFT(sample, '4000') AS sample`，同时增加 `LENGTH(sample) AS sample_full_length`。字段级恢复的 sample 只是带完整长度标记的前缀，可作为 history 证据，但不是完整 SQL，绝不能进入 EXPLAIN。
<!-- /directive -->
<!-- directive:id=archery.history.complete_before_supplemental -->
7. 查询 `mysql_slow_query_review_history` 时，除只查 id 和程序提示的字段级截断恢复外，均使用 `SELECT * FROM ...`，避免遗漏字段。完整恢复所有 history 行后不要立即结束调查；history 始终是独立的基础慢日志证据。
<!-- /directive -->
<!-- directive:id=archery.history.time_bounds -->
8. 若表中存在 `ts_min`、`ts_max`，它们分别表示聚合记录首次与末次发生时间，可用 `ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'` 判断窗口重叠，且必须为 `ts_min` 补充下界。完整条件为 `ts_min >= '<ts_min_lower_bound_beijing>' AND ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'`。禁止只有 `ts_min < 窗口结束` 的开放范围；其它字段依据真实名称和类型构造时间条件，不得改变告警窗口，时区为北京时间。
<!-- /directive -->
<!-- directive:id=archery.supplemental.sample_selection -->
9. history 成功后，从结果中选择可由普通 EXPLAIN 安全分析的单语句 sample，并保留其 history `id`、`checksum` 和原始 `sample` 作为绑定依据。优先 `Query_time_max` 较高的记录，相同指标时优先较新的 id；相同 checksum 不重复分析。可分析类型包括 SELECT、WITH 形式，以及目标 MySQL/TiDB 版本支持普通 EXPLAIN 的 INSERT、UPDATE、DELETE 和 REPLACE。DDL、CALL、存储过程、事务/管理语句、已有 EXPLAIN、无法可靠识别的语句和多语句 SQL 不可分析。
<!-- /directive -->
<!-- directive:id=archery.supplemental.target_binding -->
10. 使用 history 行的 `hostname_max` 与 MCP 返回的真实 allowlist 实例 host:port 严格匹配，取得业务实例的真实 `instance_id`；使用该行的 `db_max` 作为业务数据库，并确认该库存在于该实例的真实返回中。sample 中若存在显式 schema，其名称必须与 `db_max` 精确一致；CTE 内物理表和 DML 目标表也适用。实例、host:port、数据库或显式 schema 任一无法严格匹配时，保留真实错误，不得改用 Archery 元数据库、猜测其它目标或开始该 sample 的补充查询。
<!-- /directive -->
<!-- directive:id=archery.supplemental.table_structure -->
11. 在第 10 条确认的业务实例和 `db_max` 中，先读取 sample 引用的真实表和字段。表结构优先使用 `information_schema.COLUMNS`；也可使用 MCP 的 `list_table_columns`。不得猜测表或字段。只有字段结构已成功取得，或该阶段的失败已如实记录后，才可继续普通 EXPLAIN。
<!-- /directive -->
<!-- directive:id=archery.supplemental.explain -->
12. 对每个选中的 sample 只可调用 `EXPLAIN <sample>`；EXPLAIN 内层 SQL 必须与第 9 条绑定的原始 sample 对应，不得改写、替换或扩展为其它语句。普通 EXPLAIN 可以包裹 SELECT、WITH 形式和目标引擎支持的 DML，但绝不能直接执行任何 history sample，包括 SELECT 或 WITH 查询。禁止 `EXPLAIN ANALYZE`，因为它会实际执行内层语句；也禁止 DML、DDL、存储过程、多语句 SQL 或任何其它有副作用的直接调用。
<!-- /directive -->
<!-- directive:id=archery.supplemental.indexes_and_scope -->
13. 索引优先查询 `information_schema.STATISTICS`，避免 `SHOW INDEX` 被 MCP 自动追加 LIMIT 后产生语法错误。结构和索引条件必须使用第 10、11 条得到的真实数据库及表名。从 history 恢复开始到补充阶段结束，调用范围只允许：history 恢复查询、严格目标解析、真实表字段/索引元数据查询，以及已绑定 sample 的普通 EXPLAIN。不得直接执行 sample，也不得调用任意业务 SELECT、其它管理语句或与本次调查无关的探测。
<!-- /directive -->
<!-- directive:id=archery.supplemental.response_binding -->
14. 收集补充结果时，必须使用 MCP 返回中的实际执行 SQL 和实际目标与请求、绑定 sample 及第 10 条目标进行核对。若返回明确回显的 SQL、物理 schema/表名、`instance_id`、host:port 或数据库与绑定内容不一致，不得将该结果投影为该 history sample 的 EXPLAIN、表结构或索引事实；将不一致记录为对应补充阶段的证据缺口。
<!-- /directive -->
<!-- directive:id=archery.supplemental.failure_isolation -->
15. EXPLAIN、目标解析、表结构、索引或第 14 条核对失败时，不要丢弃、替换、修改或降级已经取得的 history。继续尝试其它仍安全且有价值的允许阶段，并保留真实 `stage`、`target`、错误类型、reason code 和错误详情。权限、allowlist、表不存在、目标版本不支持 EXPLAIN、sample 解析失败或结果核对失败都只是补充分析缺口，不得改变 history 的状态、内容、可用性或根因资格。
<!-- /directive -->
<!-- directive:id=archery.history.error_or_empty_completion -->
16. 窗口查询超时或报错时，依据真实错误、字段和索引信息调整下一次 history 查询，不要原样重复无效调用。没有匹配 history 记录时如实返回空结果；不得把告警标题中的端点替代 `hostname_max`，不得虚构日志、执行计划、表结构或索引。完成所有可安全尝试的允许补充阶段后结束 Archery 调查。
<!-- /directive -->
