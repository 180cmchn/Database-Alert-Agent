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
5. 将 `sql_instance` 返回的真实 host 和 port 严格组合为 host:port，作为 `mysql_slow_query_review_history.hostname_max` 的等值条件；确认 history 表的 `hostname_max`、`id`、`Query_time_max`、`Query_time_sum`、`sample` 和时间字段后，先查询固定投影 `id, Query_time_max, Query_time_sum`。查询必须包含 `hostname_max` 等值条件和第 8 条的完整时间范围，使用 `ORDER BY id DESC` 和不超过 100 的 `LIMIT`，并设置 `max_result_chars = 12000`。Host 在首次查询后接管分页、sample 恢复和补充分析，模型不得自行重复这些机械调用。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.list_ids -->
6. 排名投影使用 `id` keyset 物理分页；Host 固定首次最大 id，后续页使用 `id < 上一页末 id`，禁止 OFFSET。完整取得排名行后，再以相同 hostname、时间范围、快照上界和 keyset 顺序查询程序固定的紧凑字段，并包含 `LENGTH(sample) AS sample_full_length`。两个逻辑扫描的 id 集合必须一致；不一致时只保留可验证交集并标记 `history_snapshot_inconsistent`。所有页完成后，分别按 `Query_time_max` 和 `Query_time_sum` 降序取前 `ceil(N * 20%)`，截止位用 id 降序打破并列，两套结果取并集作为高优先级队列，其余 id 随后处理。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.fetch_single_id -->
紧凑扫描完成后，Host 按高优先级并集在前、普通记录在后的顺序处理所有 id。`sample_full_length <= 12000` 时执行受限的 `SELECT sample FROM mysql_slow_query_review_history WHERE id = X`；长度更大或直接 sample 结果仍被截断时，改用 Host 生成的 `SUBSTRING(sample, offset, size) AS sample_chunk` 分片。禁止清单外 id，offset 和 size 禁止由模型提供。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.retry_high_limit -->
所有 sample 分片调用固定使用 `max_result_chars = 12000`。初始 size 根据该响应上限扣除信封余量后设置，以减少调用次数；单片仍被截断时 Host 自动减半 size。每片必须核验实际 SQL、唯一行、顺序和完整性，最终重组 UTF-8 字节长度必须精确等于 `LENGTH(sample) AS sample_full_length`，否则不得作为完整 sample 或 EXPLAIN 输入。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.project_sample_prefix -->
重组后的原始完整 sample 只在 Host 内部用于语法校验和普通 EXPLAIN。主 Agent 的字段级结构投影中，12000 字节以内的 sample 保留全文；超长 sample 投影为不超过 12000 字符的结构化 SQL。普通 literal `IN`/`NOT IN` 同时保留头尾尽可能多的真实值及原始、保留、省略数量；`IN (SELECT ...)` 不压缩。非 IN 原因导致的超长 SQL保留有界头尾结构。结构化 SQL仅用于降低 Agent 上下文，不得替代原始 SQL成为 EXPLAIN 输入；始终保留原文长度和 SHA-256 绑定。
<!-- /directive -->
<!-- directive:id=archery.history.complete_before_supplemental -->
7. 两个逻辑扫描完整且 id 集一致后，紧凑 history 即构成独立基础慢日志证据，不要求所有 sample/EXPLAIN 完成后才保留。Host 在内部调查预算内按优先队列逐条恢复 sample、绑定目标、查询字段和索引并执行 EXPLAIN；预算到期时保留所有紧凑行和已完成补充结果，明确列出未完成 id，不得降级为通用 TIMEOUT。
<!-- /directive -->
<!-- directive:id=archery.history.time_bounds -->
8. 若表中存在 `ts_min`、`ts_max`，它们分别表示聚合记录首次与末次发生时间，可用 `ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'` 判断窗口重叠，且必须为 `ts_min` 补充下界。完整条件为 `ts_min >= '<ts_min_lower_bound_beijing>' AND ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'`。禁止只有 `ts_min < 窗口结束` 的开放范围；其它字段依据真实名称和类型构造时间条件，不得改变告警窗口，时区为北京时间。
<!-- /directive -->
<!-- directive:id=archery.supplemental.sample_selection -->
9. Host 对每个已重组且可由普通 EXPLAIN 安全分析的单语句 sample 保留 history `id`、目标、checksum、原始 SQL SHA-256 和结构化展示 SQL。高优先级并集先处理，其余记录随后处理，直到全部完成或内部预算到期。相同业务实例、数据库和 checksum 的计划可复用并绑定到对应 history id，避免重复远端执行。可分析类型包括 SELECT、WITH 形式，以及目标 MySQL/TiDB 版本支持普通 EXPLAIN 的 INSERT、UPDATE、DELETE 和 REPLACE。DDL、CALL、存储过程、事务/管理语句、已有 EXPLAIN、无法可靠识别的语句和多语句 SQL不可分析。
<!-- /directive -->
<!-- directive:id=archery.supplemental.target_binding -->
10. 使用 history 行的 `hostname_max` 与 MCP 返回的真实 allowlist 实例 host:port 严格匹配，取得业务实例的真实 `instance_id`。同一调查中第 3 步已经成功返回的结构化 allowlist 行可以复用；无筛选调用返回的“实例清单（第 N 页）”编号文本只是实例目录，不是执行授权，必须使用目录中的精确名称或 ID 作为 `instance_ref` 再查询一次，只有该定向查询成功返回的明确 ID、host、port 才可用于绑定。实例 allowlist 只授权下一步数据库发现；仍必须使用该行的 `db_max` 作为业务数据库，并确认该库存在于该实例随后真实返回的数据库清单中，数据库清单确认前不得执行任何业务目标 SQL。sample 中若存在显式 schema，其名称必须与 `db_max` 精确一致；CTE 内物理表和 DML 目标表也适用。实例、host:port、数据库或显式 schema 任一无法严格匹配时，保留真实错误，不得改用 Archery 元数据库、猜测其它目标或开始该 sample 的补充查询。
<!-- /directive -->
<!-- directive:id=archery.supplemental.table_structure -->
11. 在第 10 条确认的业务实例和 `db_max` 中，先读取 sample 引用的真实表和字段。表结构优先使用 `information_schema.COLUMNS`；也可使用 MCP 的 `list_table_columns`。不得猜测表或字段。只有字段结构已成功取得，或该阶段的失败已如实记录后，才可继续普通 EXPLAIN。
<!-- /directive -->
<!-- directive:id=archery.supplemental.explain -->
12. 对每个选中的 sample 只可调用 `EXPLAIN <完整原始 sample>`；EXPLAIN 内层 SQL 必须与 Host 分片重组并通过长度和 SHA-256 绑定的原始 sample 精确对应。不得使用结构化展示 SQL、压缩后的 IN 列表、前后缀或任何其它改写作为 EXPLAIN 输入。完整原 SQL只进入内部 MCP 调用与审计，不进入 Agent 消息。普通 EXPLAIN 可以包裹 SELECT、WITH 形式和目标引擎支持的 DML，但绝不能直接执行任何 history sample，包括 SELECT 或 WITH 查询。禁止 `EXPLAIN ANALYZE`，也禁止 DML、DDL、存储过程、多语句 SQL或任何其它有副作用的直接调用。
<!-- /directive -->
<!-- directive:id=archery.supplemental.indexes_and_scope -->
13. 索引优先查询 `information_schema.STATISTICS`，避免 `SHOW INDEX` 被 MCP 自动追加 LIMIT 后产生语法错误。结构和索引条件必须使用第 10、11 条得到的真实数据库及表名。从 history 恢复开始到补充阶段结束，调用范围只允许：history 恢复查询、严格目标解析、真实表字段/索引元数据查询，以及已绑定 sample 的普通 EXPLAIN。不得直接执行 sample，也不得调用任意业务 SELECT、其它管理语句或与本次调查无关的探测。
<!-- /directive -->
<!-- directive:id=archery.supplemental.response_binding -->
14. 收集补充结果时，必须使用 MCP 返回中的实际执行 SQL 和实际目标与请求、绑定 sample 及第 10 条目标进行核对。对于原请求不含顶层 `LIMIT` 的单一 `SELECT`，若唯一差异是 MCP 在语句末尾自动追加 `LIMIT N`，且 `N` 与该次调用显式提交的 `limit_num` 精确一致，这是已声明的 provider 结果限流，不视为 SQL 不一致；该例外不适用于已有顶层 `LIMIT` 的请求、`EXPLAIN` 或任何其它改写。若返回明确回显的 SQL、物理 schema/表名、`instance_id`、host:port 或数据库存在其它不一致，不得将该结果投影为该 history sample 的 EXPLAIN、表结构或索引事实；将不一致记录为对应补充阶段的证据缺口。
<!-- /directive -->
<!-- directive:id=archery.supplemental.failure_isolation -->
15. EXPLAIN、目标解析、表结构、索引或第 14 条核对失败时，不要丢弃、替换、修改或降级已经取得的 history。继续尝试其它仍安全且有价值的允许阶段，并保留真实 `stage`、`target`、错误类型、reason code 和错误详情。权限、allowlist、表不存在、目标版本不支持 EXPLAIN、sample 解析失败或结果核对失败都只是补充分析缺口，不得改变 history 的状态、内容、可用性或根因资格。
<!-- /directive -->
<!-- directive:id=archery.history.error_or_empty_completion -->
16. 窗口查询超时或报错时，依据真实错误、字段和索引信息调整下一次 history 查询，不要原样重复无效调用。没有匹配 history 记录时如实返回空结果；不得把告警标题中的端点替代 `hostname_max`，不得虚构日志、执行计划、表结构或索引。完成所有可安全尝试的允许补充阶段后结束 Archery 调查。
<!-- /directive -->
