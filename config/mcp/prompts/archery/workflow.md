<!-- directive:id=archery.alert.scope -->
1. 只使用 FlashDuty 告警详情中的 `alarm_host` 和 `alarm_port` 作为告警端点，调查窗口固定为告警发生前五分钟至告警发生时。字段缺失时如实说明。
<!-- /directive -->
<!-- directive:id=archery.tools.dynamic_contract -->
2. 按 MCP 动态发现的工具描述和 Schema 自主选择调用，每次调用后根据真实返回决定下一步。若发现认证工具，根据当前会话状态自主判断是否调用；Host 不会预先调用或隐藏固定认证工具。实例 ID、数据库、表和字段必须来自工具返回，不猜测部署结构。
<!-- /directive -->
<!-- directive:id=archery.metadata.archery_target -->
3. 先用 MCP 发现 Archery 实例及 Archery 数据库；记下其真实 MCP `instance_id`。在后续 Archery 元数据与 history 查询中必须使用该实例 `instance_id` 和 `db_name = archery`。
<!-- /directive -->
<!-- directive:id=archery.metadata.alert_endpoint_mapping -->
4. 查询 `t_instance_member` 的真实字段，查询条件使用告警详情的 `alarm_host`、`alarm_port` 等值于 `f_ip`、`f_port`，取得 `f_instance_id`；再查询 `sql_instance`，在 SQL 的 WHERE 条件中以 `f_instance_id` 的值等值于 `id` 查询真实 host 和 port。
<!-- /directive -->
<!-- directive:id=archery.history.window_query -->
5. 将 `sql_instance` 返回的真实 host 和 port 严格组合为 host:port，作为 `mysql_slow_query_review_history.hostname_max` 的等值条件；确认 history 表的全部真实字段，至少包含 `hostname_max`、`id`、`Query_time_max`、`Query_time_sum`、`sample` 和时间字段后，先查询固定排名投影 `id, Query_time_max, Query_time_sum`。查询必须包含 `hostname_max` 等值条件和第 8 条的完整时间范围，并使用 `ORDER BY id DESC`，同时设置 `max_result_chars = 12000`。普通顶层 `LIMIT` 可省略或使用任意值；其存在与数值只作为结果分页信息，不参与 SQL 身份、目标绑定或本地拒绝判定。Host 在首次查询后接管分页、完整行恢复和补充分析，模型不得自行重复这些机械调用。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.list_ids -->
6. 排名投影使用 `id` keyset 物理分页；Host 固定首次最大 id，后续页使用 `id < 上一页末 id`，禁止 OFFSET。完整取得排名行后，再以相同 hostname、时间范围、快照上界和 keyset 顺序查询 schema 中全部非 `sample` 字段，并包含 `LENGTH(sample) AS __history_sample_octet_length`。两个逻辑扫描的 id 集合必须一致；不一致、字段缺失、分页失败或快照无法证明一致时，已收到内容只作为不完整内部 artifact 保留，不得标记 History 成功或用于根因。所有页完成后，分别按 `Query_time_max` 和 `Query_time_sum` 降序取前 `ceil(N * 20%)`，截止位用 id 降序打破并列，两套结果取并集，只决定内部 sample 恢复顺序；最终 History 行必须按查询的 `id DESC` 顺序输出。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.fetch_single_id -->
完整非 sample 字段扫描完成后，Host 按高优先级并集在前、普通记录在后的内部顺序恢复所有 id 的精确 `sample`。`__history_sample_octet_length <= 12000` 时执行受限的 `SELECT sample FROM mysql_slow_query_review_history WHERE id = X`；长度更大或直接 sample 结果仍被截断时，改用 Host 生成的 `SUBSTRING(sample, offset, size) AS sample_chunk` 分片。禁止清单外 id，offset 和 size 禁止由模型提供。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.retry_high_limit -->
所有 sample 分片调用固定使用 `max_result_chars = 12000`。初始 size 根据该响应上限扣除信封余量后设置，以减少调用次数；单片仍被截断时 Host 自动减半 size。每片必须核验实际 SQL、唯一行、顺序和完整性，最终重组 UTF-8 字节长度必须精确等于 `LENGTH(sample) AS __history_sample_octet_length`，否则不得标记该 History 行完整，也不得作为 EXPLAIN 输入。
<!-- /directive -->
<!-- directive:id=archery.history.truncation.project_sample_prefix -->
重组后的原始完整 sample 必须作为该 history 行的真实 `sample` 字段原样进入最终 History；不得截断、压缩、规范化空白、改写 SQL、替换 IN 列表或设置最终字段大小上限。Host 可在内部用长度、SHA-256、语法分类和表引用核验重组与 EXPLAIN 绑定，但这些恢复元数据不得注入业务 History 行。最终 History 只允许 JSON 格式转换和既有秘密净化，业务字段名即使为 `raw`、`request_id`、`usage`、`hash` 或其它 provenance 同名词也必须保留。
<!-- /directive -->
<!-- directive:id=archery.history.complete_before_supplemental -->
7. 只有两个逻辑扫描完整、id 集一致、每个 schema 字段均存在且每个 sample 都精确恢复后，History 才构成可供主 Agent 和根因引用的独立慢日志证据。Host 必须先完成全部 History 行，再按内部优先队列运行目标绑定、字段、索引和 EXPLAIN 等 supplemental 分析。History 恢复在预算、deadline、分页、字段或分片上失败时必须 fail closed：保留已收到内容和内部 artifact，显式标记 History 不完整且不可用于根因，不运行 supplemental。History 已完整而 supplemental 未完成时，完整 History 保持成功且内容不变，只将 supplemental 标记为 partial/failed。
<!-- /directive -->
<!-- directive:id=archery.history.time_bounds -->
8. 若表中存在 `ts_min`、`ts_max`，它们分别表示聚合记录首次与末次发生时间，可用 `ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'` 判断窗口重叠，且必须为 `ts_min` 补充下界。完整条件为 `ts_min >= '<ts_min_lower_bound_beijing>' AND ts_min < '<end_beijing>' AND ts_max >= '<start_beijing>'`。禁止只有 `ts_min < 窗口结束` 的开放范围；其它字段依据真实名称和类型构造时间条件，不得改变告警窗口，时区为北京时间。
<!-- /directive -->
<!-- directive:id=archery.supplemental.sample_selection -->
9. Host 对每个已重组且可由普通 EXPLAIN 安全分析的单语句 sample 保留内部 history `id`、目标、checksum、原始 SQL SHA-256 和语句分类；这些 Host 恢复元数据不进入业务 History 行。高优先级并集先处理，其余记录随后处理，直到全部完成或内部预算到期。相同业务实例、数据库和 checksum 的计划可复用并绑定到对应 history id，避免重复远端执行。可分析类型包括 SELECT、WITH 形式，以及目标 MySQL/TiDB 版本支持普通 EXPLAIN 的 INSERT、UPDATE、DELETE 和 REPLACE。DDL、CALL、存储过程、事务/管理语句、已有 EXPLAIN、无法可靠识别的语句和多语句 SQL不可分析。
<!-- /directive -->
<!-- directive:id=archery.supplemental.target_binding -->
10. 使用 history 行的 `hostname_max` 与 MCP 返回的真实 allowlist 实例 host:port 严格匹配，取得业务实例的真实 `instance_id`。同一调查中第 3 步已经成功返回的结构化 allowlist 行可以复用；无筛选调用返回的“实例清单（第 N 页）”编号文本只是实例目录，不是执行授权，必须使用目录中的精确名称或 ID 作为 `instance_ref` 再查询一次，只有该定向查询成功返回的明确 ID、host、port 才可用于绑定。实例 allowlist 只授权下一步数据库发现；仍必须使用该行的 `db_max` 作为业务数据库，并确认该库存在于该实例随后真实返回的数据库清单中，数据库清单确认前不得执行任何业务目标 SQL。sample 中若存在显式 schema，其名称必须与 `db_max` 精确一致；CTE 内物理表和 DML 目标表也适用。实例、host:port、数据库或显式 schema 任一无法严格匹配时，保留真实错误，不得改用 Archery 元数据库、猜测其它目标或开始该 sample 的补充查询。
<!-- /directive -->
<!-- directive:id=archery.supplemental.table_structure -->
11. 在第 10 条确认的业务实例和 `db_max` 中，先读取 sample 引用的真实表和字段。表结构优先使用 `information_schema.COLUMNS`；也可使用 MCP 的 `list_table_columns`。不得猜测表或字段。只有字段结构已成功取得，或该阶段的失败已如实记录后，才可继续普通 EXPLAIN。
<!-- /directive -->
<!-- directive:id=archery.supplemental.explain -->
12. 对每个选中的 sample 只可调用 `EXPLAIN <完整原始 sample>`；EXPLAIN 内层 SQL 必须与 Host 分片重组并通过长度和内部 SHA-256 绑定的原始 sample 精确对应。不得使用前后缀、压缩后的 IN 列表或任何其它改写作为 EXPLAIN 输入。完整原 SQL作为业务 History 的 `sample` 字段无损进入主 Agent；内部重组 hash、请求信封和审计 provenance 不进入 Agent 消息。普通 EXPLAIN 可以包裹 SELECT、WITH 形式和目标引擎支持的 DML，但绝不能直接执行任何 history sample，包括 SELECT 或 WITH 查询。禁止 `EXPLAIN ANALYZE`，也禁止 DML、DDL、存储过程、多语句 SQL或任何其它有副作用的直接调用。
<!-- /directive -->
<!-- directive:id=archery.supplemental.indexes_and_scope -->
13. 索引优先查询 `information_schema.STATISTICS`，避免 `SHOW INDEX` 被 MCP 自动追加 LIMIT 后产生语法错误。结构和索引条件必须使用第 10、11 条得到的真实数据库及表名。从 history 恢复开始到补充阶段结束，调用范围只允许：history 恢复查询、严格目标解析、真实表字段/索引元数据查询，以及已绑定 sample 的普通 EXPLAIN。不得直接执行 sample，也不得调用任意业务 SELECT、其它管理语句或与本次调查无关的探测。
<!-- /directive -->
<!-- directive:id=archery.supplemental.response_binding -->
14. 收集补充结果时，必须使用 MCP 返回中的实际执行 SQL 和实际目标与请求、绑定 sample 及第 10 条目标进行核对。对任意受支持 SQL，普通顶层末尾 `LIMIT` 的存在与数值都不参与 SQL 身份核对，也不要求与调用参数 `limit_num` 一致；这适用于原请求已有 `LIMIT`、没有 `LIMIT`、普通 `EXPLAIN` 及受支持 DML。`OFFSET`、嵌套 `LIMIT` 和任何其它改写仍保持原始语义。若返回明确回显的 SQL 在这些非 `LIMIT` 部分、物理 schema/表名、`instance_id`、host:port 或数据库存在其它不一致，不得将该结果投影为该 history sample 的 EXPLAIN、表结构或索引事实；将不一致记录为对应补充阶段的证据缺口。
<!-- /directive -->
<!-- directive:id=archery.supplemental.failure_isolation -->
15. EXPLAIN、目标解析、表结构、索引或第 14 条核对失败时，不要丢弃、替换、修改或降级已经取得的 history。继续尝试其它仍安全且有价值的允许阶段，并保留真实 `stage`、`target`、错误类型、reason code 和错误详情。权限、allowlist、表不存在、目标版本不支持 EXPLAIN、sample 解析失败或结果核对失败都只是补充分析缺口，不得改变 history 的状态、内容、可用性或根因资格。
<!-- /directive -->
<!-- directive:id=archery.history.error_or_empty_completion -->
16. 窗口查询超时或报错时，依据真实错误、字段和索引信息调整下一次 history 查询，不要原样重复无效调用。没有匹配 history 记录时如实返回空结果；不得把告警标题中的端点替代 `hostname_max`，不得虚构日志、执行计划、表结构或索引。完成所有可安全尝试的允许补充阶段后结束 Archery 调查。
<!-- /directive -->
