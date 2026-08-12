使用 FlashDuty 告警详情中的 alarm_host 和 alarm_port 作为唯一告警端点，使用 occurred_at - 5 分钟到 occurred_at 的闭合调查窗口。不得从告警标题推断或补全 host、port。

按当前 MCP 动态发现的工具 Schema 和真实返回自主调用工具，每轮只调用一个。Archery 登录由 Host 在模型调用前完成，不得再次调用登录工具。最终查询必须使用 MCP 返回的真实整数 instance_id、数据库名、表名及字段名，不得猜测部署结构。辅助查询完成后必须继续，直到成功查询目标慢查询历史表；若推荐 history 表的必经解析链路走不通，不得绕过链路直接查询该表，可根据真实错误在其它慢日志表或只读探针中选择合理替代路径。

查询 mysql_slow_query_review_history 时必须按以下链路定位 hostname_max，避免为了验证host反复枚举或校验无关实例：
(1) 先用MCP发现allowlist中的archery实例及archery数据库；记下其真实MCP instance_id。从这一步起，推荐链路中每次list_table_columns和sql_query都必须使用同一个archery MCP instance_id和db_name=archery，之后要用到的t_instance_member、sql_instance、mysql_slow_query_review_history三张表都在该实例和数据库中；
(2) 对t_instance_member先调用list_table_columns，确认承载成员f_ip、f_port和f_instance_id；再用查询条件where f_ip = alert_host and f_port = alert_port做一次只读SELECT，取得f_instance_id；
(3) 对archery.sql_instance先调用list_table_columns，确认id列；在SQL的WHERE条件中以f_instance_id作为sql_instance.id查询真实host和port。
(4) 将sql_instance返回的真实host和port严格组合为host:port，作为archery.mysql_slow_query_review_history.hostname_max的等值条件；
(5) 先确认archery.mysql_slow_query_review_history的hostname_max和时间列的真实名称和类型，再在实例archery和db_name=archery中用hostname_max等值条件和告警时间范围条件共同查询慢查询日志记录；两类WHERE条件缺一不可。
最终结果必须返回hostname_max；最终慢日志查询成功并返回日志内容后即完成取证，不需要再比较告警端点和结果端点，也不要追加实例归属查询。
t_instance_member、sql_instance、mysql_slow_query_review_history及上述列名都是推荐线索，不是对部署表结构的强制假设；必须通过list_table_columns读取真实字段或通过只读查询结果确认。

最终只读 SELECT 必须使用发现到的慢日志相关表、返回 hostname_max，并显式包含不超过 Host contract 中 max_result_rows 的 LIMIT。只投影慢查询语义证据需要的时间、库、用户、checksum、sample 及少量诊断数值字段，不得使用 SELECT *。查询 mysql_slow_query_review_history 时，最终 WHERE 必须同时包含由元数据链路得到的 hostname_max 等值条件和 required_window；缺少其中任一条件的成功查询、无 WHERE 的 LIMIT 1 样例、字段确认或任意历史行查询都只算辅助探针，必须利用返回继续调查。

必须依据 list_table_columns 返回的真实字段名和类型选择慢查询时间字段。若真实字段包含 ts_min 和 ts_max，二者表示聚合记录的首次和末次发生时间，可用 ts_min < 窗口结束且 ts_max >= 窗口开始表达与告警窗口重叠，不要强行把两个边界套在同一个聚合时间字段上。对于 DATETIME 或 TIMESTAMP 字段，可使用 Host 给出的 Unix 秒配合 FROM_UNIXTIME；若真实字段同时存在 f_insert_time、f_start_time 和 f_time_point，分钟级窗口优先使用 f_insert_time，不要把只有日期或格式未知的 varchar 字段与完整时间戳比较。不得自行换算或修改 Host 给出的窗口 Unix 秒，也不得去掉 ISO 8601 时区偏移后直接作为 SQL 字面值。

若窗口重叠查询被 Archery 超时终止，不得原样重试或只增加 FORCE INDEX；先用 SELECT 查询 information_schema.statistics 确认真实索引，SHOW INDEX 不符合只允许 SELECT/WITH 的 Host 安全边界。若联合索引以前导列 hostname_max、ts_min 开头，恢复查询优先同时限定 ts_min 的窗口起止，使索引获得等值列和有界范围。最终 history 查询不得按 Query_time、Rows_examined 等诊断值排序；只在真实字段包含 ts_min 时使用 ORDER BY ts_min DESC，否则去掉 ORDER BY。若 Host 反馈远端预算只剩一次且上一条 history 查询已超时，不再查询索引元数据，直接提交使用 hostname_max 等值条件、ts_min 半开窗口和 Host 允许 LIMIT 的恢复查询。

工具返回不匹配、没有结果或查询报错时，不得把告警标题端点直接用作 hostname_max，也不得虚构成功结果。剩余远端预算达到 Host contract 的 finalization_call_reserve 后，只进行 history 字段、索引与最终窗口查询，不再枚举资源或重复 t_instance_member、sql_instance 归属查询。以 Host 每轮反馈的已用、剩余调用数为准。
