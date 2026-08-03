from tools.test_archery_mcp_config import DB_NAME, INSTANCE_REF, OLDEST_SLOW_LOG_SQL


def test_archery_mcp_config_smoke_query_uses_fixed_oldest_target() -> None:
    assert INSTANCE_REF == "archery"
    assert DB_NAME == "archery"
    assert "FROM t_slowlog_info" in OLDEST_SLOW_LOG_SQL
    assert "ORDER BY f_insert_time ASC, f_id ASC" in OLDEST_SLOW_LOG_SQL
    assert OLDEST_SLOW_LOG_SQL.rstrip().endswith("LIMIT 5")
