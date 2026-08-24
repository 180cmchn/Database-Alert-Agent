from app.adapters.archery_sql import (
    SQLTableReference,
    canonical_sql,
    is_simple_single_table_select,
    mysql_table_references,
    strip_mysql_comments,
)


def test_mysql_dash_comment_requires_following_whitespace() -> None:
    assert strip_mysql_comments("SELECT 5--2") == "SELECT 5--2"
    assert strip_mysql_comments("SELECT 5-- comment\n+ 1") == "SELECT 5\n+ 1"
    assert canonical_sql("SELECT 5--2") != canonical_sql("SELECT 5")


def test_canonical_sql_ignores_formatting_comments_and_keyword_case() -> None:
    left = "SELECT /* ordinary */ `Order_ID` FROM orders WHERE id=1;"
    right = " select `Order_ID` from orders where id = 1 "

    assert canonical_sql(left) == canonical_sql(right)


def test_canonical_sql_preserves_literal_case_and_internal_whitespace() -> None:
    original = "SELECT * FROM orders WHERE note = 'A  B'"

    assert canonical_sql(original) != canonical_sql(
        "SELECT * FROM orders WHERE note = 'a b'"
    )
    assert canonical_sql(original) == canonical_sql(
        " select * from orders where note='A  B'; "
    )


def test_canonical_sql_casefolds_bare_words_but_preserves_quoted_identifiers() -> None:
    assert canonical_sql("SELECT LOW_PRIORITY * FROM Orders") == canonical_sql(
        "select low_priority * from orders"
    )
    assert canonical_sql("SELECT * FROM `Orders`") != canonical_sql(
        "SELECT * FROM `orders`"
    )


def test_mysql_executable_and_malformed_comments_are_rejected() -> None:
    assert strip_mysql_comments("SELECT /*! SQL_NO_CACHE */ 1") is None
    assert strip_mysql_comments("SELECT /*M! SQL_NO_CACHE */ 1") is None
    assert strip_mysql_comments("SELECT /* missing end") is None
    assert canonical_sql("SELECT 'missing end") is None


def test_ambiguous_backslash_quote_and_odbc_escape_syntax_fail_closed() -> None:
    ambiguous = r"SELECT * FROM orders WHERE note = 'prefix\' OR admin = 1'"
    odbc = "SELECT * FROM {OJ orders LEFT JOIN audit ON orders.id = audit.id}"

    assert canonical_sql(ambiguous) is None
    assert mysql_table_references(ambiguous) is None
    assert canonical_sql(odbc) is None
    assert mysql_table_references(odbc) is None


def test_simple_single_table_select_is_a_positive_structural_allowlist() -> None:
    assert is_simple_single_table_select(
        "SELECT f_instance_id FROM t_instance_member "
        "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1"
    )
    assert is_simple_single_table_select(
        "SELECT host, port FROM sql_instance WHERE id IN (53, 54) ORDER BY id LIMIT 1"
    )

    rejected = (
        "SELECT SLEEP(1) FROM sql_instance",
        "SELECT id FROM sql_instance WHERE id = custom_lookup(53)",
        "SELECT s.id FROM sql_instance s JOIN t_instance_member m ON m.id = s.id",
        "SELECT id FROM sql_instance UNION SELECT f_instance_id FROM t_instance_member",
        "SELECT id FROM sql_instance WHERE id IN (SELECT id FROM t_instance_member)",
        "SELECT * FROM (SELECT * FROM sql_instance) resolved",
        "SELECT * FROM {OJ sql_instance LEFT JOIN t_instance_member ON 1 = 1}",
        "SELECT @resolved := id FROM sql_instance",
        "SELECT * FROM sql_instance FOR UPDATE",
    )
    assert all(not is_simple_single_table_select(sql) for sql in rejected)


def test_optimizer_hints_are_preserved_as_semantic_tokens() -> None:
    hinted = "SELECT /*+ INDEX(orders PRIMARY) */ * FROM orders"

    assert strip_mysql_comments(hinted) == hinted
    assert canonical_sql(hinted) == canonical_sql(
        "select /*+ INDEX(orders PRIMARY) */ * from orders"
    )
    assert canonical_sql(hinted) != canonical_sql(
        "SELECT /*+ INDEX(orders idx_customer) */ * FROM orders"
    )


def test_mysql_table_references_ignore_literals_and_cover_comma_sources() -> None:
    references = mysql_table_references(
        "SELECT 'FROM other_prod.decoy' FROM orders o, other_prod.secret s"
    )

    assert references == (
        SQLTableReference(schema=None, table="orders"),
        SQLTableReference(schema="other_prod", table="secret"),
    )


def test_mysql_table_references_cover_modified_dml_targets() -> None:
    assert mysql_table_references(
        "UPDATE LOW_PRIORITY IGNORE other_prod.Orders SET status = 1"
    ) == (SQLTableReference(schema="other_prod", table="Orders"),)
    assert mysql_table_references(
        "UPDATE /*+ NO_MERGE(Orders) */ other_prod.Orders SET status = 1"
    ) == (SQLTableReference(schema="other_prod", table="Orders"),)
    assert mysql_table_references(
        "INSERT HIGH_PRIORITY IGNORE INTO other_prod.archive SELECT * FROM source_rows"
    ) == (
        SQLTableReference(schema=None, table="source_rows"),
        SQLTableReference(schema="other_prod", table="archive"),
    )


def test_mysql_table_references_cover_delete_using_and_table_query_sources() -> None:
    assert mysql_table_references(
        "DELETE FROM victim USING other_prod.victim WHERE victim.id = 1"
    ) == (
        SQLTableReference(schema=None, table="victim"),
        SQLTableReference(schema="other_prod", table="victim"),
    )
    assert mysql_table_references(
        "INSERT INTO archive TABLE other_prod.source_rows"
    ) == (
        SQLTableReference(schema=None, table="archive"),
        SQLTableReference(schema="other_prod", table="source_rows"),
    )
    assert mysql_table_references(
        "REPLACE INTO archive TABLE other_prod.source_rows"
    ) == (
        SQLTableReference(schema=None, table="archive"),
        SQLTableReference(schema="other_prod", table="source_rows"),
    )
    assert mysql_table_references(
        "WITH recent AS (TABLE other_prod.secret) SELECT * FROM recent"
    ) == (
        SQLTableReference(schema="other_prod", table="secret"),
        SQLTableReference(schema=None, table="recent"),
    )
    assert mysql_table_references(
        "SELECT * FROM local_rows UNION ALL TABLE other_prod.secret"
    ) == (
        SQLTableReference(schema=None, table="local_rows"),
        SQLTableReference(schema="other_prod", table="secret"),
    )
    assert mysql_table_references("SELECT * FROM (TABLE other_prod.secret) rows") == (
        SQLTableReference(schema="other_prod", table="secret"),
    )


def test_insert_table_source_must_immediately_follow_optional_column_list() -> None:
    assert mysql_table_references(
        "INSERT INTO archive (id) TABLE other_prod.source_rows"
    ) == (
        SQLTableReference(schema=None, table="archive"),
        SQLTableReference(schema="other_prod", table="source_rows"),
    )
    assert mysql_table_references(
        "INSERT INTO archive SELECT table FROM source_rows"
    ) == (
        SQLTableReference(schema=None, table="source_rows"),
        SQLTableReference(schema=None, table="archive"),
    )
    assert mysql_table_references(
        "REPLACE INTO archive (id, table_name) SELECT table FROM source_rows"
    ) == (
        SQLTableReference(schema=None, table="source_rows"),
        SQLTableReference(schema=None, table="archive"),
    )


def test_mysql_table_references_support_ansi_quoted_structural_identifiers() -> None:
    assert mysql_table_references('SELECT * FROM "other_prod"."Orders"') == (
        SQLTableReference(schema="other_prod", table="Orders"),
    )


def test_mysql_table_references_do_not_treat_table_functions_as_physical_tables() -> None:
    assert mysql_table_references(
        "SELECT * FROM LATERAL (SELECT * FROM orders) recent"
    ) == (SQLTableReference(schema=None, table="orders"),)
    assert mysql_table_references(
        "SELECT * FROM JSON_TABLE('[1]', '$[*]' "
        "COLUMNS (value INT PATH '$')) values_from_json"
    ) == ()


def test_mysql_table_references_cover_parenthesized_table_factors() -> None:
    assert mysql_table_references("SELECT * FROM (other_prod.secret)") == (
        SQLTableReference(schema="other_prod", table="secret"),
    )
    assert mysql_table_references(
        "SELECT * FROM (other_prod.a JOIN local_rows b ON a.id = b.id)"
    ) == (
        SQLTableReference(schema="other_prod", table="a"),
        SQLTableReference(schema=None, table="local_rows"),
    )
    assert mysql_table_references(
        "SELECT * FROM ((other_prod.a JOIN local_rows b ON a.id = b.id))"
    ) == (
        SQLTableReference(schema="other_prod", table="a"),
        SQLTableReference(schema=None, table="local_rows"),
    )
    assert mysql_table_references(
        "SELECT * FROM (local_rows a, other_prod.secret s)"
    ) == (
        SQLTableReference(schema=None, table="local_rows"),
        SQLTableReference(schema="other_prod", table="secret"),
    )
    assert mysql_table_references(
        "SELECT * FROM (local_rows) a, other_prod.secret s"
    ) == (
        SQLTableReference(schema=None, table="local_rows"),
        SQLTableReference(schema="other_prod", table="secret"),
    )


def test_mysql_table_references_cover_qualified_multi_table_delete_targets() -> None:
    assert mysql_table_references(
        "DELETE other_prod.orders FROM orders JOIN local_rows l ON orders.id = l.id"
    ) == (
        SQLTableReference(schema=None, table="orders"),
        SQLTableReference(schema=None, table="local_rows"),
        SQLTableReference(schema="other_prod", table="orders"),
    )
    assert mysql_table_references(
        "DELETE /*+ NO_MERGE(orders) */ other_prod.orders.* "
        "FROM orders JOIN local_rows l ON orders.id = l.id"
    ) == (
        SQLTableReference(schema=None, table="orders"),
        SQLTableReference(schema=None, table="local_rows"),
        SQLTableReference(schema="other_prod", table="orders"),
    )
    assert mysql_table_references(
        "DELETE a, b FROM other_prod.orders a "
        "JOIN local_rows b ON a.id = b.id"
    ) == (
        SQLTableReference(schema="other_prod", table="orders"),
        SQLTableReference(schema=None, table="local_rows"),
    )
