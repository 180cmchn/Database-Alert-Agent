from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import app.adapters.archery_harness as archery_harness_module
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.archery_harness import (
    ARCHERY_HARNESS_PROVIDER,
    ArcheryHarnessRuntimeDependencies,
)
from app.adapters.archery_mcp import (
    ARCHERY_MCP_COLUMNS_TOOL_NAME,
    ARCHERY_MCP_DATABASES_TOOL_NAME,
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_SLOW_QUERY_REVIEW_TABLE,
    ArcheryMCPClient,
    MCPServerSettings,
)
from app.adapters.persistence import (
    SQLAlchemyAlertRepository,
)
from app.agent_runtime import (
    RunManifest,
)
from app.domain.models import InvestigationRun
from app.domain.tool_calling import MCPModelToolCall
from app.mcp_catalog import load_mcp_catalog
from app.mcp_runtime import (
    DiscoveredMCPTool,
    ReplayCallFixture,
    ReplayMCPConnector,
)

OCCURRED_AT = datetime.fromisoformat("2026-07-23T16:00:00+08:00")
ARCHERY_MCP_LOGIN_TOOL_NAME = "ensure_login_gymJPA"
ARCHERY_MCP_QUERY_TOOL_NAME = "sql_query_gymJPA"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARCHERY_PROMPTS = load_mcp_catalog(
    PROJECT_ROOT / "config/mcp/settings.json"
).require("archery").prompts
ALERT_CONTEXT = {"alert_endpoint": "db-1.example:3306"}
FINISH_TOOL_NAME = "finish_archery_investigation"
RESULT_ASSESSMENT_TOOL_NAME = "report_archery_result_assessment"
TARGET_ARGUMENTS = {
    "instance_id": 17,
    "db_name": "archery",
    "limit_num": 20,
}
FINAL_SQL = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784793300) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "ORDER BY ts_min DESC LIMIT 20"
)
MEMBER_SQL = (
    "SELECT f_instance_id FROM t_instance_member "
    "WHERE f_ip = 'db-1.example' AND f_port = 3306 LIMIT 1"
)
INSTANCE_SQL = "SELECT host, port FROM sql_instance WHERE id = 53 LIMIT 1"


def _lineage_actions(final_sql: str = FINAL_SQL) -> list[MCPModelToolCall]:
    return [
        _call("member", MEMBER_SQL),
        _call("instance", INSTANCE_SQL),
        _call("final", final_sql),
        _finish(),
    ]


def _lineage_replay_calls(
    final_sql: str = FINAL_SQL,
    *,
    rows: list[dict[str, Any]] | None = None,
) -> list[ReplayCallFixture]:
    return [
        _success(MEMBER_SQL, rows=[{"f_instance_id": 53}]),
        _success(INSTANCE_SQL, rows=[{"host": "db-1.example", "port": 3306}]),
        _success(final_sql, rows=rows),
    ]


class _ScriptedModel:
    def __init__(self, responses: list[MCPModelToolCall | Exception]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall:
        self.requests.append(
            {
                "messages": deepcopy(messages),
                "tools": deepcopy(tools),
                "tool_names": [item["function"]["name"] for item in tools],
            }
        )
        if [item["function"]["name"] for item in tools] == [
            RESULT_ASSESSMENT_TOOL_NAME
        ]:
            if (
                self.responses
                and isinstance(self.responses[0], MCPModelToolCall)
                and self.responses[0].name == RESULT_ASSESSMENT_TOOL_NAME
            ):
                return self.responses.pop(0)
            pending = next(
                (
                    payload
                    for message in reversed(messages)
                    if isinstance((payload := _json_message(message)), dict)
                    and payload.get("type") == "archery_result_assessment_required"
                ),
                None,
            )
            assert pending is not None
            program_checks = pending.get("program_checks")
            incomplete = bool(
                isinstance(program_checks, dict)
                and program_checks.get("result_incomplete") is True
            )
            return MCPModelToolCall(
                call_id=f"assessment-{len(self.requests)}",
                name=RESULT_ASSESSMENT_TOOL_NAME,
                arguments={
                    "source_invocation_id": pending["source_invocation_id"],
                    "content_state": "content_too_long" if incomplete else "complete",
                    "scope": pending["scope"],
                    "stage": pending["stage"],
                    "history_id": pending.get("history_id"),
                    "basis": "explicit_message" if incomplete else "appears_complete",
                },
                request_id=f"request-assessment-{len(self.requests)}",
            )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _json_message(message: dict[str, Any]) -> Any:
    content = message.get("content")
    if not isinstance(content, str):
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def _call(call_id: str, sql: str) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        request_id=f"request-{call_id}",
    )


def _named_call(
    call_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=tool_name,
        arguments=arguments,
        request_id=f"request-{call_id}",
    )


def _target_call(
    call_id: str,
    sql: str,
    *,
    instance_id: int,
    db_name: str,
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=ARCHERY_MCP_QUERY_TOOL_NAME,
        arguments={
            "instance_id": instance_id,
            "db_name": db_name,
            "limit_num": 20,
            "sql_content": sql,
        },
        request_id=f"request-{call_id}",
    )


def _finish(
    call_id: str = "finish",
    *,
    reason: str = "Archery evidence collection is complete",
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=call_id,
        name=FINISH_TOOL_NAME,
        arguments={"reason": reason},
        request_id=f"request-{call_id}",
    )


def _result_assessment(
    source_call_id: str,
    *,
    scope: str,
    content_state: str,
    history_id: int | None = None,
    stage: str = "history_recovery",
    basis: str = "abrupt_ending",
) -> MCPModelToolCall:
    return MCPModelToolCall(
        call_id=f"assessment-{source_call_id}",
        name=RESULT_ASSESSMENT_TOOL_NAME,
        arguments={
            "source_invocation_id": source_call_id,
            "content_state": content_state,
            "scope": scope,
            "stage": stage,
            "history_id": history_id,
            "basis": basis,
        },
        request_id=f"request-assessment-{source_call_id}",
    )


def _tools() -> list[DiscoveredMCPTool]:
    return [
        DiscoveredMCPTool(
            name=ARCHERY_MCP_LOGIN_TOOL_NAME,
            description="Confirm the configured Archery identity",
            input_schema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_QUERY_TOOL_NAME,
            description="Execute one read-only SELECT",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "db_name": {"type": "string"},
                    "sql_content": {"type": "string"},
                    "limit_num": {"type": "integer"},
                    "max_result_chars": {"type": "integer"},
                },
                "required": ["instance_id", "db_name", "sql_content"],
            },
            annotations={"readOnlyHint": True},
        ),
    ]


def _analysis_tools() -> list[DiscoveredMCPTool]:
    return [
        *_tools(),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            description="List allowlisted database instances",
            input_schema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            description="List databases for one allowlisted instance",
            input_schema={
                "type": "object",
                "properties": {"instance_id": {"type": "integer"}},
                "required": ["instance_id"],
            },
            annotations={"readOnlyHint": True},
        ),
        DiscoveredMCPTool(
            name=ARCHERY_MCP_COLUMNS_TOOL_NAME,
            description="List real columns for one table",
            input_schema={
                "type": "object",
                "properties": {
                    "instance_id": {"type": "integer"},
                    "db_name": {"type": "string"},
                    "tb_name": {"type": "string"},
                },
                "required": ["instance_id", "db_name", "tb_name"],
            },
            annotations={"readOnlyHint": True},
        ),
    ]


def _analysis_discovery_actions(
    *,
    instance_id: int = 3,
) -> list[MCPModelToolCall]:
    return [
        _named_call("allowlist", ARCHERY_MCP_INSTANCES_TOOL_NAME, {}),
        _named_call(
            "databases",
            ARCHERY_MCP_DATABASES_TOOL_NAME,
            {"instance_id": instance_id},
        ),
    ]


def _analysis_discovery_calls(
    *,
    instance_id: int = 3,
    endpoint: str = "orders-db.example:3306",
    db_name: str = "orders_prod",
) -> list[ReplayCallFixture]:
    host, port_text = endpoint.rsplit(":", 1)
    return [
        ReplayCallFixture(
            tool_name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
            expected_arguments={},
            result={
                "structuredContent": {
                    "status": "success",
                    "rows": [{"id": instance_id, "host": host, "port": int(port_text)}],
                }
            },
        ),
        ReplayCallFixture(
            tool_name=ARCHERY_MCP_DATABASES_TOOL_NAME,
            expected_arguments={"instance_id": instance_id},
            result={
                "structuredContent": {
                    "status": "success",
                    "rows": [{"name": db_name}],
                }
            },
        ),
    ]


def _success(
    sql: str,
    *,
    rows: list[dict[str, Any]] | None = None,
    max_result_chars: int | None = None,
) -> ReplayCallFixture:
    expected_arguments = {**TARGET_ARGUMENTS, "sql_content": sql}
    if max_result_chars is not None:
        expected_arguments["max_result_chars"] = max_result_chars
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments=expected_arguments,
        result={
            "structuredContent": {
                "status": "success",
                "full_sql": sql,
                "rows": rows or [],
            }
        },
    )


def _response_result_success(
    sql: str,
    *,
    columns: list[str],
    rows: list[list[Any]],
) -> ReplayCallFixture:
    payload = {
        "full_sql": sql,
        "rows": rows,
        "column_list": columns,
        "affected_rows": len(rows),
    }
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={**TARGET_ARGUMENTS, "sql_content": sql},
        result={
            "structuredContent": {
                "response": {
                    "result": (
                        f"SQL 查询已执行。\n执行的SQL：{sql}\n\n"
                        f"返回 {len(rows)} 行。\n结果：\n"
                        + json.dumps(payload, ensure_ascii=False)
                    )
                }
            }
        },
    )


def _client(
    model: _ScriptedModel,
    connector: ReplayMCPConnector,
    *,
    repository: SQLAlchemyAlertRepository | None = None,
) -> ArcheryMCPClient:
    return ArcheryMCPClient(
        MCPServerSettings(
            url="https://archery.example.test/mcp",
            headers={"X-Archery-Token": "fixture-token"},
            prompts=ARCHERY_PROMPTS,
        ),
        model,
        harness_connector=connector,
        harness_runtime_dependencies=(
            ArcheryHarnessRuntimeDependencies(repository)
            if repository is not None
            else None
        ),
    )


def _scenario() -> archery_harness_module.ArcheryHarnessScenario:
    client = _client(
        _ScriptedModel([]),
        ReplayMCPConnector(ARCHERY_HARNESS_PROVIDER, []),
    )
    state = archery_harness_module.ArcheryHarnessState(
        window_start=OCCURRED_AT,
        window_end=OCCURRED_AT,
        occurred_at=OCCURRED_AT,
        alert_context=dict(ALERT_CONTEXT),
        alert_endpoint=ALERT_CONTEXT["alert_endpoint"],
    )
    return archery_harness_module.ArcheryHarnessScenario(
        client,
        state,
        archery_harness_module._PlannerCallRegistry(),
    )


def _assess_pending_result(
    scenario: archery_harness_module.ArcheryHarnessScenario,
    state: archery_harness_module.ArcheryHarnessState,
    *,
    content_state: str = "complete",
) -> None:
    pending = state.pending_result_assessment
    assert pending is not None
    prepared = scenario.prepare_call(
        SimpleNamespace(
            tool_name=RESULT_ASSESSMENT_TOOL_NAME,
            objective="Assess raw history result completeness",
            hypothesis_ids=(),
            arguments={
                "source_invocation_id": pending["source_invocation_id"],
                "content_state": content_state,
                "scope": pending["scope"],
                "stage": pending["stage"],
                "history_id": pending.get("history_id"),
                "basis": (
                    "appears_complete"
                    if content_state == "complete"
                    else "abrupt_ending"
                ),
            },
        ),
        state=state,
    )
    scenario.on_result(state, prepared, prepared.local_result)


def _bound_history_scenario(
    rows: list[dict[str, Any]],
    *,
    instance_id: int = 3,
    endpoint: str = "orders-db.example:3306",
    db_name: str = "orders_prod",
) -> tuple[
    archery_harness_module.ArcheryHarnessScenario,
    archery_harness_module.ArcheryHarnessState,
]:
    scenario = _scenario()
    state = scenario.initial_state()
    state.final_result = archery_harness_module.ArcherySlowLogQueryResult(
        payload={"rows": rows},
        requested_sql=FINAL_SQL,
        window_start=state.window_start,
        window_end=state.window_end,
    )
    state.history_window_state = archery_harness_module._HISTORY_WINDOW_SUCCEEDED
    state.history_result_target = (
        TARGET_ARGUMENTS["instance_id"],
        TARGET_ARGUMENTS["db_name"],
    )
    state.analysis_instance_endpoints = {instance_id: {endpoint}}
    state.analysis_database_names = {instance_id: {db_name}}
    return scenario, state


async def _create_durable_run(
    repository: SQLAlchemyAlertRepository,
    *,
    external_id: str,
) -> tuple[RunManifest, InvestigationRun]:
    run_id = uuid4()
    manifest = RunManifest(
        run_id=run_id,
        agent_name="database-alert-investigation",
        code_version="archery-harness-test",
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": external_id,
            "severity": "WARNING",
            "title": "MySQL/mysql_slow_query_400/db-1.example:3306",
            "reason": "database_latency",
            "occurred_at": OCCURRED_AT.isoformat(),
        }
    )
    stored, created = await repository.create_or_get(alert)
    assert created is True
    run = await repository.create_run(
        str(stored.alert.id),
        "archery-worker",
        300,
        manifest=manifest,
    )
    assert run is not None
    assert run.id == run_id
    assert run.lease_owner == "archery-worker"
    return manifest, run


_MERGE_WINDOW_SQL = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784789700) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "AND ts_max >= FROM_UNIXTIME(1784793300) "
    "ORDER BY id DESC"
)
_MERGE_IDS_SQL = (
    f"SELECT id FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} "
    "WHERE hostname_max = 'db-1.example:3306' "
    "AND ts_min >= FROM_UNIXTIME(1784789700) "
    "AND ts_min < FROM_UNIXTIME(1784793600) "
    "AND ts_max >= FROM_UNIXTIME(1784793300) "
    "ORDER BY id DESC"
)
_MERGE_ID_SQL_60 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413460"
)
_MERGE_ID_SQL_58 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413458"
)
_MERGE_ID_SQL_54 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413454"
)
_MERGE_ID_SQL_44 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413644"
)
_MERGE_RECOVERED_ROW = {
    "id": 24413458,
    "hostname_max": "db-1.example:3306",
    "db_max": "dpm",
    "user_max": "dpm_rw",
    "checksum": "a" * 32,
    "sample": "UPDATE t_dpm_task_warning SET del_flag = 1",
    "ts_min": "2026-08-17T09:41:30",
    "ts_max": "2026-08-17T09:42:49",
    "ts_cnt": 6,
    "Query_time_sum": 0.340724,
    "Query_time_max": 0.058781,
    "Query_time_pct_95": 0.0585588,
}


def _merge_truncated_window_fixture(
    recovered_row: dict[str, Any] | None = None,
) -> ReplayCallFixture:
    recovered_row = recovered_row or _MERGE_RECOVERED_ROW
    truncated_result = (
        '{"rows":['
        + json.dumps(recovered_row, ensure_ascii=False)
        + ',{"id":24413460,"hostname_max":"db-1.example:3306'
    )
    wrapped_window_result = (
        f"SQL 查询已执行。\n执行的SQL：{_MERGE_WINDOW_SQL}\n\n返回 6 行。\n结果：\n"
        + truncated_result
    )
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _MERGE_WINDOW_SQL,
        },
        result={
            "structuredContent": {
                "response": {"result": wrapped_window_result},
            }
        },
    )


def _truncated_window_positional_fixture() -> ReplayCallFixture:
    """Mirror of run 2c18cb74: Archery's JSON puts ``rows`` before
    ``column_list``, so a mid-rows truncation recovers positional rows whose
    column names are lost with the tail of the payload.
    """
    recovered = json.dumps(
        [
            list({**_MERGE_RECOVERED_ROW, "id": row_id}.values())
            for row_id in (24413648, 24413647, 24413646, 24413645)
        ]
    )
    truncated_result = (
        '{"full_sql": '
        + json.dumps(_MERGE_WINDOW_SQL, ensure_ascii=False)
        + ', "rows": '
        + recovered[:-1]
        + ',\n      [24413644, "db-1.example:3306", "d'
    )
    wrapped_window_result = (
        f"SQL 查询已执行。\n执行的SQL：{_MERGE_WINDOW_SQL}\n\n返回 6 行。\n结果：\n"
        + truncated_result
    )
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments={
            **TARGET_ARGUMENTS,
            "sql_content": _MERGE_WINDOW_SQL,
        },
        result={
            "structuredContent": {
                "response": {"result": wrapped_window_result},
            }
        },
    )


_TRUNCATED_ID_SQL_40 = (
    f"SELECT * FROM {ARCHERY_SLOW_QUERY_REVIEW_TABLE} WHERE id = 24413640"
)


def _truncated_id_retrieval_fixture(
    sql: str,
    *,
    max_result_chars: int | None = None,
) -> ReplayCallFixture:
    truncated_result = (
        '{"rows":[{"id":24413640,"hostname_max":"db-1.example:3306",'
        '"sample":"SELECT count(0) FROM t_device WHERE store_code IN ('
    )
    wrapped = (
        f"SQL 查询已执行。\n执行的SQL：{sql}\n\n返回 1 行。\n结果：\n"
        + truncated_result
    )
    expected = {**TARGET_ARGUMENTS, "sql_content": sql}
    if max_result_chars is not None:
        expected["max_result_chars"] = max_result_chars
    return ReplayCallFixture(
        tool_name=ARCHERY_MCP_QUERY_TOOL_NAME,
        expected_arguments=expected,
        result={
            "structuredContent": {
                "response": {"result": wrapped},
            }
        },
    )


_PROJECTION_SAMPLE_PREFIX = (
    "SELECT count(0) FROM t_device WHERE store_code IN "
    "('1000042256', '1000042257')"
)
_PROJECTION_ID_SQL_40 = ArcheryMCPClient.history_sample_projection_sql(24413640)
