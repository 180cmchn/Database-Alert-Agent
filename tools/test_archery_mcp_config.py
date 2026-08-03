#!/usr/bin/env python3
"""Run a live, read-only Archery MCP connection and target smoke test.

Run from the project root so the result is printed in the VS Code terminal::

    .venv/bin/python -m tools.test_archery_mcp_config \
        --instance-ref db-prod-01:3306 --db-name orders
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.adapters.archery_mcp import (
    ARCHERY_MCP_INSTANCES_TOOL_NAME,
    ARCHERY_MCP_LOGIN_TOOL_NAME,
    ARCHERY_MCP_QUERY_TOOL_NAME,
    ArcheryMCPClient,
    ArcherySlowLogEvidenceTool,
    MCPServerSettings,
    load_mcp_server_settings,
)
from app.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULT_CHARACTER_LIMIT = 24_000
LATEST_SLOW_LOG_SQL = """SELECT
    f_id,
    f_instances_id,
    f_start_time,
    f_db,
    f_sql_text,
    f_user,
    f_time_point,
    f_max_time,
    f_min_time,
    f_times,
    f_sumtime,
    f_insert_time,
    f_update_time
FROM t_slowlog_info
ORDER BY f_insert_time DESC, f_id DESC
LIMIT 5"""


def _positive_integer(value: Any) -> int | None:
    if type(value) is int:
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _walk_mappings(value: Any) -> list[Mapping[str, Any]]:
    mappings: list[Mapping[str, Any]] = []
    pending = [value]
    while pending and len(mappings) < 200:
        current = pending.pop()
        if isinstance(current, Mapping):
            mappings.append(current)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return mappings


def _walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    pending = [value]
    while pending and len(strings) < 200:
        current = pending.pop()
        if isinstance(current, str):
            strings.append(current)
        elif isinstance(current, Mapping):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return strings


def _instance_id_from_payload(payload: Mapping[str, Any], instance_ref: str) -> int:
    expected = instance_ref.strip().casefold()
    name_keys = ("name", "instance_name", "instance_ref", "instance")
    id_keys = ("id", "instance_id")
    for item in _walk_mappings(payload):
        names = [item.get(key) for key in name_keys]
        if not any(
            isinstance(name, str) and name.strip().casefold() == expected
            for name in names
        ):
            continue
        for key in id_keys:
            instance_id = _positive_integer(item.get(key))
            if instance_id is not None:
                return instance_id

    text_pattern = re.compile(
        rf"\[ID\s*:\s*(?P<id>\d+)\]\s*{re.escape(instance_ref.strip())}(?=\s|$)",
        re.IGNORECASE,
    )
    for text in _walk_strings(payload):
        match = text_pattern.search(text)
        if match is not None:
            return int(match.group("id"))

    raise RuntimeError(
        f"list_instances did not return an exact match for configured instance "
        f"{instance_ref!r}"
    )


def _load_connection() -> tuple[Settings, MCPServerSettings]:
    settings = Settings(_env_file=PROJECT_ROOT / ".env")
    required = {
        "ARCHERY_MCP_URL": settings.archery_mcp_url,
        "ARCHERY_MCP_TOKEN": settings.archery_mcp_token,
    }
    missing = [name for name, value in required.items() if not value.strip()]
    if missing:
        raise RuntimeError("missing Archery MCP configuration: " + ", ".join(missing))

    settings_path = settings.mcp_settings_path
    if not settings_path.is_absolute():
        settings_path = PROJECT_ROOT / settings_path
    server = load_mcp_server_settings(
        settings_path,
        server_name="archery",
        environment={
            "ARCHERY_MCP_URL": settings.archery_mcp_url,
            "ARCHERY_MCP_TOKEN": settings.archery_mcp_token,
        },
    )
    return settings, server


async def _available_tool_names(session: ClientSession) -> set[str]:
    names: set[str] = set()
    cursor: str | None = None
    for _page in range(10):
        result = await session.list_tools(
            params=mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None
        )
        names.update(tool.name for tool in result.tools)
        if not result.nextCursor:
            return names
        cursor = result.nextCursor
    raise RuntimeError("Archery MCP tools/list pagination exceeded 10 pages")


async def _call_read_only_tool(
    session: ClientSession,
    *,
    name: str,
    arguments: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    result = await session.call_tool(
        name,
        arguments,
        read_timeout_seconds=timedelta(seconds=timeout_seconds),
    )
    dumped = result.model_dump(by_alias=True, mode="json", exclude_none=True)
    text_blocks = ArcheryMCPClient._tool_text_blocks(dumped)
    payload = ArcheryMCPClient._extract_tool_payload(dumped)
    ArcheryMCPClient._validate_business_success(
        payload,
        tool_name=name,
        supplemental_text=text_blocks,
    )
    return payload


async def run(*, instance_ref: str, db_name: str) -> None:
    settings, server = _load_connection()
    timeout_seconds = settings.archery_mcp_timeout_seconds
    print("=== Archery MCP 配置冒烟测试 ===")
    print(f"MCP Endpoint: {server.url}")
    print(f"模拟告警实例: {instance_ref}")
    print(f"模拟告警数据库: {db_name}")
    print("查询目标: t_slowlog_info 最新 5 条\n")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        headers=server.headers,
    ) as http_client:
        async with streamable_http_client(
            server.url,
            http_client=http_client,
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=timeout_seconds),
                client_info=mcp_types.Implementation(
                    name="database-alert-agent-config-test",
                    version="0.1.0",
                ),
            ) as session:
                await session.initialize()
                tool_names = await _available_tool_names(session)
                required_tools = {
                    ARCHERY_MCP_LOGIN_TOOL_NAME,
                    ARCHERY_MCP_INSTANCES_TOOL_NAME,
                    ARCHERY_MCP_QUERY_TOOL_NAME,
                }
                missing_tools = sorted(required_tools - tool_names)
                if missing_tools:
                    raise RuntimeError(
                        "Archery MCP is missing required tools: "
                        + ", ".join(missing_tools)
                    )

                print("[1/3] 调用 ensure_login_gymJPA")
                await _call_read_only_tool(
                    session,
                    name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                    arguments={},
                    timeout_seconds=timeout_seconds,
                )
                print("      登录确认成功")

                print(f"[2/3] 按模拟告警实例查询 instance_id: {instance_ref}")
                instances_payload = await _call_read_only_tool(
                    session,
                    name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                    arguments={"instance_ref": instance_ref, "page": 1, "size": 200},
                    timeout_seconds=timeout_seconds,
                )
                instance_id = _instance_id_from_payload(instances_payload, instance_ref)
                print(f"      instance_id={instance_id}")

                print(f"[3/3] 查询 {db_name}.t_slowlog_info 最新 5 条")
                query_payload = await _call_read_only_tool(
                    session,
                    name=ARCHERY_MCP_QUERY_TOOL_NAME,
                    arguments={
                        "instance_id": instance_id,
                        "db_name": db_name,
                        "sql_content": LATEST_SLOW_LOG_SQL,
                        "limit_num": 5,
                        "max_result_chars": RESULT_CHARACTER_LIMIT,
                    },
                    timeout_seconds=timeout_seconds,
                )

    normalized, executed_sql, actual_sql_verified = (
        ArcheryMCPClient._normalize_query_payload(
            query_payload,
            requested_sql=LATEST_SLOW_LOG_SQL,
        )
    )
    row_count = ArcherySlowLogEvidenceTool._row_count(normalized)
    print("\n=== MCP 查询完成 ===")
    print(f"实际 SQL 已核对: {'是' if actual_sql_verified else '否'}")
    print(f"返回行数: {row_count if row_count is not None else '无法解析'}")
    print("实际执行 SQL:")
    print(executed_sql or "MCP 未返回实际执行 SQL")
    print("\n完整结果:")
    print(json.dumps(normalized, ensure_ascii=False, indent=2, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="使用显式告警目标测试 Archery MCP 只读查询链路"
    )
    parser.add_argument(
        "--instance-ref",
        required=True,
        help="模拟告警中的数据库实例名、主机或 host:port",
    )
    parser.add_argument(
        "--db-name",
        required=True,
        help="模拟告警中的数据库名",
    )
    args = parser.parse_args()
    try:
        asyncio.run(
            run(
                instance_ref=args.instance_ref.strip(),
                db_name=args.db_name.strip(),
            )
        )
    except KeyboardInterrupt:
        print("\n测试已取消。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\nArchery MCP 配置测试失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
