#!/usr/bin/env python3
r"""Run a live Archery MCP connection, authentication, and discovery smoke test.

Run from the project root so the result is printed in the VS Code terminal::

    .\.venv\Scripts\python.exe -m tools.test_archery_mcp_config
"""

from __future__ import annotations

import asyncio
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
    MCPServerSettings,
    load_mcp_server_settings,
)
from app.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTANCE_REF = "archery"


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
        if not any(isinstance(name, str) and name.strip().casefold() == expected for name in names):
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
        f"list_instances did not return an exact match for configured instance {instance_ref!r}"
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


async def run() -> None:
    settings, server = _load_connection()
    timeout_seconds = settings.archery_mcp_timeout_seconds
    print("=== Archery MCP 配置冒烟测试 ===")
    print(f"MCP Endpoint: {server.url}")
    print(f"固定实例: {INSTANCE_REF}")
    print("检查范围: 初始化、工具发现、登录和实例发现\n")

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
                        "Archery MCP is missing required tools: " + ", ".join(missing_tools)
                    )

                print("[1/2] 调用 ensure_login_gymJPA")
                await _call_read_only_tool(
                    session,
                    name=ARCHERY_MCP_LOGIN_TOOL_NAME,
                    arguments={},
                    timeout_seconds=timeout_seconds,
                )
                print("      登录确认成功")

                print(f"[2/2] 按固定实例查询 instance_id: {INSTANCE_REF}")
                instances_payload = await _call_read_only_tool(
                    session,
                    name=ARCHERY_MCP_INSTANCES_TOOL_NAME,
                    arguments={"instance_ref": INSTANCE_REF, "page": 1, "size": 200},
                    timeout_seconds=timeout_seconds,
                )
                instance_id = _instance_id_from_payload(instances_payload, INSTANCE_REF)
                print(f"      instance_id={instance_id}")

    print("\n=== Archery MCP 配置冒烟检查完成 ===")


def main() -> int:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n测试已取消。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\nArchery MCP 配置测试失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
