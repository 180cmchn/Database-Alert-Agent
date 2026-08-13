#!/usr/bin/env python3
r"""Run a live Archery MCP connection and dynamic discovery smoke test.

Run from the project root so the result is printed in the VS Code terminal::

    .\.venv\Scripts\python.exe -m tools.test_archery_mcp_config
"""

from __future__ import annotations

import asyncio
import sys
from datetime import timedelta
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client

from app.adapters.archery_mcp import MCPServerSettings, load_mcp_server_settings
from app.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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


async def _available_tools(session: ClientSession) -> list[mcp_types.Tool]:
    tools: dict[str, mcp_types.Tool] = {}
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        result = await session.list_tools(
            params=mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None
        )
        tools.update((tool.name, tool) for tool in result.tools)
        if not result.nextCursor:
            return [tools[name] for name in sorted(tools)]
        next_cursor = result.nextCursor
        if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
            raise RuntimeError("Archery MCP returned an invalid or repeated tools/list cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


async def run() -> None:
    settings, server = _load_connection()
    timeout_seconds = settings.archery_mcp_timeout_seconds
    print("=== Archery MCP 配置冒烟测试 ===")
    print(f"MCP Endpoint: {server.url}")
    print("检查范围: 初始化与动态工具发现；不预设或调用任何固定工具\n")

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
                tools = await _available_tools(session)
                if not tools:
                    raise RuntimeError("Archery MCP did not expose any tools")
                print(f"发现 {len(tools)} 个工具：")
                for tool in tools:
                    print(f"  - {tool.name}: {tool.description or '(无描述)'}")

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
