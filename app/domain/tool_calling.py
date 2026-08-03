from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class MCPModelToolCall:
    """One function-style tool call selected by the configured model."""

    call_id: str
    name: str
    arguments: dict[str, Any]
    request_id: str | None = None


@runtime_checkable
class MCPToolCallingModel(Protocol):
    """Minimal model capability required by an embedded MCP host."""

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> MCPModelToolCall: ...
