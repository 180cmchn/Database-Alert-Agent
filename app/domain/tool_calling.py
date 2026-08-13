from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

ReasoningDeltaCallback = Callable[[str, int], Awaitable[None]]
ReasoningTraceCallback = Callable[[str, str, int], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class MCPModelToolCall:
    """One function-style tool call selected by the configured model."""

    call_id: str
    name: str
    arguments: dict[str, Any]
    request_id: str | None = None
    reasoning_content: str | None = None
    usage: dict[str, Any] | None = None


@runtime_checkable
class MCPToolCallingModel(Protocol):
    """Minimal model capability required by an embedded MCP host."""

    async def request_mcp_tool_call(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        reasoning_callback: ReasoningDeltaCallback | None = None,
    ) -> MCPModelToolCall: ...
