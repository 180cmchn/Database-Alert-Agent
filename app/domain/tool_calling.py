from __future__ import annotations

from collections.abc import Awaitable, Callable
from copy import deepcopy
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
    provider_output_items: tuple[dict[str, Any], ...] = ()


def mcp_tool_result_messages(
    call: MCPModelToolCall,
    *,
    output: str,
    fallback_messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the next-turn tool result in the provider's native conversation form."""

    if not call.provider_output_items:
        return deepcopy(fallback_messages)
    return [
        *(deepcopy(item) for item in call.provider_output_items),
        {
            "type": "function_call_output",
            "call_id": call.call_id,
            "output": output,
        },
    ]


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
