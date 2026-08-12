"""Provider-neutral read-only MCP Agent for declarative catalog entries."""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import AsyncExitStack
from copy import deepcopy
from datetime import UTC, timedelta
from typing import Any

import httpx
from jsonschema import Draft202012Validator
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.application.sanitization import REDACTED, sanitize
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.models import (
    InvestigationContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.tool_calling import MCPToolCallingModel
from app.mcp_catalog import MCPServerDescriptor, ResolvedMCPConnection

_FINISH_TOOL = "finish_investigation"
_MAX_STEPS_DEFAULT = 8
_MAX_TOOL_LIST_PAGES = 10
_SENSITIVE_TEXT_MARKERS = (
    "://",
    "authorization",
    "bearer ",
    "password",
    "passwd",
    "pwd=",
    "pwd:",
    "secret",
    "token",
    "api_key",
    "api-key",
    "credential",
    "connection_string",
    "connection-string",
    "?key=",
    "&key=",
)


def _sanitize_complete(value: Any, key: str | None = None) -> Any:
    """Sanitize MCP data without applying costly regexes to ordinary large logs."""

    if value is None:
        return None
    if key and sanitize("", key) == REDACTED:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_complete(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_complete(item) for item in value]
    if isinstance(value, str):
        folded = value.casefold()
        if not any(marker in folded for marker in _SENSITIVE_TEXT_MARKERS):
            return value
    return sanitize(value, key)


def _no_redirect_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """Build an MCP transport client without forwarding credentials via redirects."""

    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=False,
    )


def _has_result_data(value: Any, *, content_item: bool = False) -> bool:
    """Return whether a sanitized MCP result contains an actual observation."""

    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (int, float, bool)):
        return True
    if isinstance(value, (list, tuple)):
        return any(_has_result_data(item, content_item=True) for item in value)
    if not isinstance(value, dict):
        return True

    ignored_keys = {
        "_meta",
        "isError",
        "is_error",
        "meta",
    }
    if content_item:
        ignored_keys.add("type")
    return any(
        _has_result_data(item_value, content_item=content_item)
        for item_key, item_value in value.items()
        if item_key not in ignored_keys
    )


class GenericMCPConfigurationError(ValueError):
    """A generic MCP descriptor cannot be executed safely."""


class GenericMCPReadOnlyViolation(ValueError):
    """A remote MCP tool did not meet the explicit read-only contract."""


class GenericReadOnlyMCPEvidenceTool:
    """Run one selected MCP in an isolated, bounded tool-calling conversation."""

    read_only = True
    input_schema = {"type": "object", "properties": {}, "additionalProperties": False}
    max_attempts = 1

    def __init__(
        self,
        descriptor: MCPServerDescriptor,
        connection: ResolvedMCPConnection,
        model: MCPToolCallingModel,
        *,
        timeout_seconds: float = 60,
    ) -> None:
        if descriptor.read_only is not True:
            raise GenericMCPConfigurationError(
                f"MCP server {descriptor.name!r} is not explicitly read-only"
            )
        self.descriptor = descriptor
        self.connection = connection
        self.model = model
        self.timeout_seconds = timeout_seconds
        raw_steps = descriptor.provider_options.get("maxAgentSteps", _MAX_STEPS_DEFAULT)
        if type(raw_steps) is not int or not 1 <= raw_steps <= 100:
            raise GenericMCPConfigurationError("maxAgentSteps must be an integer from 1 to 100")
        self.max_agent_steps = raw_steps
        transport = str(descriptor.provider_options.get("transport") or "streamable_http")
        if transport not in {"streamable_http", "sse"}:
            raise GenericMCPConfigurationError("transport must be streamable_http or sse")
        self.transport = transport
        self.name = f"query_mcp_{descriptor.name}"
        self.source_system = f"{descriptor.name}_mcp"
        self.capability = descriptor.prompts.purpose
        self.policy_version = "declarative-mcp-read-only-v1"
        self.default_timeout_seconds = timeout_seconds * max(2, self.max_agent_steps)

    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> ToolExecutionResult:
        if request.parameters:
            raise GenericMCPReadOnlyViolation(
                "Generic MCP arguments are derived exclusively from the trusted alert context"
            )
        alert = preprocess_normalized_alert(context.alert)
        window_end = alert.occurred_at.astimezone(UTC)
        window_start = window_end - timedelta(minutes=5)
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": self.descriptor.prompts.execution_instructions,
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": request.objective or self.descriptor.prompts.purpose,
                        "read_only": True,
                        "alert": alert.model_dump(mode="json", exclude={"raw_payload"}),
                        "query_window": {
                            "start": window_start.isoformat(),
                            "end": window_end.isoformat(),
                        },
                        "instruction": (
                            "Use only explicitly read-only tools. You may call another tool "
                            "after inspecting each result. Finish when enough relevant data "
                            "has been collected or no safe useful call remains."
                        ),
                    },
                    ensure_ascii=False,
                ),
            },
        ]

        async with AsyncExitStack() as stack:
            session = await self._open_session(stack)
            remote_tools = await self._list_tools(session)
            tools = [self._tool_definition(item) for item in remote_tools]
            tool_names = [item["function"]["name"] for item in tools]
            if len(tool_names) != len(set(tool_names)):
                raise GenericMCPConfigurationError(
                    "MCP returned duplicate tool names across tool-list pages"
                )
            if not tools:
                return ToolExecutionResult(
                    status=ToolStatus.NO_DATA,
                    summary=f"MCP {self.descriptor.name} 未声明可调用的只读工具。",
                    structured_data={"reason_code": "no_explicit_read_only_tools"},
                )
            finish_tool = {
                "type": "function",
                "function": {
                    "name": _FINISH_TOOL,
                    "description": "Finish this MCP investigation without another remote call.",
                    "parameters": {
                        "type": "object",
                        "properties": {"reason": {"type": "string"}},
                        "required": ["reason"],
                        "additionalProperties": False,
                    },
                },
            }
            observations: list[dict[str, Any]] = []
            finished_by_model = False
            for _ in range(self.max_agent_steps):
                call = await self.model.request_mcp_tool_call(
                    messages=deepcopy(messages), tools=[*tools, finish_tool]
                )
                if call.name == _FINISH_TOOL:
                    finished_by_model = True
                    break
                definition = next(
                    (item for item in tools if item["function"]["name"] == call.name), None
                )
                if definition is None:
                    raise GenericMCPReadOnlyViolation(
                        f"Model selected an unapproved MCP tool: {call.name}"
                    )
                Draft202012Validator(definition["function"]["parameters"]).validate(
                    call.arguments
                )
                async with asyncio.timeout(self.timeout_seconds):
                    raw_result = await session.call_tool(call.name, call.arguments)
                raw_payload = raw_result.model_dump(
                    mode="json", by_alias=True, exclude_none=False
                )
                if not isinstance(raw_payload, dict):
                    raise GenericMCPConfigurationError(
                        "MCP returned a non-object tool result"
                    )
                result = _sanitize_complete(raw_payload)
                assert isinstance(result, dict)
                is_error = result.get("isError") is True or result.get("is_error") is True
                has_data = not is_error and _has_result_data(result)
                observation = {
                    "tool_name": call.name,
                    "arguments": sanitize(call.arguments),
                    "result": result,
                    "is_error": is_error,
                    "has_data": has_data,
                }
                observations.append(observation)
                messages.append(
                    {
                        "role": "user",
                        "content": json.dumps(observation, ensure_ascii=False, default=str),
                    }
                )

        if not observations:
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=f"Agent 判断 MCP {self.descriptor.name} 无需执行远端查询。",
                structured_data={"reason_code": "no_useful_read_only_call"},
            )
        successful_observations = [
            item for item in observations if item["has_data"] and not item["is_error"]
        ]
        if not successful_observations:
            errors_only = all(item["is_error"] for item in observations)
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=(
                    f"MCP {self.descriptor.name} 的只读调用均返回错误。"
                    if errors_only
                    else f"MCP {self.descriptor.name} 未返回可用于分析的数据。"
                ),
                structured_data={
                    "server": self.descriptor.name,
                    "read_only": True,
                    "observations": observations,
                    "successful_observation_count": 0,
                    "finished_by_model": finished_by_model,
                    "partial": not finished_by_model,
                    "termination_reason": (
                        "remote_tool_errors"
                        if errors_only
                        else "empty_remote_results"
                    ),
                    "reason_code": (
                        "remote_tool_errors" if errors_only else "empty_remote_results"
                    ),
                    "root_cause_eligible": False,
                },
            )
        return ToolExecutionResult(
            status=ToolStatus.SUCCESS,
            summary=(
                f"MCP {self.descriptor.name} 已完成 {len(observations)} 次只读调用。"
                if finished_by_model
                else (
                    f"MCP {self.descriptor.name} 已达到 {self.max_agent_steps} 次调用预算，"
                    "调查结果不完整。"
                )
            ),
            structured_data={
                "server": self.descriptor.name,
                "read_only": True,
                "observations": observations,
                "successful_observation_count": len(successful_observations),
                "finished_by_model": finished_by_model,
                "partial": not finished_by_model,
                "termination_reason": (
                    "model_finished" if finished_by_model else "max_agent_steps_reached"
                ),
                "root_cause_eligible": finished_by_model,
            },
        )

    async def _open_session(self, stack: AsyncExitStack) -> ClientSession:
        if self.transport == "sse":
            read_stream, write_stream = await stack.enter_async_context(
                sse_client(
                    self.connection.url,
                    headers=dict(self.connection.headers),
                    timeout=self.timeout_seconds,
                    sse_read_timeout=self.timeout_seconds,
                    httpx_client_factory=_no_redirect_http_client,
                )
            )
        else:
            http_client = await stack.enter_async_context(
                httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout_seconds),
                    headers=dict(self.connection.headers),
                    follow_redirects=False,
                )
            )
            read_stream, write_stream, _ = await stack.enter_async_context(
                streamable_http_client(self.connection.url, http_client=http_client)
            )
        session = await stack.enter_async_context(
            ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=self.timeout_seconds),
                client_info=mcp_types.Implementation(
                    name="database-alert-agent", version="0.1.0"
                ),
            )
        )
        await session.initialize()
        return session

    async def _list_tools(self, session: ClientSession) -> list[Any]:
        tools: list[Any] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for page in range(_MAX_TOOL_LIST_PAGES):
            listed = (
                await session.list_tools()
                if page == 0
                else await session.list_tools(cursor=cursor)
            )
            tools.extend(listed.tools)
            raw_cursor = getattr(listed, "nextCursor", None)
            if raw_cursor is None:
                raw_cursor = getattr(listed, "next_cursor", None)
            if not raw_cursor:
                return tools
            if not isinstance(raw_cursor, str) or raw_cursor in seen_cursors:
                raise GenericMCPConfigurationError(
                    "MCP returned an invalid or repeated tool-list cursor"
                )
            seen_cursors.add(raw_cursor)
            cursor = raw_cursor
        raise GenericMCPConfigurationError(
            f"MCP tool listing exceeded {_MAX_TOOL_LIST_PAGES} pages"
        )

    def _tool_definition(self, tool: Any) -> dict[str, Any]:
        raw = tool.model_dump(mode="json", exclude_none=True)
        annotations = raw.get("annotations")
        if not isinstance(annotations, dict):
            raise GenericMCPReadOnlyViolation(
                f"MCP tool {raw.get('name')!r} has no explicit read-only annotation"
            )
        read_only = annotations.get("readOnlyHint", annotations.get("read_only_hint"))
        destructive = annotations.get("destructiveHint", annotations.get("destructive_hint"))
        if read_only is not True or destructive is True:
            raise GenericMCPReadOnlyViolation(
                f"MCP tool {raw.get('name')!r} is not explicitly read-only"
            )
        name = raw.get("name")
        schema = raw.get("inputSchema") or raw.get("input_schema")
        if not isinstance(name, str) or not name or not isinstance(schema, dict):
            raise GenericMCPConfigurationError("MCP returned an invalid tool contract")
        canonical_schema = json.dumps(schema, sort_keys=True, separators=(",", ":"))
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": (
                    str(raw.get("description") or "Read-only MCP tool")
                    + " [read_only=true; schema_sha256="
                    + hashlib.sha256(canonical_schema.encode()).hexdigest()[:16]
                    + "]"
                ),
                "parameters": schema,
            },
        }
