"""Provider-neutral MCP Agent for declarative catalog entries."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
from collections import Counter
from collections.abc import Mapping
from contextlib import AsyncExitStack
from copy import deepcopy
from datetime import UTC, timedelta
from typing import Any
from uuid import UUID, uuid5

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.agent_runtime.contracts import ArtifactRef
from app.agent_runtime.events import AgentEventKind, EventSink, InMemoryEventSink
from app.agent_runtime.persistence import RepositoryEventSink
from app.agent_runtime.trace import AgentTraceEmitter, AgentTraceScope
from app.application.sanitization import REDACTED, sanitize
from app.domain.alert_preprocessing import preprocess_normalized_alert
from app.domain.models import (
    InvestigationContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)
from app.domain.ports import AlertRepository
from app.domain.tool_calling import MCPToolCallingModel, mcp_tool_result_messages
from app.mcp_catalog import MCPServerDescriptor, ResolvedMCPConnection

_FINISH_TOOL_PREFIX = "finish_investigation"
_REMOTE_RESPONSE_ARTIFACT_CONTRACT = "declarative-mcp-remote-response/v1"
_MAX_MODEL_NUMERIC_GROUPS = 20
_MAX_MODEL_SCALAR_GROUPS = 40
_MAX_MODEL_SAMPLES_PER_GROUP = 3
_MAX_MODEL_SAMPLE_CHARS = 500
_MAX_MODEL_SOURCE_PATHS = 3
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
_INFRASTRUCTURE_PROJECTION_KEYS = {
    "_meta",
    "artifact",
    "artifact_id",
    "artifact_ref",
    "artifact_uri",
    "digest",
    "hash",
    "internal_audit_artifact",
    "meta",
    "request_id",
    "sha256",
    "source_artifact",
    "source_artifact_id",
    "source_artifact_uri",
    "source_sha256",
    "uri",
    "usage",
}
_INFRASTRUCTURE_PROJECTION_KEY_FORMS = {
    key.replace("_", "") for key in _INFRASTRUCTURE_PROJECTION_KEYS
}
_INTERNAL_ARTIFACT_URI_PREFIX = "agent-artifact://"


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


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _is_infrastructure_projection_key(value: str) -> bool:
    normalized = value.strip().casefold().replace("-", "_")
    return normalized.startswith("raw_") or (
        normalized.replace("_", "") in _INFRASTRUCTURE_PROJECTION_KEY_FORMS
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _bounded_scalar(value: Any) -> Any:
    if not isinstance(value, str) or len(value) <= _MAX_MODEL_SAMPLE_CHARS:
        return value
    return {
        "excerpt": value[:_MAX_MODEL_SAMPLE_CHARS],
        "total_chars": len(value),
    }


def _accepts_keyword_argument(callable_obj: Any, argument: str) -> bool:
    try:
        parameters = inspect.signature(callable_obj).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == argument or parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _display_number(value: float) -> int | float:
    return int(value) if value.is_integer() else round(value, 6)


def _project_result_for_model(
    result: dict[str, Any],
    *,
    source_path: str,
    is_error: bool,
) -> dict[str, Any]:
    """Project one complete response into bounded deterministic facts.

    Values are grouped by structural JSON Pointer (list indexes become ``*``),
    aggregated, and deterministically ranked. Internal artifact provenance and raw
    response envelopes are excluded recursively; retained facts remain traceable by
    exact JSON Pointer without exposing artifact identities, URIs, or hashes.
    """

    source_json_chars = len(_canonical_json(result))
    shape: Counter[str] = Counter()
    ignored_field_count = 0
    numeric: dict[str, dict[str, Any]] = {}
    scalar: dict[str, dict[str, Any]] = {}

    def remember_source(bucket: dict[str, Any], path: str) -> None:
        paths = bucket.setdefault("source_paths", [])
        if len(paths) < _MAX_MODEL_SOURCE_PATHS and path not in paths:
            paths.append(path)

    def visit(
        value: Any,
        *,
        exact_path: str,
        pattern_path: str,
        content_item: bool = False,
    ) -> None:
        nonlocal ignored_field_count
        if isinstance(value, Mapping):
            shape["objects"] += 1
            for raw_key, child in sorted(value.items(), key=lambda item: str(item[0])):
                key = str(raw_key)
                normalized_key = key.strip().casefold().replace("-", "_")
                if (
                    _is_infrastructure_projection_key(key)
                    or normalized_key in {"iserror", "is_error"}
                    or (content_item and normalized_key == "type")
                ):
                    ignored_field_count += 1
                    continue
                pointer = _pointer_token(key)
                visit(
                    child,
                    exact_path=f"{exact_path}/{pointer}",
                    pattern_path=f"{pattern_path}/{pointer}",
                )
            return
        if isinstance(value, (list, tuple)):
            shape["arrays"] += 1
            shape["array_items"] += len(value)
            children_are_content_items = pattern_path.casefold().endswith("/content")
            for index, child in enumerate(value):
                visit(
                    child,
                    exact_path=f"{exact_path}/{index}",
                    pattern_path=f"{pattern_path}/*",
                    content_item=children_are_content_items,
                )
            return
        if value is None:
            shape["nulls"] += 1
            return
        if isinstance(value, bool):
            shape["booleans"] += 1
        elif isinstance(value, (int, float)) and math.isfinite(float(value)):
            shape["numbers"] += 1
            number = float(value)
            bucket = numeric.setdefault(
                pattern_path,
                {
                    "count": 0,
                    "sum": 0.0,
                    "min": number,
                    "max": number,
                    "first": number,
                    "latest": number,
                },
            )
            bucket["count"] += 1
            bucket["sum"] += number
            bucket["min"] = min(bucket["min"], number)
            bucket["max"] = max(bucket["max"], number)
            bucket["latest"] = number
            remember_source(bucket, exact_path)
            return
        elif isinstance(value, str):
            if value.strip().casefold().startswith(_INTERNAL_ARTIFACT_URI_PREFIX):
                ignored_field_count += 1
                return
            shape["strings"] += 1
            if not value.strip():
                shape["blank_strings"] += 1
                return
        else:
            shape["other_scalars"] += 1

        bucket = scalar.setdefault(pattern_path, {"count": 0, "samples": {}})
        bucket["count"] += 1
        projected_value = _bounded_scalar(value)
        sample_key = _canonical_json(projected_value)
        samples: dict[str, dict[str, Any]] = bucket["samples"]
        samples.setdefault(
            sample_key,
            {"value": projected_value, "source_path": exact_path},
        )
        if len(samples) > _MAX_MODEL_SAMPLES_PER_GROUP:
            for key in sorted(samples)[_MAX_MODEL_SAMPLES_PER_GROUP:]:
                del samples[key]

    visit(result, exact_path=source_path, pattern_path=source_path)

    numeric_aggregates: list[dict[str, Any]] = []
    for path, bucket in numeric.items():
        count = int(bucket["count"])
        numeric_aggregates.append(
            {
                "path_pattern": path,
                "count": count,
                "min": _display_number(bucket["min"]),
                "max": _display_number(bucket["max"]),
                "avg": _display_number(bucket["sum"] / count),
                "first": _display_number(bucket["first"]),
                "latest": _display_number(bucket["latest"]),
                "delta": _display_number(bucket["latest"] - bucket["first"]),
                "source_paths": bucket["source_paths"],
                "omitted_source_path_count": max(count - len(bucket["source_paths"]), 0),
            }
        )
    numeric_aggregates.sort(key=lambda item: (-int(item["count"]), item["path_pattern"]))

    scalar_groups: list[dict[str, Any]] = []
    for path, bucket in scalar.items():
        samples = [bucket["samples"][key] for key in sorted(bucket["samples"])]
        scalar_groups.append(
            {
                "path_pattern": path,
                "value_count": bucket["count"],
                "samples": samples,
                "omitted_value_count": max(bucket["count"] - len(samples), 0),
            }
        )
    scalar_groups.sort(key=lambda item: (-int(item["value_count"]), item["path_pattern"]))

    has_data = not is_error and bool(numeric_aggregates or scalar_groups)
    return {
        "projection_type": "deterministic_fact_projection",
        "source_path": source_path,
        "source_json_chars": source_json_chars,
        "is_error": is_error,
        "has_data": has_data,
        "payload_shape": dict(sorted(shape.items())),
        "ignored_metadata_field_count": ignored_field_count,
        "numeric_aggregates": numeric_aggregates[:_MAX_MODEL_NUMERIC_GROUPS],
        "omitted_numeric_group_count": max(len(numeric_aggregates) - _MAX_MODEL_NUMERIC_GROUPS, 0),
        "scalar_groups": scalar_groups[:_MAX_MODEL_SCALAR_GROUPS],
        "omitted_scalar_group_count": max(len(scalar_groups) - _MAX_MODEL_SCALAR_GROUPS, 0),
    }


class GenericMCPConfigurationError(ValueError):
    """A generic MCP descriptor or protocol response is invalid."""


class GenericMCPEvidenceTool:
    """Run one selected MCP in an isolated tool-calling conversation."""

    input_schema = {"type": "object", "additionalProperties": True}

    def __init__(
        self,
        descriptor: MCPServerDescriptor,
        connection: ResolvedMCPConnection,
        model: MCPToolCallingModel,
        *,
        timeout_seconds: float = 60,
        repository: AlertRepository | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        if repository is not None and event_sink is not None:
            raise ValueError("repository and event_sink are mutually exclusive")
        self.descriptor = descriptor
        self.connection = connection
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.repository = repository
        self.event_sink = event_sink or InMemoryEventSink()
        transport = str(descriptor.provider_options.get("transport") or "streamable_http")
        if transport not in {"streamable_http", "sse"}:
            raise GenericMCPConfigurationError("transport must be streamable_http or sse")
        self.transport = transport
        self.name = f"query_mcp_{descriptor.name}"
        self.source_system = f"{descriptor.name}_mcp"
        self.role = descriptor.prompts.role
        self.capability = descriptor.prompts.purpose
        self.workflow = descriptor.prompts.workflow
        self.safety = descriptor.prompts.safety
        self.policy_version = "declarative-mcp-discovery-v1"
        self.default_timeout_seconds = timeout_seconds

    async def execute(
        self,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> ToolExecutionResult:
        alert = preprocess_normalized_alert(context.alert)
        window_end = alert.occurred_at.astimezone(UTC)
        window_start = window_end - timedelta(minutes=5)
        trace = self._trace_emitter(context)
        trace_scope = str(context.outer_dispatch_id or context.run_id)
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
                        "caller_parameters": request.parameters,
                        "alert": alert.model_dump(mode="json", exclude={"raw_payload"}),
                        "query_window": {
                            "start": window_start.isoformat(),
                            "end": window_end.isoformat(),
                        },
                        "instruction": (
                            "Choose from the tools discovered in this MCP session. You may call "
                            "another tool "
                            "after inspecting each result. Finish when enough relevant data "
                            "has been collected or no useful call remains."
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
            if not tools:
                return ToolExecutionResult(
                    status=ToolStatus.NO_DATA,
                    summary=f"MCP {self.descriptor.name} 未声明可调用工具。",
                    structured_data={"reason_code": "no_discovered_tools"},
                )
            remote_tool_names = {
                item["function"]["name"]
                for item in tools
                if isinstance(item.get("function"), dict)
                and isinstance(item["function"].get("name"), str)
            }
            finish_tool_name = self._local_finish_tool_name(remote_tool_names)
            finish_tool = {
                "type": "function",
                "function": {
                    "name": finish_tool_name,
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
            decision_round = 0
            while True:
                decision_round += 1
                trace_prefix = (
                    f"declarative-mcp:{self.descriptor.name}:{trace_scope}:{decision_round}"
                )
                request_attempt = await self._next_reasoning_request_attempt(
                    trace,
                    context.run_id,
                    prefix=f"{trace_prefix}:reasoning:request:",
                )
                stream_id = f"{trace_prefix}:reasoning:request:{request_attempt}"
                reasoning_callback_invoked = False

                async def emit_reasoning_delta(
                    content: str,
                    delta_index: int,
                    durable_stream_id: str = stream_id,
                ) -> None:
                    nonlocal reasoning_callback_invoked
                    emitted = await trace.emit_reasoning_delta(
                        content,
                        stream_id=durable_stream_id,
                        delta_index=delta_index,
                        trace_key=f"{durable_stream_id}:delta:{delta_index}",
                    )
                    reasoning_callback_invoked = reasoning_callback_invoked or emitted is not None

                model_kwargs = {
                    "messages": deepcopy(messages),
                    "tools": [*tools, finish_tool],
                }
                if _accepts_keyword_argument(
                    self.model.request_mcp_tool_call,
                    "reasoning_callback",
                ):
                    call = await self.model.request_mcp_tool_call(
                        **model_kwargs,
                        reasoning_callback=emit_reasoning_delta,
                    )
                else:
                    call = await self.model.request_mcp_tool_call(**model_kwargs)
                if not reasoning_callback_invoked:
                    await trace.emit_reasoning(
                        call.reasoning_content,
                        trace_key=f"{stream_id}:complete",
                    )
                await trace.emit_action(
                    json.dumps(
                        {
                            "action": "finish" if call.name == finish_tool_name else "call_tool",
                            "tool_name": call.name,
                            "arguments": sanitize(call.arguments),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                    ),
                    trace_key=f"{trace_prefix}:action",
                )
                if call.name == finish_tool_name:
                    finished_by_model = True
                    break
                async with asyncio.timeout(self.timeout_seconds):
                    raw_result = await session.call_tool(call.name, call.arguments)
                raw_payload = raw_result.model_dump(mode="json", by_alias=True, exclude_none=False)
                if not isinstance(raw_payload, dict):
                    raise GenericMCPConfigurationError("MCP returned a non-object tool result")
                result = _sanitize_complete(raw_payload)
                assert isinstance(result, dict)
                observation_index = len(observations)
                await self._persist_remote_response_artifact(
                    request=request,
                    context=context,
                    tool_name=call.name,
                    arguments=call.arguments,
                    result=result,
                    response_index=observation_index,
                    decision_round=decision_round,
                )
                is_error = result.get("isError") is True or result.get("is_error") is True
                projection = _project_result_for_model(
                    result,
                    source_path="/result",
                    is_error=is_error,
                )
                has_data = projection["has_data"] is True
                observation = {
                    "tool_name": call.name,
                    "arguments": sanitize(call.arguments),
                    "response_ordinal": observation_index + 1,
                    "decision_round": decision_round,
                    "projection": projection,
                    "is_error": is_error,
                    "has_data": has_data,
                }
                observations.append(observation)
                await trace.emit_observation(
                    json.dumps(
                        {
                            "observation_type": "program_fact_projection",
                            "tool_name": call.name,
                            "projection": projection,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                    ),
                    actor=call.name,
                    provider=self.source_system,
                    trace_key=f"{trace_prefix}:observation",
                )
                model_observation = json.dumps(
                    {
                        "observation_type": "program_fact_projection",
                        "tool_name": call.name,
                        "arguments": sanitize(call.arguments),
                        "projection": projection,
                        "instruction": (
                            "Use only these program-projected facts when choosing the "
                            "next action. The complete response is retained only in the "
                            "internal audit artifact."
                        ),
                    },
                    ensure_ascii=False,
                    default=str,
                )
                messages.extend(
                    mcp_tool_result_messages(
                        call,
                        output=model_observation,
                        fallback_messages=[{"role": "user", "content": model_observation}],
                    )
                )

        if not observations:
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=f"Agent 判断 MCP {self.descriptor.name} 无需执行远端查询。",
                structured_data={"reason_code": "no_useful_call"},
            )
        successful_observations = [
            item for item in observations if item["has_data"] and not item["is_error"]
        ]
        if not successful_observations:
            errors_only = all(item["is_error"] for item in observations)
            return ToolExecutionResult(
                status=ToolStatus.NO_DATA,
                summary=(
                    f"MCP {self.descriptor.name} 的调用均返回错误。"
                    if errors_only
                    else f"MCP {self.descriptor.name} 未返回可用于分析的数据。"
                ),
                structured_data={
                    "server": self.descriptor.name,
                    "observations": observations,
                    "successful_observation_count": 0,
                    "finished_by_model": finished_by_model,
                    "partial": False,
                    "termination_reason": (
                        "remote_tool_errors" if errors_only else "empty_remote_results"
                    ),
                    "reason_code": (
                        "remote_tool_errors" if errors_only else "empty_remote_results"
                    ),
                    "root_cause_eligible": False,
                },
            )
        return ToolExecutionResult(
            status=ToolStatus.SUCCESS,
            summary=f"MCP {self.descriptor.name} 已完成 {len(observations)} 次调用。",
            structured_data={
                "server": self.descriptor.name,
                "observations": observations,
                "successful_observation_count": len(successful_observations),
                "finished_by_model": finished_by_model,
                "partial": False,
                "termination_reason": "model_finished",
                "root_cause_eligible": True,
            },
        )

    async def _persist_remote_response_artifact(
        self,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        response_index: int,
        decision_round: int,
    ) -> ArtifactRef | None:
        """Durably retain one complete response before any later fallible work."""

        if self.repository is None:
            return None
        invocation_id = self._audit_invocation_id(request=request, context=context)
        artifact_id = uuid5(
            invocation_id,
            f"{_REMOTE_RESPONSE_ARTIFACT_CONTRACT}:{self.descriptor.name}:"
            f"response:{response_index + 1}",
        )
        artifact = ArtifactRef(
            artifact_id=artifact_id,
            kind="declarative_mcp_remote_response",
            media_type="application/json",
            uri=f"agent-artifact://{artifact_id}",
            metadata={
                "contract": _REMOTE_RESPONSE_ARTIFACT_CONTRACT,
                "server": self.descriptor.name,
                "source_system": self.source_system,
                "tool_name": tool_name,
                "response_ordinal": response_index + 1,
                "decision_round": decision_round,
                "sanitized": True,
                "internal_only": True,
            },
        )
        content = {
            "contract": _REMOTE_RESPONSE_ARTIFACT_CONTRACT,
            "server": self.descriptor.name,
            "source_system": self.source_system,
            "tool_name": tool_name,
            "arguments": sanitize(arguments),
            "response_ordinal": response_index + 1,
            "decision_round": decision_round,
            "result": result,
        }
        return await self.repository.save_agent_artifact(
            str(context.run_id),
            artifact,
            content,
            invocation_id=(str(invocation_id) if context.outer_dispatch_id is not None else None),
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )

    def _audit_invocation_id(
        self,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
    ) -> UUID:
        if context.outer_dispatch_id is not None:
            # Keep the durable outer-dispatch invocation UUID contract stable.
            return uuid5(context.outer_dispatch_id, "attempt:1")
        direct_call = {
            "tool_name": request.tool_name,
            "objective": request.objective,
            "parameters": request.parameters,
        }
        request_digest = hashlib.sha256(_canonical_json(direct_call).encode("utf-8")).hexdigest()
        return uuid5(
            context.run_id,
            f"{_REMOTE_RESPONSE_ARTIFACT_CONTRACT}:direct:{self.descriptor.name}:{request_digest}",
        )

    def _trace_emitter(self, context: InvestigationContext) -> AgentTraceEmitter:
        sink: EventSink
        if self.repository is None:
            sink = self.event_sink
        else:
            sink = RepositoryEventSink(
                self.repository,
                lease_owner=context.lease_owner,
                fencing_token=context.fencing_token,
            )
        return AgentTraceEmitter(
            sink,
            run_id=context.run_id,
            actor=f"{self.descriptor.name}_mcp_agent",
            provider=self.source_system,
            scope=AgentTraceScope.MCP_INTERNAL,
        )

    @staticmethod
    def _local_finish_tool_name(remote_tool_names: set[str]) -> str:
        """Choose a local finish action without shadowing a server-owned tool name."""

        candidate = _FINISH_TOOL_PREFIX
        suffix = 2
        while candidate in remote_tool_names:
            candidate = f"{_FINISH_TOOL_PREFIX}_{suffix}"
            suffix += 1
        return candidate

    @staticmethod
    async def _next_reasoning_request_attempt(
        trace: AgentTraceEmitter,
        run_id: UUID,
        *,
        prefix: str,
    ) -> int:
        attempts: list[int] = []
        for event in await trace.sink.read(run_id):
            if event.kind != AgentEventKind.TRACE_REASONING:
                continue
            stream_id = event.payload.get("stream_id")
            if not isinstance(stream_id, str) or not stream_id.startswith(prefix):
                continue
            suffix = stream_id.removeprefix(prefix)
            if suffix.isdigit():
                attempts.append(int(suffix))
        return max(attempts, default=-1) + 1

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
                client_info=mcp_types.Implementation(name="database-alert-agent", version="0.1.0"),
            )
        )
        await session.initialize()
        return session

    async def _list_tools(self, session: ClientSession) -> list[Any]:
        tools: list[Any] = []
        cursor: Any = None
        seen_cursors: set[str] = set()
        first_page = True
        while True:
            listed = (
                await session.list_tools()
                if first_page
                else await session.list_tools(cursor=cursor)
            )
            first_page = False
            tools.extend(listed.tools)
            raw_cursor = getattr(listed, "nextCursor", None)
            if raw_cursor is None:
                raw_cursor = getattr(listed, "next_cursor", None)
            if not raw_cursor:
                return tools
            cursor_identity = _canonical_json(raw_cursor)
            if cursor_identity in seen_cursors:
                raise GenericMCPConfigurationError("MCP returned a repeated tool-list cursor")
            seen_cursors.add(cursor_identity)
            cursor = raw_cursor

    def _tool_definition(self, tool: Any) -> dict[str, Any]:
        raw = tool.model_dump(mode="json", exclude_none=True)
        name = raw.get("name")
        schema = raw.get("inputSchema") if "inputSchema" in raw else raw.get("input_schema")
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": str(raw.get("description") or f"MCP tool {name}"),
                "parameters": schema,
            },
        }
