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
from dataclasses import dataclass
from datetime import UTC, timedelta
from typing import Any
from uuid import UUID, uuid5

import httpx
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.agent_runtime.contracts import ArtifactRef, RunCheckpoint
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
from app.domain.tool_calling import (
    MCPModelToolCall,
    MCPToolCallingModel,
    mcp_tool_result_messages,
)
from app.mcp_catalog import MCPServerDescriptor, ResolvedMCPConnection

_FINISH_TOOL_PREFIX = "finish_investigation"
_REMOTE_RESPONSE_ARTIFACT_CONTRACT = "declarative-mcp-remote-response/v2"
_CHECKPOINT_CONTRACT = "declarative-mcp-investigation-checkpoint/v1"
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


@dataclass(frozen=True, slots=True)
class _DeferredRemoteResponse:
    """One complete response retained in memory until the MCP session closes."""

    tool_name: str
    arguments: dict[str, Any]
    envelope: dict[str, Any]
    model_call: MCPModelToolCall
    response_index: int
    decision_round: int


@dataclass(slots=True)
class _GenericMCPExecutionState:
    """Durable state required to continue one declarative MCP investigation."""

    messages: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    remote_responses: list[_DeferredRemoteResponse]
    decision_round: int = 0
    pending_response_index: int | None = None
    finished_by_model: bool = False
    completed: bool = False


@dataclass(slots=True)
class _CheckpointCursor:
    namespace: str
    manifest_hash: str
    invocation_id: UUID
    version: int = 0


def _sanitize_complete(value: Any, key: str | None = None) -> Any:
    """Build a safe projection copy without touching the raw model envelope."""

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
        initial_messages: list[dict[str, Any]] = [
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
        state, checkpoint = await self._restore_execution_state(
            request=request,
            context=context,
            initial_messages=initial_messages,
        )
        if state.completed:
            await self._persist_remote_response_artifacts(
                request=request,
                context=context,
                responses=state.remote_responses,
            )
            return self._execution_result(state)

        no_tools_result: ToolExecutionResult | None = None
        try:
            if state.pending_response_index is not None:
                await self._apply_remote_response(
                    state,
                    state.remote_responses[state.pending_response_index],
                    trace=trace,
                    trace_scope=trace_scope,
                )
                state.pending_response_index = None
                await self._save_execution_checkpoint(
                    state,
                    context=context,
                    cursor=checkpoint,
                )

            async with AsyncExitStack() as stack:
                session = await self._open_session(stack)
                remote_tools = await self._list_tools(session)
                tools = [self._tool_definition(item) for item in remote_tools]
                if not tools:
                    no_tools_result = ToolExecutionResult(
                        status=ToolStatus.NO_DATA,
                        summary=f"MCP {self.descriptor.name} 未声明可调用工具。",
                        structured_data={"reason_code": "no_discovered_tools"},
                    )
                else:
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
                            "description": (
                                "Finish this MCP investigation without another remote call."
                            ),
                            "parameters": {
                                "type": "object",
                                "properties": {"reason": {"type": "string"}},
                                "required": ["reason"],
                                "additionalProperties": False,
                            },
                        },
                    }

                while no_tools_result is None:
                    state.decision_round += 1
                    trace_prefix = (
                        f"declarative-mcp:{self.descriptor.name}:"
                        f"{trace_scope}:{state.decision_round}"
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
                        reasoning_callback_invoked = (
                            reasoning_callback_invoked or emitted is not None
                        )

                    model_kwargs = {
                        "messages": deepcopy(state.messages),
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
                                "action": (
                                    "finish" if call.name == finish_tool_name else "call_tool"
                                ),
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
                        state.finished_by_model = True
                        state.completed = True
                        await self._save_execution_checkpoint(
                            state,
                            context=context,
                            cursor=checkpoint,
                        )
                        break

                    async with asyncio.timeout(self.timeout_seconds):
                        raw_result = await session.call_tool(call.name, call.arguments)
                    raw_payload = raw_result.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=False,
                    )
                    if not isinstance(raw_payload, dict):
                        raise GenericMCPConfigurationError(
                            "MCP returned a non-object tool result"
                        )
                    response_index = len(state.remote_responses)
                    response = _DeferredRemoteResponse(
                        tool_name=call.name,
                        arguments=deepcopy(call.arguments),
                        envelope=deepcopy(raw_payload),
                        model_call=deepcopy(call),
                        response_index=response_index,
                        decision_round=state.decision_round,
                    )
                    state.remote_responses.append(response)
                    state.pending_response_index = response_index
                    await self._save_execution_checkpoint(
                        state,
                        context=context,
                        cursor=checkpoint,
                    )
                    await self._apply_remote_response(
                        state,
                        response,
                        trace=trace,
                        trace_scope=trace_scope,
                    )
                    state.pending_response_index = None
                    await self._save_execution_checkpoint(
                        state,
                        context=context,
                        cursor=checkpoint,
                    )
        except asyncio.CancelledError as exc:
            try:
                await self._persist_remote_response_artifacts(
                    request=request,
                    context=context,
                    responses=state.remote_responses,
                )
            except BaseException as persist_error:
                exc.add_note(
                    "Generic MCP raw-response artifact persistence also failed: "
                    f"{type(persist_error).__name__}: {persist_error}"
                )
            raise
        except Exception as exc:
            try:
                await self._persist_remote_response_artifacts(
                    request=request,
                    context=context,
                    responses=state.remote_responses,
                )
            except BaseException as persist_error:
                exc.add_note(
                    "Generic MCP raw-response artifact persistence also failed: "
                    f"{type(persist_error).__name__}: {persist_error}"
                )
            raise

        await self._persist_remote_response_artifacts(
            request=request,
            context=context,
            responses=state.remote_responses,
        )
        if no_tools_result is not None:
            return no_tools_result
        return self._execution_result(state)

    async def _apply_remote_response(
        self,
        state: _GenericMCPExecutionState,
        response: _DeferredRemoteResponse,
        *,
        trace: AgentTraceEmitter,
        trace_scope: str,
    ) -> None:
        """Project one staged response and append its unmodified model feedback."""

        if response.response_index != len(state.observations):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint response order is inconsistent"
            )
        projected_result = _sanitize_complete(response.envelope)
        assert isinstance(projected_result, dict)
        is_error = (
            projected_result.get("isError") is True
            or projected_result.get("is_error") is True
        )
        projection = _project_result_for_model(
            projected_result,
            source_path="/result",
            is_error=is_error,
        )
        observation = {
            "tool_name": response.tool_name,
            "arguments": sanitize(response.arguments),
            "response_ordinal": response.response_index + 1,
            "decision_round": response.decision_round,
            "projection": projection,
            "is_error": is_error,
            "has_data": projection["has_data"] is True,
        }
        trace_prefix = (
            f"declarative-mcp:{self.descriptor.name}:"
            f"{trace_scope}:{response.decision_round}"
        )
        await trace.emit_observation(
            json.dumps(
                {
                    "observation_type": "program_fact_projection",
                    "tool_name": response.tool_name,
                    "projection": projection,
                },
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ),
            actor=response.tool_name,
            provider=self.source_system,
            trace_key=f"{trace_prefix}:observation",
        )
        model_observation = json.dumps(
            response.envelope,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        state.messages.extend(
            mcp_tool_result_messages(
                response.model_call,
                output=model_observation,
                fallback_messages=self._chat_tool_result_messages(
                    response.model_call,
                    model_observation,
                ),
            )
        )
        state.observations.append(observation)

    @staticmethod
    def _chat_tool_result_messages(
        call: MCPModelToolCall,
        output: str,
    ) -> list[dict[str, Any]]:
        """Build a valid Chat Completions tool-call/result message pair."""

        return [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": call.call_id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": json.dumps(
                                call.arguments,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": call.call_id,
                "content": output,
            },
        ]

    def _execution_result(self, state: _GenericMCPExecutionState) -> ToolExecutionResult:
        observations = state.observations
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
            reason_code = "remote_tool_errors" if errors_only else "empty_remote_results"
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
                    "finished_by_model": state.finished_by_model,
                    "partial": False,
                    "termination_reason": reason_code,
                    "reason_code": reason_code,
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
                "finished_by_model": state.finished_by_model,
                "partial": False,
                "termination_reason": "model_finished",
                "root_cause_eligible": True,
            },
        )

    async def _restore_execution_state(
        self,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        initial_messages: list[dict[str, Any]],
    ) -> tuple[_GenericMCPExecutionState, _CheckpointCursor | None]:
        initial = _GenericMCPExecutionState(
            messages=deepcopy(initial_messages),
            observations=[],
            remote_responses=[],
        )
        if self.repository is None:
            return initial, None
        manifest = await self.repository.get_run_manifest(str(context.run_id))
        if manifest is None:
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint requires a durable run manifest"
            )
        invocation_id = self._audit_invocation_id(request=request, context=context)
        scope_id = context.outer_dispatch_id or invocation_id
        cursor = _CheckpointCursor(
            namespace=f"mcp:{self.source_system}:{scope_id}",
            manifest_hash=manifest.digest(),
            invocation_id=invocation_id,
        )
        checkpoint = await self.repository.load_checkpoint(
            str(context.run_id),
            namespace=cursor.namespace,
        )
        if checkpoint is None:
            state = initial
        else:
            if checkpoint.manifest_hash != cursor.manifest_hash:
                raise GenericMCPConfigurationError(
                    "Generic MCP checkpoint manifest does not match the current run"
                )
            cursor.version = checkpoint.version
            state = self._decode_execution_state(
                checkpoint.state,
                initial_messages=initial_messages,
                invocation_id=invocation_id,
            )
        await self._restore_orphan_remote_response(
            state,
            context=context,
            invocation_id=invocation_id,
        )
        return state, cursor

    async def _restore_orphan_remote_response(
        self,
        state: _GenericMCPExecutionState,
        *,
        context: InvestigationContext,
        invocation_id: UUID,
    ) -> None:
        """Recover a response artifact left by a failed pending checkpoint write."""

        if (
            self.repository is None
            or state.completed
            or state.pending_response_index is not None
        ):
            return
        response_index = len(state.remote_responses)
        artifact_id = self._remote_response_artifact_id(
            invocation_id,
            response_index=response_index,
        )
        stored = await self.repository.get_agent_artifact(str(artifact_id))
        if stored is None:
            return
        artifact, content = stored
        response = self._decode_remote_response_artifact(
            artifact,
            content,
            expected_artifact_id=artifact_id,
            expected_index=response_index,
            expected_context=context,
            expected_invocation_id=invocation_id,
        )
        if response.decision_round != state.decision_round + 1:
            raise GenericMCPConfigurationError(
                "Generic MCP orphan artifact decision round is inconsistent"
            )
        state.remote_responses.append(response)
        state.pending_response_index = response_index
        state.decision_round = response.decision_round

    async def _save_execution_checkpoint(
        self,
        state: _GenericMCPExecutionState,
        *,
        context: InvestigationContext,
        cursor: _CheckpointCursor | None,
    ) -> None:
        if self.repository is None or cursor is None:
            return
        next_version = cursor.version + 1
        checkpoint = RunCheckpoint(
            run_id=context.run_id,
            namespace=cursor.namespace,
            version=next_version,
            sequence=next_version,
            state=self._encode_execution_state(
                state,
                invocation_id=cursor.invocation_id,
            ),
            budget_snapshot={},
            manifest_hash=cursor.manifest_hash,
        )
        await self.repository.save_checkpoint(
            checkpoint,
            expected_version=cursor.version,
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )
        cursor.version = next_version

    def _encode_execution_state(
        self,
        state: _GenericMCPExecutionState,
        *,
        invocation_id: UUID,
    ) -> dict[str, Any]:
        return {
            "contract": _CHECKPOINT_CONTRACT,
            "server": self.descriptor.name,
            "source_system": self.source_system,
            "invocation_id": str(invocation_id),
            "messages": deepcopy(state.messages),
            "observations": deepcopy(state.observations),
            "remote_responses": [
                self._encode_remote_response(response)
                for response in state.remote_responses
            ],
            "decision_round": state.decision_round,
            "pending_response_index": state.pending_response_index,
            "finished_by_model": state.finished_by_model,
            "completed": state.completed,
        }

    def _decode_execution_state(
        self,
        payload: dict[str, Any],
        *,
        initial_messages: list[dict[str, Any]],
        invocation_id: UUID,
    ) -> _GenericMCPExecutionState:
        if (
            payload.get("contract") != _CHECKPOINT_CONTRACT
            or payload.get("server") != self.descriptor.name
            or payload.get("source_system") != self.source_system
            or payload.get("invocation_id") != str(invocation_id)
        ):
            raise GenericMCPConfigurationError("Generic MCP checkpoint identity is invalid")
        messages = payload.get("messages")
        observations = payload.get("observations")
        raw_responses = payload.get("remote_responses")
        decision_round = payload.get("decision_round")
        pending_response_index = payload.get("pending_response_index")
        finished_by_model = payload.get("finished_by_model")
        completed = payload.get("completed")
        if (
            not isinstance(messages, list)
            or not all(isinstance(item, dict) for item in messages)
            or messages[: len(initial_messages)] != initial_messages
            or not isinstance(observations, list)
            or not all(isinstance(item, dict) for item in observations)
            or not isinstance(raw_responses, list)
            or not isinstance(decision_round, int)
            or isinstance(decision_round, bool)
            or decision_round < 0
            or not isinstance(finished_by_model, bool)
            or not isinstance(completed, bool)
        ):
            raise GenericMCPConfigurationError("Generic MCP checkpoint state is invalid")
        responses = [
            self._decode_remote_response(item, expected_index=index)
            for index, item in enumerate(raw_responses)
        ]
        if pending_response_index is not None and (
            not isinstance(pending_response_index, int)
            or isinstance(pending_response_index, bool)
            or pending_response_index != len(observations)
            or pending_response_index != len(responses) - 1
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint pending response is invalid"
            )
        if pending_response_index is None and len(responses) != len(observations):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint response count is invalid"
            )
        if pending_response_index is not None and len(responses) != len(observations) + 1:
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint pending response count is invalid"
            )
        if completed != finished_by_model or (completed and pending_response_index is not None):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint completion state is invalid"
            )
        expected_decision_round = len(responses) + (1 if completed else 0)
        if decision_round != expected_decision_round:
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint decision round is invalid"
            )
        return _GenericMCPExecutionState(
            messages=deepcopy(messages),
            observations=deepcopy(observations),
            remote_responses=responses,
            decision_round=decision_round,
            pending_response_index=pending_response_index,
            finished_by_model=finished_by_model,
            completed=completed,
        )

    @staticmethod
    def _encode_model_call(call: MCPModelToolCall) -> dict[str, Any]:
        return {
            "protocol": "responses" if call.provider_output_items else "chat",
            "call_id": call.call_id,
            "name": call.name,
            "arguments": deepcopy(call.arguments),
            "request_id": call.request_id,
            "reasoning_content": call.reasoning_content,
            "usage": deepcopy(call.usage),
            "provider_output_items": [
                deepcopy(item) for item in call.provider_output_items
            ],
        }

    def _encode_remote_response(
        self,
        response: _DeferredRemoteResponse,
    ) -> dict[str, Any]:
        return {
            "tool_name": response.tool_name,
            "arguments": deepcopy(response.arguments),
            "envelope": deepcopy(response.envelope),
            "model_call": self._encode_model_call(response.model_call),
            "response_index": response.response_index,
            "decision_round": response.decision_round,
        }

    @classmethod
    def _decode_remote_response(
        cls,
        payload: Any,
        *,
        expected_index: int,
    ) -> _DeferredRemoteResponse:
        if not isinstance(payload, dict):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint remote response is invalid"
            )
        tool_name = payload.get("tool_name")
        arguments = payload.get("arguments")
        envelope = payload.get("envelope")
        model_call_payload = payload.get("model_call")
        response_index = payload.get("response_index")
        decision_round = payload.get("decision_round")
        if (
            not isinstance(tool_name, str)
            or not tool_name
            or not isinstance(arguments, dict)
            or not isinstance(envelope, dict)
            or not isinstance(model_call_payload, dict)
            or type(response_index) is not int
            or response_index != expected_index
            or type(decision_round) is not int
            or decision_round != expected_index + 1
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint remote response is invalid"
            )
        model_call = cls._decode_model_call(
            model_call_payload,
            tool_name=tool_name,
            arguments=arguments,
        )
        return _DeferredRemoteResponse(
            tool_name=tool_name,
            arguments=deepcopy(arguments),
            envelope=deepcopy(envelope),
            model_call=model_call,
            response_index=response_index,
            decision_round=decision_round,
        )

    @staticmethod
    def _decode_model_call(
        payload: dict[str, Any],
        *,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> MCPModelToolCall:
        call_id = payload.get("call_id")
        call_name = payload.get("name")
        call_arguments = payload.get("arguments")
        request_id = payload.get("request_id")
        reasoning_content = payload.get("reasoning_content")
        usage = payload.get("usage")
        output_items = payload.get("provider_output_items")
        protocol = payload.get("protocol")
        if (
            protocol not in ("chat", "responses")
            or (protocol == "chat" and output_items != [])
            or not isinstance(call_id, str)
            or not call_id
            or call_name != tool_name
            or not isinstance(call_arguments, dict)
            or _canonical_json(call_arguments) != _canonical_json(arguments)
            or (request_id is not None and not isinstance(request_id, str))
            or (reasoning_content is not None and not isinstance(reasoning_content, str))
            or (usage is not None and not isinstance(usage, dict))
            or not isinstance(output_items, list)
            or not all(isinstance(item, dict) for item in output_items)
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP checkpoint model call is invalid"
            )
        if protocol == "responses":
            if (
                not output_items
                or output_items[-1].get("type") != "function_call"
                or any(item.get("type") != "reasoning" for item in output_items[:-1])
            ):
                raise GenericMCPConfigurationError(
                    "Generic MCP Responses model call lineage is invalid"
                )
            function_call = output_items[-1]
            function_arguments = function_call.get("arguments")
            if (
                function_call.get("call_id") != call_id
                or function_call.get("name") != call_name
                or not isinstance(function_arguments, str)
            ):
                raise GenericMCPConfigurationError(
                    "Generic MCP Responses function call is inconsistent"
                )
            try:
                decoded_function_arguments = json.loads(function_arguments)
            except json.JSONDecodeError as exc:
                raise GenericMCPConfigurationError(
                    "Generic MCP Responses function arguments are invalid"
                ) from exc
            if (
                not isinstance(decoded_function_arguments, dict)
                or _canonical_json(decoded_function_arguments)
                != _canonical_json(call_arguments)
            ):
                raise GenericMCPConfigurationError(
                    "Generic MCP Responses function arguments are inconsistent"
                )
        return MCPModelToolCall(
            call_id=call_id,
            name=call_name,
            arguments=deepcopy(call_arguments),
            request_id=request_id,
            reasoning_content=reasoning_content,
            usage=deepcopy(usage),
            provider_output_items=tuple(deepcopy(output_items)),
        )

    def _decode_remote_response_artifact(
        self,
        artifact: ArtifactRef,
        content: bytes | str | dict[str, Any],
        *,
        expected_artifact_id: UUID,
        expected_index: int,
        expected_context: InvestigationContext,
        expected_invocation_id: UUID,
    ) -> _DeferredRemoteResponse:
        metadata = artifact.metadata
        expected_run_id = str(expected_context.run_id)
        expected_outer_dispatch_id = (
            str(expected_context.outer_dispatch_id)
            if expected_context.outer_dispatch_id is not None
            else None
        )
        if (
            artifact.artifact_id != expected_artifact_id
            or artifact.kind != "declarative_mcp_remote_response"
            or artifact.media_type != "application/json"
            or artifact.uri != f"agent-artifact://{expected_artifact_id}"
            or metadata.get("contract") != _REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or metadata.get("server") != self.descriptor.name
            or metadata.get("source_system") != self.source_system
            or metadata.get("run_id") != expected_run_id
            or metadata.get("invocation_id") != str(expected_invocation_id)
            or metadata.get("outer_dispatch_id") != expected_outer_dispatch_id
            or type(metadata.get("response_ordinal")) is not int
            or metadata.get("response_ordinal") != expected_index + 1
            or type(metadata.get("decision_round")) is not int
            or metadata.get("decision_round") != expected_index + 1
            or metadata.get("sanitized") is not False
            or metadata.get("raw_response_unmodified") is not True
            or metadata.get("internal_only") is not True
            or not isinstance(content, bytes)
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP orphan response artifact identity is invalid"
            )
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GenericMCPConfigurationError(
                "Generic MCP orphan response artifact content is invalid"
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("contract") != _REMOTE_RESPONSE_ARTIFACT_CONTRACT
            or payload.get("server") != self.descriptor.name
            or payload.get("source_system") != self.source_system
            or payload.get("run_id") != expected_run_id
            or payload.get("invocation_id") != str(expected_invocation_id)
            or payload.get("outer_dispatch_id") != expected_outer_dispatch_id
            or type(payload.get("response_ordinal")) is not int
            or payload.get("response_ordinal") != expected_index + 1
            or type(payload.get("response_index")) is not int
            or payload.get("response_index") != expected_index
            or type(payload.get("decision_round")) is not int
            or payload.get("decision_round") != expected_index + 1
            or payload.get("tool_name") != metadata.get("tool_name")
            or payload.get("decision_round") != metadata.get("decision_round")
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP orphan response artifact content is invalid"
            )
        return self._decode_remote_response(
            {
                "tool_name": payload.get("tool_name"),
                "arguments": payload.get("arguments"),
                "envelope": payload.get("result"),
                "model_call": payload.get("model_call"),
                "response_index": payload.get("response_index"),
                "decision_round": payload.get("decision_round"),
            },
            expected_index=expected_index,
        )

    async def _persist_remote_response_artifacts(
        self,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        responses: list[_DeferredRemoteResponse],
    ) -> None:
        """Persist all completed responses after the MCP investigation terminates."""

        for response in responses:
            await self._persist_remote_response_artifact(
                request=request,
                context=context,
                tool_name=response.tool_name,
                arguments=response.arguments,
                result=response.envelope,
                model_call=response.model_call,
                response_index=response.response_index,
                decision_round=response.decision_round,
            )

    async def _persist_remote_response_artifact(
        self,
        *,
        request: ToolExecutionRequest,
        context: InvestigationContext,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        model_call: MCPModelToolCall,
        response_index: int,
        decision_round: int,
    ) -> ArtifactRef | None:
        """Idempotently persist one complete, unmodified response envelope."""

        if self.repository is None:
            return None
        invocation_id = self._audit_invocation_id(request=request, context=context)
        if (
            model_call.name != tool_name
            or _canonical_json(model_call.arguments) != _canonical_json(arguments)
        ):
            raise GenericMCPConfigurationError(
                "Generic MCP artifact model call is inconsistent"
            )
        artifact_id = self._remote_response_artifact_id(
            invocation_id,
            response_index=response_index,
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
                "run_id": str(context.run_id),
                "invocation_id": str(invocation_id),
                "outer_dispatch_id": (
                    str(context.outer_dispatch_id)
                    if context.outer_dispatch_id is not None
                    else None
                ),
                "tool_name": tool_name,
                "response_ordinal": response_index + 1,
                "decision_round": decision_round,
                "sanitized": False,
                "raw_response_unmodified": True,
                "internal_only": True,
            },
        )
        content = {
            "contract": _REMOTE_RESPONSE_ARTIFACT_CONTRACT,
            "server": self.descriptor.name,
            "source_system": self.source_system,
            "run_id": str(context.run_id),
            "invocation_id": str(invocation_id),
            "outer_dispatch_id": (
                str(context.outer_dispatch_id)
                if context.outer_dispatch_id is not None
                else None
            ),
            "tool_name": tool_name,
            "arguments": deepcopy(arguments),
            "model_call": self._encode_model_call(model_call),
            "response_ordinal": response_index + 1,
            "response_index": response_index,
            "decision_round": decision_round,
            "result": result,
        }
        content_bytes = json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return await self.repository.save_agent_artifact(
            str(context.run_id),
            artifact,
            content_bytes,
            invocation_id=(str(invocation_id) if context.outer_dispatch_id is not None else None),
            lease_owner=context.lease_owner,
            fencing_token=context.fencing_token,
        )

    def _remote_response_artifact_id(
        self,
        invocation_id: UUID,
        *,
        response_index: int,
    ) -> UUID:
        return uuid5(
            invocation_id,
            f"{_REMOTE_RESPONSE_ARTIFACT_CONTRACT}:{self.descriptor.name}:"
            f"response:{response_index + 1}",
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
