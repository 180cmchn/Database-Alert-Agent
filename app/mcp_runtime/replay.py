"""Deterministic planner and MCP transport for sanitized replay fixtures."""

from __future__ import annotations

from copy import deepcopy
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.contracts import AgentAction, ToolSpec
from app.mcp_runtime.contracts import DiscoveredMCPTool, MCPToolSession


class ReplayContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReplayCallOutcome(StrEnum):
    RESULT = "RESULT"
    ERROR = "ERROR"
    DISCONNECT = "DISCONNECT"


class ReplayErrorFixture(ReplayContract):
    code: str = Field(default="replay_error", min_length=1, max_length=256)
    message: str = Field(min_length=1, max_length=4000)
    retryable: bool = True
    unknown_outcome: bool = False


class ReplayCallFixture(ReplayContract):
    tool_name: str = Field(min_length=1, max_length=256)
    expected_arguments: dict[str, Any] | None = None
    outcome: ReplayCallOutcome = ReplayCallOutcome.RESULT
    result: Any = None
    error: ReplayErrorFixture | None = None

    @model_validator(mode="after")
    def require_error_for_failure(self) -> ReplayCallFixture:
        if self.outcome != ReplayCallOutcome.RESULT and self.error is None:
            raise ValueError("non-result replay call requires an error fixture")
        if self.outcome == ReplayCallOutcome.RESULT and self.error is not None:
            raise ValueError("result replay call cannot include an error fixture")
        return self


class ReplaySessionFixture(ReplayContract):
    session_id: str = Field(min_length=1, max_length=256)
    tools: list[DiscoveredMCPTool] = Field(default_factory=list)
    calls: list[ReplayCallFixture] = Field(default_factory=list)
    open_error: ReplayErrorFixture | None = None
    bootstrap_error: ReplayErrorFixture | None = None


class ReplayMCPError(RuntimeError):
    def __init__(self, fixture: ReplayErrorFixture) -> None:
        super().__init__(fixture.message)
        self.code = fixture.code
        self.retryable = fixture.retryable
        self.unknown_outcome = fixture.unknown_outcome


class ReplayFixtureMismatchError(ReplayMCPError):
    def __init__(self, message: str) -> None:
        super().__init__(
            ReplayErrorFixture(
                code="replay_fixture_mismatch",
                message=message,
                retryable=False,
            )
        )


class _ReplayMCPToolSession:
    def __init__(self, fixture: ReplaySessionFixture) -> None:
        self.fixture = fixture
        self._call_index = 0
        self._closed = False

    @property
    def session_id(self) -> str:
        return self.fixture.session_id

    async def list_tools(self) -> list[DiscoveredMCPTool]:
        self._require_open()
        if self.fixture.bootstrap_error is not None:
            raise ReplayMCPError(self.fixture.bootstrap_error)
        return deepcopy(self.fixture.tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self._require_open()
        if self._call_index >= len(self.fixture.calls):
            raise ReplayFixtureMismatchError(
                f"Session {self.session_id} has no replay call at index {self._call_index}"
            )
        call = self.fixture.calls[self._call_index]
        self._call_index += 1
        if call.tool_name != name:
            raise ReplayFixtureMismatchError(f"Expected tool {call.tool_name!r}, received {name!r}")
        if call.expected_arguments is not None and call.expected_arguments != arguments:
            raise ReplayFixtureMismatchError(
                f"Arguments for {name!r} do not match the sanitized replay fixture"
            )
        if call.outcome == ReplayCallOutcome.RESULT:
            return deepcopy(call.result)
        if call.outcome == ReplayCallOutcome.DISCONNECT:
            self._closed = True
        assert call.error is not None
        raise ReplayMCPError(call.error)

    async def close(self) -> None:
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ReplayFixtureMismatchError(f"Session {self.session_id} is closed")


class ReplayMCPConnector:
    def __init__(self, provider: str, sessions: list[ReplaySessionFixture]) -> None:
        if not provider:
            raise ValueError("provider must not be empty")
        self._provider = provider
        self._sessions = list(sessions)
        self._session_index = 0
        self.opened_session_ids: list[str] = []

    @property
    def provider(self) -> str:
        return self._provider

    async def open_session(self) -> MCPToolSession:
        if self._session_index >= len(self._sessions):
            raise ReplayFixtureMismatchError("No replay MCP session remains")
        fixture = self._sessions[self._session_index]
        self._session_index += 1
        self.opened_session_ids.append(fixture.session_id)
        if fixture.open_error is not None:
            raise ReplayMCPError(fixture.open_error)
        return _ReplayMCPToolSession(fixture)


class PlannerRequest(ReplayContract):
    messages: list[dict[str, Any]]
    tools: list[ToolSpec]


class ScriptedPlannerExhaustedError(RuntimeError):
    pass


class ScriptedPlanner:
    """Returns one scripted response per planner request and records its inputs."""

    def __init__(self, responses: list[AgentAction | dict[str, Any] | Exception | None]) -> None:
        self._responses = list(responses)
        self.requests: list[PlannerRequest] = []

    async def plan(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        reasoning_callback: Any | None = None,
    ) -> AgentAction | dict[str, Any] | None:
        del reasoning_callback
        self.requests.append(
            PlannerRequest(
                messages=deepcopy(messages),
                tools=[item.model_copy(deep=True) for item in tools],
            )
        )
        if not self._responses:
            raise ScriptedPlannerExhaustedError("No scripted planner response remains")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)
