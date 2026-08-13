import asyncio
from uuid import uuid4

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.investigation import (
    InvestigationToolRegistry,
    ToolExecutor,
)
from app.domain.models import (
    InvestigationContext,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
)


class SuccessfulTool:
    name = "successful"
    source_system = "test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        return "evidence collected", {"value": 42}


class SlowTool:
    name = "slow"
    source_system = "test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        await asyncio.sleep(0.05)
        return "too late", {}


class FailingTool:
    name = "failing"
    source_system = "test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        raise RuntimeError("backend unavailable")


class NoDataTool:
    name = "no_data"
    source_system = "test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        return ToolExecutionResult(
            status=ToolStatus.NO_DATA,
            summary="query succeeded without records",
            structured_data={"rows": []},
        )


class PermissionDeniedError(RuntimeError):
    status_code = 403
    code = "Forbidden"
    request_id = "req-forbidden"


class PermissionDeniedTool:
    name = "permission_denied"
    source_system = "test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        raise PermissionDeniedError("not allowed")


class LargeControlledTool:
    name = "large_controlled"
    source_system = "archery_mcp"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        return "large evidence", {
            "query_completed": True,
            "root_cause_eligible": True,
            "root_cause_ineligible_reason": "",
            "partial": True,
            "allow_followup_dispatch": False,
            "termination_reason": "sse_error_after_partial_result",
            "termination_error_type": "ConnectionError",
            "mcp_session_attempts": 2,
            "reconnect_error_type": "PrometheusMCPProtocolError",
            "result": {"sample": "x" * 3000},
        }


class LargeUnqualifiedTool:
    name = "large_unqualified"
    source_system = "live_test_system"

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        return "large evidence without eligibility", {"sample": "x" * 3000}


class SchemaBoundTool:
    name = "schema_bound"
    source_system = "test_system"
    capability = "lookup_by_service"
    policy_version = "test-policy-v2"
    input_schema = {
        "type": "object",
        "properties": {"service": {"type": "string", "minLength": 1}},
        "required": ["service"],
        "additionalProperties": False,
    }

    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, request, context):  # type: ignore[no-untyped-def]
        self.calls += 1
        return "matched", {"service": request.parameters["service"]}


class ArbitraryCommandTool(SchemaBoundTool):
    name = "arbitrary_command"


def make_context() -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "tool-test-1",
            "severity": "WARNING",
            "title": "Database latency",
            "reason": "latency",
        }
    )
    return InvestigationContext(run_id=uuid4(), alert=alert)


@pytest.mark.asyncio
async def test_tool_executor_returns_success() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([SuccessfulTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="successful", parameters={"sample": True}),
        make_context(),
    )

    assert record.status == ToolStatus.SUCCESS
    assert record.source_system == "test_system"
    assert record.summary == "evidence collected"
    assert record.structured_data == {"value": 42}
    assert record.error is None


@pytest.mark.asyncio
async def test_tool_executor_keeps_complete_provider_result() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([LargeControlledTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="large_controlled"),
        make_context(),
    )

    assert record.truncated is False
    assert record.structured_data["query_completed"] is True
    assert record.structured_data["root_cause_eligible"] is True
    assert record.structured_data["root_cause_ineligible_reason"] == ""
    assert record.structured_data["partial"] is True
    assert record.structured_data["allow_followup_dispatch"] is False
    assert (
        record.structured_data["termination_reason"]
        == "sse_error_after_partial_result"
    )
    assert record.structured_data["termination_error_type"] == "ConnectionError"
    assert record.structured_data["mcp_session_attempts"] == 2
    assert (
        record.structured_data["reconnect_error_type"]
        == "PrometheusMCPProtocolError"
    )
    assert "instance_identity_verification" not in record.structured_data
    assert "analysis_usable" not in record.structured_data
    assert record.structured_data["result"]["sample"] == "x" * 3000
    assert record.is_root_cause_support_eligible() is False


@pytest.mark.asyncio
async def test_complete_result_does_not_invent_root_cause_ineligibility() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([LargeUnqualifiedTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="large_unqualified"),
        make_context(),
    )

    assert record.truncated is False
    assert record.structured_data["sample"] == "x" * 3000
    assert "root_cause_eligible" not in record.structured_data
    assert "root_cause_ineligible_reason" not in record.structured_data
    assert record.is_root_cause_support_eligible() is True


@pytest.mark.asyncio
async def test_tool_executor_returns_timeout() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([SlowTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="slow", timeout_seconds=0.001),
        make_context(),
    )

    assert record.status == ToolStatus.TIMEOUT
    assert record.error == "Tool execution timed out"
    assert record.structured_data == {}


@pytest.mark.asyncio
async def test_tool_executor_returns_failed() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([FailingTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="failing"),
        make_context(),
    )

    assert record.status == ToolStatus.FAILED
    assert record.error == "RuntimeError: backend unavailable"
    assert record.structured_data == {"reason_code": "RuntimeError"}


def test_tool_executor_sanitizes_exception_diagnostics() -> None:
    exc = RuntimeError("backend unavailable")
    exc.diagnostic_data = {  # type: ignore[attr-defined]
        "stage": "login",
        "token": "do-not-expose",
    }

    assert ToolExecutor._failure_data(exc) == {
        "reason_code": "RuntimeError",
        "diagnostics": {
            "stage": "login",
            "token": "***REDACTED***",
        },
    }


@pytest.mark.asyncio
async def test_tool_executor_distinguishes_no_data_from_success() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([NoDataTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="no_data"),
        make_context(),
    )

    assert record.status == ToolStatus.NO_DATA
    assert record.summary == "query succeeded without records"
    assert record.structured_data == {"rows": []}
    assert record.error is None


@pytest.mark.asyncio
async def test_tool_executor_skips_unregistered_tools_without_external_call() -> None:
    executor = ToolExecutor(InvestigationToolRegistry())

    record = await executor.execute(
        ToolExecutionRequest(tool_name="invented_tool"),
        make_context(),
    )

    assert record.status == ToolStatus.SKIPPED
    assert record.source_system == "unregistered"
    assert record.structured_data == {"reason_code": "tool_not_registered"}
    assert record.error is None


@pytest.mark.asyncio
async def test_tool_executor_records_permission_failures_separately() -> None:
    executor = ToolExecutor(InvestigationToolRegistry([PermissionDeniedTool()]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name="permission_denied"),
        make_context(),
    )

    assert record.status == ToolStatus.FAILED
    assert record.structured_data == {
        "reason_code": "permission_denied",
        "vendor_error_code": "Forbidden",
        "http_status": 403,
        "request_id": "req-forbidden",
    }


def test_registry_exposes_versioned_tool_contracts() -> None:
    registry = InvestigationToolRegistry([SchemaBoundTool()])

    spec = registry.available_specs()[0]

    assert spec.name == "schema_bound"
    assert spec.provider == "test_system"
    assert spec.capability == "lookup_by_service"
    assert not hasattr(spec, "read_only")
    assert spec.policy_version == "test-policy-v2"
    assert spec.schema_version == "dynamic-mcp-schema-v1"
    assert spec.input_schema["required"] == ["service"]


def test_registry_does_not_invent_a_permission_contract_for_legacy_tool() -> None:
    class UndeclaredTool:
        name = "undeclared"
        source_system = "test_system"

    registry = InvestigationToolRegistry([UndeclaredTool()])  # type: ignore[list-item]

    assert not hasattr(registry.available_specs()[0], "read_only")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "parameters"),
    [
        (SchemaBoundTool(), {"service": 42}),
        (SchemaBoundTool(), {"service": "orders", "unsafe": True}),
        (ArbitraryCommandTool(), {"service": "orders"}),
    ],
)
async def test_executor_does_not_reject_or_rewrite_agent_arguments_from_host_policy(
    tool: SchemaBoundTool,
    parameters: dict[str, object],
) -> None:
    executor = ToolExecutor(InvestigationToolRegistry([tool]))

    record = await executor.execute(
        ToolExecutionRequest(tool_name=tool.name, parameters=parameters),
        make_context(),
    )

    assert record.status == ToolStatus.SUCCESS
    assert record.structured_data["service"] == parameters["service"]
    assert tool.calls == 1
