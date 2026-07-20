import asyncio
from uuid import uuid4

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.domain.models import (
    InvestigationContext,
    InvestigationStrategy,
    ToolExecutionRequest,
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


def make_context() -> InvestigationContext:
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "external_id": "tool-test-1",
            "severity": "WARNING",
            "title": "Database latency",
            "reason": "latency",
        }
    )
    strategy = InvestigationStrategy(
        strategy_id="tool-test-v1",
        title="Tool test",
        description="Exercise tool execution outcomes",
    )
    return InvestigationContext(run_id=uuid4(), alert=alert, strategy=strategy)


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
    assert record.structured_data == {}
