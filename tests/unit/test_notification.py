from __future__ import annotations

import logging
from uuid import uuid4

import httpx
import pytest

from app.adapters.notification import (
    WECOM_MARKDOWN_MAX_BYTES,
    LogManagementNotifier,
    WeComManagementNotifier,
    format_wecom_markdown,
)
from app.domain.errors import NotificationError
from app.domain.models import (
    AlertStatus,
    AnalysisBasis,
    AnalysisBasisSource,
    AnalysisResultEvent,
    DatabaseTarget,
    NormalizedAlert,
    Recommendation,
    RecommendationStep,
    RunbookReference,
    Severity,
)
from app.logging_config import configure_logging


def analysis_result_event(*, title: str = "数据库连接数接近上限") -> AnalysisResultEvent:
    reference = RunbookReference(
        runbook_id="connection-limit", section="initial-triage"
    )
    return AnalysisResultEvent(
        alert=NormalizedAlert(
            id=uuid4(),
            external_id="wecom-test-1",
            source="canonical",
            raw_severity="CRITICAL",
            severity=Severity.CRITICAL,
            environment="production",
            service_name="orders-api",
            title=title,
            reason="connection_exhausted",
            description="password=must-not-appear",
            database=DatabaseTarget(engine="postgresql", instance="orders-primary"),
            raw_payload={"authorization": "Bearer must-not-appear"},
        ),
        recommendation=Recommendation(
            summary="连接使用率达到 95%，请先执行只读核查。",
            likely_causes=["连接池回收异常"],
            analysis_bases=[
                AnalysisBasis(
                    source=AnalysisBasisSource.RUNBOOK,
                    statement="手册将连接使用率过高列为该告警的常见原因。",
                    source_ref=reference,
                ),
                AnalysisBasis(
                    source=AnalysisBasisSource.AI,
                    statement="告警字段 connection_usage_percent=95 与该场景一致。",
                ),
            ],
            steps=[
                RecommendationStep(
                    order=1,
                    action="检查当前连接数与最大连接数。",
                    source_ref=reference,
                )
            ],
            risks=["不要未经审批终止会话"],
            requires_human=True,
            confidence=0.86,
            manual_matched=True,
            runbook_references=[reference],
        ),
        status=AlertStatus.COMPLETED,
        message="分析完成；token=must-not-appear",
    )


def test_wecom_markdown_contains_causes_and_orders_runbook_before_ai() -> None:
    content = format_wecom_markdown(analysis_result_event())

    assert "AI 分析结果" in content
    assert "可能原因" in content
    assert "连接池回收异常" in content
    assert "判断依据（手册优先，AI 其次）" in content
    assert content.index("[手册]") < content.index("[AI]")
    assert "connection-limit/initial-triage" in content
    assert "must-not-appear" not in content
    assert "***REDACTED***" in content
    assert "raw_payload" not in content
    assert len(content.encode("utf-8")) <= WECOM_MARKDOWN_MAX_BYTES


def test_wecom_markdown_truncates_long_chinese_text_on_utf8_boundary() -> None:
    event = analysis_result_event()
    event.recommendation = event.recommendation.model_copy(
        update={"summary": "连接异常" * 3_000}
    )
    content = format_wecom_markdown(event)

    assert len(content.encode("utf-8")) <= WECOM_MARKDOWN_MAX_BYTES
    assert "内容已截断" in content
    content.encode("utf-8").decode("utf-8")


@pytest.mark.asyncio
async def test_log_notifier_records_only_delivery_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    event = analysis_result_event(title="sensitive database host")
    caplog.set_level(logging.WARNING, logger="app.adapters.notification")

    delivery_id = await LogManagementNotifier().send(event)

    assert delivery_id.startswith("log-")
    assert str(event.alert.id) in caplog.text
    assert "COMPLETED" in caplog.text
    assert "sensitive database host" not in caplog.text
    assert "must-not-appear" not in caplog.text
    assert "raw_payload" not in caplog.text


@pytest.mark.asyncio
async def test_wecom_notifier_sends_one_markdown_result() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"errcode": 0, "errmsg": "ok", "msgid": "wecom-message-1"},
        )

    event = analysis_result_event()
    notifier = WeComManagementNotifier(
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=top-secret-key",
        transport=httpx.MockTransport(handler),
    )

    delivery_id = await notifier.send(event)

    assert delivery_id == "wecom-message-1"
    assert len(requests) == 1
    request = requests[0]
    assert request.headers["x-alert-id"] == str(event.alert.id)
    assert request.headers["x-analysis-status"] == "COMPLETED"
    assert request.headers["idempotency-key"] == f"{event.alert.id}:analysis-result"
    assert b'"msgtype":"markdown"' in request.content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"errcode": 93000, "errmsg": "invalid webhook"}),
        httpx.Response(200, json={"errmsg": "ok"}),
        httpx.Response(200, content=b"not-json"),
        httpx.Response(503, json={"errcode": 0, "errmsg": "ok"}),
    ],
)
async def test_wecom_notifier_reports_safe_errors_without_webhook_key(
    response: httpx.Response,
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return response

    notifier = WeComManagementNotifier(
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=must-not-leak",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(NotificationError) as caught:
        await notifier.send(analysis_result_event())

    assert "must-not-leak" not in str(caught.value)


@pytest.mark.asyncio
async def test_wecom_webhook_key_is_not_written_to_http_transport_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    original_levels = (httpx_logger.level, httpcore_logger.level)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errcode": 0, "errmsg": "ok"})

    try:
        configure_logging("DEBUG")
        caplog.set_level(logging.DEBUG)
        notifier = WeComManagementNotifier(
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=log-secret-key",
            transport=httpx.MockTransport(handler),
        )
        await notifier.send(analysis_result_event())
    finally:
        httpx_logger.setLevel(original_levels[0])
        httpcore_logger.setLevel(original_levels[1])

    assert "log-secret-key" not in caplog.text
