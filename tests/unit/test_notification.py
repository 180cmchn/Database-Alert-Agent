from __future__ import annotations

import logging
from uuid import uuid4

import httpx
import pytest

from app.adapters.notification import (
    LogManagementNotifier,
    WeComManagementNotifier,
    build_wecom_template_card,
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
            database=DatabaseTarget(
                engine="postgresql",
                instance="orders-primary",
                host="db-orders.internal",
            ),
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
        run_id=uuid4(),
    )


def test_wecom_card_contains_alert_facts_and_exactly_three_actions() -> None:
    event = analysis_result_event()
    card = build_wecom_template_card(
        event,
        page_base_url="https://alerts.intra.example.com",
    )

    assert card["card_type"] == "text_notice"
    assert card["main_title"]["title"] == "数据库连接数接近上限"
    facts = {
        item["keyname"]: item["value"]
        for item in card["horizontal_content_list"]
    }
    assert facts["告警级别"] == "严重 / CRITICAL"
    assert facts["告警主机"] == "db-orders.internal"
    assert facts["数据库"] == "postgresql"

    actions = card["jump_list"]
    assert [item["title"] for item in actions] == [
        "告警根因分析",
        "告警恢复建议",
        "人工反馈",
    ]
    assert actions[0]["url"] == (
        f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}/root-cause"
    )
    assert actions[1]["url"] == (
        f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}/recovery-advice"
    )
    assert actions[2]["url"] == (
        f"https://alerts.intra.example.com/alerts/{event.alert.id}#feedback"
    )
    assert card["card_action"] == {
        "type": 1,
        "url": f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}",
    }


def test_wecom_card_sanitizes_and_bounds_text_fields() -> None:
    event = analysis_result_event(title=f"token=must-not-appear {'连接异常' * 20}")
    card = build_wecom_template_card(
        event,
        page_base_url="https://alerts.intra.example.com",
    )

    serialized = str(card)
    assert "must-not-appear" not in serialized
    assert "***REDACTED***" in serialized
    assert len(card["main_title"]["title"]) <= 26
    assert len(card["sub_title_text"]) <= 112
    assert all(
        len(item["value"]) <= 26 for item in card["horizontal_content_list"]
    )


def test_wecom_card_external_feedback_url_gets_correlation_parameters() -> None:
    event = analysis_result_event()
    card = build_wecom_template_card(
        event,
        page_base_url="https://alerts.intra.example.com/base",
        feedback_form_url=(
            "https://survey.example.com/form?campaign=dba&alert_id=stale#questions"
        ),
    )

    feedback_url = card["jump_list"][2]["url"]
    assert feedback_url.startswith("https://survey.example.com/form?")
    assert "campaign=dba" in feedback_url
    assert "alert_id=stale" not in feedback_url
    assert f"alert_id={event.alert.id}" in feedback_url
    assert f"run_id={event.run_id}" in feedback_url
    assert "source=wecom" in feedback_url
    assert feedback_url.endswith("#questions")


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
async def test_wecom_notifier_sends_one_template_card() -> None:
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
        "https://alerts.intra.example.com",
        transport=httpx.MockTransport(handler),
    )

    delivery_id = await notifier.send(event)

    assert delivery_id == "wecom-message-1"
    assert len(requests) == 1
    request = requests[0]
    assert request.headers["x-alert-id"] == str(event.alert.id)
    assert request.headers["x-analysis-status"] == "COMPLETED"
    assert request.headers["idempotency-key"] == f"{event.alert.id}:analysis-result"
    assert b'"msgtype":"template_card"' in request.content
    assert b'"card_type":"text_notice"' in request.content
    assert request.content.count(b'"title":"') >= 4


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
        "https://alerts.intra.example.com",
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
            "https://alerts.intra.example.com",
            transport=httpx.MockTransport(handler),
        )
        await notifier.send(analysis_result_event())
    finally:
        httpx_logger.setLevel(original_levels[0])
        httpcore_logger.setLevel(original_levels[1])

    assert "log-secret-key" not in caplog.text
