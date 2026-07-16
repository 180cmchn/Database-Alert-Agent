from __future__ import annotations

import json
import logging
from uuid import uuid4

import httpx
import pytest

from app.adapters.notification import (
    WECOM_MARKDOWN_MAX_BYTES,
    WebhookManagementNotifier,
    WeComManagementNotifier,
    format_wecom_markdown,
)
from app.domain.errors import NotificationError
from app.domain.models import (
    DatabaseTarget,
    NormalizedAlert,
    NotificationEvent,
    NotificationPhase,
    Recommendation,
    RecommendationStep,
    RunbookReference,
    Severity,
)
from app.logging_config import configure_logging


def notification_event(
    *,
    phase: NotificationPhase = NotificationPhase.ADVICE_READY,
    title: str = "数据库连接数接近上限",
) -> NotificationEvent:
    reference = RunbookReference(
        runbook_id="connection-limit", section="initial-triage"
    )
    recommendation = Recommendation(
        summary="连接使用率达到 95%，请先执行只读核查。",
        likely_causes=["连接池回收异常"],
        evidence=["connection_usage_percent=95"],
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
    )
    return NotificationEvent(
        phase=phase,
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
        recommendation=(
            recommendation if phase == NotificationPhase.ADVICE_READY else None
        ),
        message="分析完成；token=must-not-appear",
    )


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        (NotificationPhase.INITIAL_ALERT, "首次升级"),
        (NotificationPhase.ADVICE_READY, "分析完成"),
        (NotificationPhase.ANALYSIS_FAILED, "分析失败"),
    ],
)
def test_wecom_markdown_is_phase_aware_bounded_and_does_not_include_raw_payload(
    phase: NotificationPhase, expected: str
) -> None:
    content = format_wecom_markdown(notification_event(phase=phase))

    assert expected in content
    assert "orders-primary" in content
    assert "must-not-appear" not in content
    assert "***REDACTED***" in content
    assert "raw_payload" not in content
    assert len(content.encode("utf-8")) <= WECOM_MARKDOWN_MAX_BYTES
    if phase == NotificationPhase.ADVICE_READY:
        assert "connection-limit/initial-triage" in content


def test_wecom_markdown_truncates_long_chinese_text_on_utf8_boundary() -> None:
    event = notification_event()
    assert event.recommendation is not None
    event.recommendation = event.recommendation.model_copy(
        update={"summary": "连接异常" * 3_000}
    )
    content = format_wecom_markdown(event)

    assert len(content.encode("utf-8")) <= WECOM_MARKDOWN_MAX_BYTES
    assert "内容已截断" in content
    content.encode("utf-8").decode("utf-8")


def test_wecom_markdown_redacts_authorization_headers_and_common_tokens() -> None:
    event = notification_event(phase=NotificationPhase.INITIAL_ALERT)
    event.alert.description = (
        "Authorization: Basic basic-secret; "
        "Authorization=ApiKey api-secret; access_token=access-secret"
    )

    content = format_wecom_markdown(event)

    assert "basic-secret" not in content
    assert "api-secret" not in content
    assert "access-secret" not in content
    assert "***REDACTED***" in content


@pytest.mark.asyncio
async def test_wecom_notifier_sends_markdown_and_requires_business_success() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"errcode": 0, "errmsg": "ok", "msgid": "wecom-message-1"},
        )

    event = notification_event()
    notifier = WeComManagementNotifier(
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=top-secret-key",
        transport=httpx.MockTransport(handler),
    )

    delivery_id = await notifier.send(event)

    assert delivery_id == "wecom-message-1"
    assert len(requests) == 1
    request = requests[0]
    assert request.headers["x-alert-id"] == str(event.alert.id)
    assert request.headers["x-notification-phase"] == "ADVICE_READY"
    assert request.headers["idempotency-key"] == f"{event.alert.id}:ADVICE_READY"
    assert request.url.params["key"] == "top-secret-key"
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
        await notifier.send(notification_event())

    assert "must-not-leak" not in str(caught.value)


@pytest.mark.asyncio
async def test_wecom_notifier_hides_url_on_transport_failure() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("failed for key=must-not-leak")

    notifier = WeComManagementNotifier(
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=must-not-leak",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(NotificationError) as caught:
        await notifier.send(notification_event())

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
        await notifier.send(notification_event())
    finally:
        httpx_logger.setLevel(original_levels[0])
        httpcore_logger.setLevel(original_levels[1])

    assert "log-secret-key" not in caplog.text


@pytest.mark.asyncio
async def test_generic_webhook_recursively_sanitizes_outbound_event() -> None:
    bodies: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, headers={"X-Delivery-Id": "relay-1"})

    event = notification_event()
    assert event.recommendation is not None
    event.recommendation = event.recommendation.model_copy(
        update={"summary": "Authorization: Bearer recommendation-secret"}
    )
    notifier = WebhookManagementNotifier(
        "https://relay.example.test/notifications",
        transport=httpx.MockTransport(handler),
    )

    delivery_id = await notifier.send(event)

    assert delivery_id == "relay-1"
    serialized = json.dumps(bodies[0], ensure_ascii=False)
    assert "recommendation-secret" not in serialized
    assert "must-not-appear" not in serialized
    assert "***REDACTED***" in serialized
