from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from app.adapters.notification import (
    LogManagementNotifier,
    WeComManagementNotifier,
    build_wecom_failure_card,
    build_wecom_template_card,
)
from app.domain.errors import NotificationError
from app.domain.models import (
    AlertStatus,
    AnalysisBasis,
    AnalysisBasisSource,
    AnalysisFailureEvent,
    AnalysisResultEvent,
    DatabaseTarget,
    KnowledgeExcerpt,
    KnowledgeReference,
    ModelFailure,
    ModelFailureCategory,
    NormalizedAlert,
    Recommendation,
    RecommendationStep,
    Severity,
)
from app.logging_config import configure_logging

MONGODB_MEMORY_TITLE = "MongoDBHostMemoryLow / 10.126.53.39:9100"


def analysis_result_event(*, title: str = "数据库连接数接近上限") -> AnalysisResultEvent:
    knowledge = KnowledgeExcerpt(
        source="incident_library",
        knowledge_id="connection-limit",
        title="连接使用率处置经验",
        content="阻塞会话导致连接使用率过高时，终止已确认的阻塞会话并限制异常连接流量。",
        source_uri="https://knowledge.example.test/connection-limit",
        score=0.9,
        raw_score=0.1,
    )
    reference = KnowledgeReference(
        source=knowledge.source,
        knowledge_id=knowledge.knowledge_id,
        title=knowledge.title,
        source_uri=knowledge.source_uri,
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
            occurred_at=datetime(2026, 9, 3, 20, 15, 30, tzinfo=UTC),
            database=DatabaseTarget(
                engine="postgresql",
                instance="orders-primary",
                host="db-orders.internal",
            ),
            raw_payload={"authorization": "Bearer must-not-appear"},
        ),
        recommendation=Recommendation(
            summary="阻塞会话导致连接使用率达到 95%，应释放阻塞连接并限制异常流量。",
            likely_causes=["连接池回收异常"],
            analysis_bases=[
                AnalysisBasis(
                    source=AnalysisBasisSource.KNOWLEDGE,
                    statement="历史知识将连接使用率过高列为需核查的机制。",
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
                    action="终止已确认的阻塞会话并限制异常连接流量。",
                    source_ref=reference,
                )
            ],
            risks=["不要未经审批终止会话"],
            confidence=0.86,
            knowledge_matches=[knowledge],
        ),
        status=AlertStatus.COMPLETED,
        message="分析完成；token=must-not-appear",
        run_id=uuid4(),
    )


def analysis_failure_event() -> AnalysisFailureEvent:
    result = analysis_result_event()
    return AnalysisFailureEvent(
        alert=result.alert,
        status=AlertStatus.FAILED,
        message="Authorization: Bearer must-not-appear",
        run_id=uuid4(),
        failure=ModelFailure(
            category=ModelFailureCategory.AUTHORIZATION,
            provider="openai_compatible",
            model="analysis-model",
            phase="final",
            pauses_dispatch=True,
            http_status=403,
            vendor_code="permission_denied",
            request_id="provider-request-1",
            safe_detail="forbidden",
        ),
    )


@pytest.mark.parametrize(
    ("title", "alert_name", "expected_title", "expected_subtitle"),
    [
        (
            "数据库连接数接近上限",
            None,
            "数据库连接数接近上限",
            "告警原因：connection_exhausted",
        ),
        (
            MONGODB_MEMORY_TITLE,
            "MongoDBHostMemoryLow",
            "MongoDBHostMemoryLow",
            f"告警标题：{MONGODB_MEMORY_TITLE}\n告警原因：connection_exhausted",
        ),
        (
            MONGODB_MEMORY_TITLE,
            None,
            "数据库告警分析",
            f"告警标题：{MONGODB_MEMORY_TITLE}\n告警原因：connection_exhausted",
        ),
    ],
    ids=["short-title", "mongodb-alert-name", "mongodb-default-unknown"],
)
def test_wecom_card_contains_alert_facts_and_exactly_two_actions(
    title: str,
    alert_name: str | None,
    expected_title: str,
    expected_subtitle: str,
) -> None:
    event = analysis_result_event(title=title)
    if alert_name is not None:
        event.alert.alert_name = alert_name
    original_alert = event.alert.model_dump()
    card = build_wecom_template_card(
        event,
        page_base_url="https://alerts.intra.example.com",
    )

    assert card["card_type"] == "text_notice"
    assert card["main_title"]["title"] == expected_title
    assert card["main_title"]["desc"] == "2026-09-04 04:15:30（北京时间）"
    assert card["sub_title_text"] == expected_subtitle
    assert card["source"] == {"desc": "数据库告警 Agent", "desc_color": 2}
    assert card["emphasis_content"] == {"title": "CRITICAL", "desc": "分析完成"}
    assert card["horizontal_content_list"] == [
        {"keyname": "告警级别", "value": "严重 / CRITICAL"},
        {"keyname": "告警主机", "value": "db-orders.internal"},
        {"keyname": "数据库", "value": "postgresql"},
        {"keyname": "环境", "value": "production"},
        {"keyname": "服务", "value": "orders-api"},
        {"keyname": "外部ID", "value": "wecom-test-1"},
    ]
    assert event.alert.model_dump() == original_alert

    actions = card["jump_list"]
    assert [item["title"] for item in actions] == [
        "AI 分析结论",
        "告警恢复建议",
    ]
    assert [item["type"] for item in actions] == [1, 1]
    assert actions[0]["url"] == (
        f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}/root-cause"
        f"?run_id={event.run_id}"
    )
    assert actions[1]["url"] == (
        f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}/recovery-advice"
        f"?run_id={event.run_id}"
    )
    assert card["card_action"] == {
        "type": 1,
        "url": (
            f"https://alerts.intra.example.com/wecom/alerts/{event.alert.id}?run_id={event.run_id}"
        ),
    }


@pytest.mark.parametrize(
    ("title", "expected_title", "expected_subtitle"),
    [
        ("数据库连接数接近上限", "数据库连接数接近上限", "告警原因：connection_exhausted"),
        ("", "未提供", "告警原因：connection_exhausted"),
        (" \n\t ", "未提供", "告警原因：connection_exhausted"),
        ("A" * 26, "A" * 26, "告警原因：connection_exhausted"),
        ("A" * 27, "OtherAlert", f"告警标题：{'A' * 27}\n告警原因：connection_exhausted"),
        ("中" * 27, "OtherAlert", f"告警标题：{'中' * 27}\n告警原因：connection_exhausted"),
        (
            "DB数据库" * 6,
            "OtherAlert",
            f"告警标题：{'DB数据库' * 6}\n告警原因：connection_exhausted",
        ),
        (
            f"{' ' * 30}数据库\n\t 告警  ",
            "数据库 告警",
            "告警原因：connection_exhausted",
        ),
        (
            "token=very-long-secret-that-must-be-redacted",
            "token=***REDACTED***",
            "告警原因：connection_exhausted",
        ),
        (
            "数据库连接异常 token=x",
            "OtherAlert",
            "告警标题：数据库连接异常 token=***REDACTED***\n告警原因：connection_exhausted",
        ),
    ],
    ids=[
        "short-title-wins",
        "empty-title",
        "blank-title",
        "title-26",
        "english-title-27",
        "chinese-title-27",
        "mixed-long-title",
        "collapse-before-measuring",
        "redaction-shortens-title",
        "redaction-expands-title-to-27",
    ],
)
def test_wecom_card_selects_title_after_sanitizing(
    title: str,
    expected_title: str,
    expected_subtitle: str,
) -> None:
    event = analysis_result_event(title=title)
    event.alert.alert_name = "OtherAlert"

    card = build_wecom_template_card(event, page_base_url="https://alerts.intra.example.com")

    assert card["main_title"]["title"] == expected_title
    assert card["sub_title_text"] == expected_subtitle
    assert event.alert.title == title


@pytest.mark.parametrize(
    ("alert_name", "expected_title"),
    [
        ("", "数据库告警分析"),
        (" \n\t ", "数据库告警分析"),
        ("unknown", "数据库告警分析"),
        ("UNKNOWN", "数据库告警分析"),
        (" \tUnKnOwN\n", "数据库告警分析"),
        ("名" * 26, "名" * 26),
        ("名" * 27, "数据库告警分析"),
        (f"{' ' * 30}MongoDBHostMemoryLow\n", "MongoDBHostMemoryLow"),
        ("token=very-long-secret-that-must-be-redacted", "token=***REDACTED***"),
        ("数据库连接异常 token=x", "数据库告警分析"),
    ],
    ids=[
        "empty",
        "blank",
        "unknown",
        "uppercase-unknown",
        "cleaned-mixed-case-unknown",
        "name-26",
        "name-27",
        "collapse-before-measuring",
        "redaction-shortens-name",
        "redaction-expands-name-to-27",
    ],
)
def test_wecom_card_uses_only_valid_short_alert_names(
    alert_name: str,
    expected_title: str,
) -> None:
    event = analysis_result_event(title=MONGODB_MEMORY_TITLE)
    event.alert.alert_name = alert_name
    event.alert.database = None
    original_alert = event.alert.model_dump()

    card = build_wecom_template_card(event, page_base_url="https://alerts.intra.example.com")

    assert card["main_title"]["title"] == expected_title
    assert card["sub_title_text"] == (
        f"告警标题：{MONGODB_MEMORY_TITLE}\n告警原因：connection_exhausted"
    )
    facts = {item["keyname"]: item["value"] for item in card["horizontal_content_list"]}
    assert facts["告警主机"] == "未提供"
    assert facts["数据库"] == "未提供"
    assert event.alert.model_dump() == original_alert


@pytest.mark.parametrize(
    ("title", "reason", "expected_subtitle"),
    [
        ("中" * 107, "原因", f"告警标题：{'中' * 107}"),
        ("中" * 108, "原因", f"告警标题：{'中' * 97}…（完整标题见详情）"),
        ("中" * 101, "原因", f"告警标题：{'中' * 101}"),
        ("中" * 100, "因", f"告警标题：{'中' * 100}\n告警原因：因"),
        ("中" * 100, "原因", f"告警标题：{'中' * 100}\n告警原因：…"),
        ("中" * 99, "原因长", f"告警标题：{'中' * 99}\n告警原因：原…"),
        (MONGODB_MEMORY_TITLE, "", f"告警标题：{MONGODB_MEMORY_TITLE}"),
        (MONGODB_MEMORY_TITLE, " \n\t ", f"告警标题：{MONGODB_MEMORY_TITLE}"),
        ("短标题", "因" * 120, f"告警原因：{'因' * 107}"),
    ],
    ids=[
        "title-line-112",
        "title-line-113-has-detail-marker",
        "reason-prefix-only-is-omitted",
        "one-reason-character-fits",
        "one-character-budget-uses-ellipsis",
        "reason-is-truncated-with-ellipsis",
        "empty-reason-is-omitted",
        "blank-reason-is-omitted",
        "short-title-keeps-existing-reason-limit",
    ],
)
def test_wecom_card_preserves_title_within_body_budget(
    title: str,
    reason: str,
    expected_subtitle: str,
) -> None:
    event = analysis_result_event(title=title)
    event.alert.reason = reason

    card = build_wecom_template_card(event, page_base_url="https://alerts.intra.example.com")

    assert card["sub_title_text"] == expected_subtitle
    assert len(card["sub_title_text"]) <= 112
    assert event.alert.title == title


def test_wecom_card_sanitizes_and_bounds_text_fields() -> None:
    event = analysis_result_event(
        title="数据库连接异常告警\tAuthorization: title-secret",
    )
    event.alert.alert_name = "token=short-secret"
    event.alert.reason = "password=reason-secret\n重试\t稍后"
    original_alert = event.alert.model_dump()
    card = build_wecom_template_card(
        event,
        page_base_url="https://alerts.intra.example.com",
    )

    serialized = str(card)
    assert "must-not-appear" not in serialized
    assert "title-secret" not in serialized
    assert "short-secret" not in serialized
    assert "reason-secret" not in serialized
    assert "***REDACTED***" in serialized
    assert card["main_title"]["title"] == "token=***REDACTED***"
    assert card["sub_title_text"] == (
        "告警标题：数据库连接异常告警 Authorization=***REDACTED***"
        "\n告警原因：password=***REDACTED*** 重试 稍后"
    )
    assert event.alert.model_dump() == original_alert
    assert len(card["main_title"]["title"]) <= 26
    assert len(card["sub_title_text"]) <= 112
    assert all(len(item["value"]) <= 26 for item in card["horizontal_content_list"])


def test_wecom_failure_card_is_deterministic_and_contains_no_recommendation() -> None:
    event = analysis_failure_event()

    card = build_wecom_failure_card(
        event,
        page_base_url="https://alerts.intra.example.com",
    )

    serialized = json.dumps(card, ensure_ascii=False)
    assert card["main_title"]["title"] == "数据库告警分析失败"
    assert card["emphasis_content"] == {
        "title": "AUTHORIZATION",
        "desc": "分析调度已暂停",
    }
    assert "HTTP 403 / permission_denied" in serialized
    assert "must-not-appear" not in serialized
    assert "recommendation" not in serialized.casefold()
    assert "root cause" not in serialized.casefold()


@pytest.mark.asyncio
async def test_wecom_failure_notification_uses_run_scoped_failure_key() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"errcode": 0, "errmsg": "ok", "msgid": "failure-1"})

    event = analysis_failure_event()
    notifier = WeComManagementNotifier(
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=top-secret-key",
        "https://alerts.intra.example.com",
        transport=httpx.MockTransport(handler),
    )

    assert await notifier.send(event) == "failure-1"
    assert requests[0].headers["idempotency-key"] == (
        f"{event.alert.id}:{event.run_id}:analysis_failure"
    )
    assert requests[0].headers["x-analysis-status"] == "FAILED"


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
@pytest.mark.parametrize(
    ("title", "alert_name", "expected_title", "expected_subtitle"),
    [
        (
            "数据库连接数接近上限",
            None,
            "数据库连接数接近上限",
            "告警原因：connection_exhausted",
        ),
        (
            MONGODB_MEMORY_TITLE,
            "MongoDBHostMemoryLow",
            "MongoDBHostMemoryLow",
            f"告警标题：{MONGODB_MEMORY_TITLE}\n告警原因：connection_exhausted",
        ),
        (
            MONGODB_MEMORY_TITLE,
            None,
            "数据库告警分析",
            f"告警标题：{MONGODB_MEMORY_TITLE}\n告警原因：connection_exhausted",
        ),
    ],
    ids=["short-title", "mongodb-alert-name", "mongodb-default-unknown"],
)
async def test_wecom_notifier_sends_one_template_card(
    title: str,
    alert_name: str | None,
    expected_title: str,
    expected_subtitle: str,
) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"errcode": 0, "errmsg": "ok", "msgid": "wecom-message-1"},
        )

    event = analysis_result_event(title=title)
    if alert_name is not None:
        event.alert.alert_name = alert_name
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
    assert request.headers["idempotency-key"] == (
        f"{event.alert.id}:{event.run_id}:analysis_result"
    )
    assert b'"msgtype":"template_card"' in request.content
    assert b'"card_type":"text_notice"' in request.content
    assert request.content.count(b'"title":"') >= 3
    payload = json.loads(request.content)
    assert payload["msgtype"] == "template_card"
    assert payload["template_card"]["main_title"]["title"] == expected_title
    assert payload["template_card"]["sub_title_text"] == expected_subtitle
    assert "must-not-appear" not in request.content.decode()
    assert event.alert.title == title


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
