from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import httpx

from app.application.sanitization import sanitize_text
from app.domain.errors import NotificationError
from app.domain.models import AnalysisResultEvent

logger = logging.getLogger(__name__)

WECOM_RATE_LIMIT_PER_MINUTE = 20
WECOM_RATE_LIMIT_WINDOW_SECONDS = 60.0
_WHITESPACE = re.compile(r"\s+")


def _safe_text(value: Any, *, limit: int, fallback: str = "未提供") -> str:
    raw = "" if value is None else str(value)
    cleaned = _WHITESPACE.sub(" ", sanitize_text(raw)).strip()
    return cleaned[:limit] or fallback


def _action_urls(
    event: AnalysisResultEvent,
    *,
    page_base_url: str,
) -> dict[str, str]:
    alert_id = quote(str(event.alert.id), safe="")
    wecom_url = f"{page_base_url.rstrip('/')}/wecom/alerts/{alert_id}"
    return {
        "overview": wecom_url,
        "root_cause": f"{wecom_url}/root-cause",
        "recovery_advice": f"{wecom_url}/recovery-advice",
    }


def build_wecom_template_card(
    event: AnalysisResultEvent,
    *,
    page_base_url: str,
) -> dict[str, Any]:
    """Build a bounded WeCom text-notice card with analysis detail actions."""

    if not page_base_url:
        raise NotificationError("WeCom page base URL is not configured")

    alert = event.alert
    database = alert.database
    urls = _action_urls(event, page_base_url=page_base_url)
    severity_labels = {
        "CRITICAL": "严重",
        "WARNING": "警告",
        "INFO": "提示",
    }
    status_labels = {
        "COMPLETED": "分析完成",
        "INCONCLUSIVE": "结论不充分",
        "FAILED": "分析失败",
    }
    severity = alert.severity.value
    host = (database.host or database.instance) if database else None
    database_name = None
    if database:
        database_name = " / ".join(
            value for value in (database.engine, database.database) if value
        )

    return {
        "card_type": "text_notice",
        "source": {
            "desc": "数据库告警 Agent",
            "desc_color": 2 if severity == "CRITICAL" else 0,
        },
        "main_title": {
            "title": _safe_text(alert.title, limit=26),
            "desc": _safe_text(alert.occurred_at.isoformat(), limit=30),
        },
        "emphasis_content": {
            "title": _safe_text(severity, limit=10),
            "desc": _safe_text(
                status_labels.get(event.status.value, event.status.value),
                limit=15,
            ),
        },
        "sub_title_text": _safe_text(
            f"告警原因：{alert.reason}",
            limit=112,
        ),
        "horizontal_content_list": [
            {
                "keyname": "告警级别",
                "value": _safe_text(
                    f"{severity_labels.get(severity, severity)} / {severity}",
                    limit=26,
                ),
            },
            {"keyname": "告警主机", "value": _safe_text(host, limit=26)},
            {"keyname": "数据库", "value": _safe_text(database_name, limit=26)},
            {"keyname": "环境", "value": _safe_text(alert.environment, limit=26)},
            {"keyname": "服务", "value": _safe_text(alert.service_name, limit=26)},
            {"keyname": "外部ID", "value": _safe_text(alert.external_id, limit=26)},
        ],
        "jump_list": [
            {
                "type": 1,
                "title": "告警根因分析",
                "url": urls["root_cause"],
            },
            {
                "type": 1,
                "title": "告警恢复建议",
                "url": urls["recovery_advice"],
            },
        ],
        # WeCom requires template_card.card_action. The overview page exposes
        # only the summary, so it cannot be used to switch between the two
        # dedicated detail actions above.
        "card_action": {"type": 1, "url": urls["overview"]},
    }


class _WeComRateLimiter:
    """Sliding-window rate limiter for WeCom group robot messages.

    WeCom enforces a hard limit of 20 messages per minute per webhook. This
    limiter tracks send timestamps in a deque and blocks callers when the
    window is full, releasing them once the oldest entry expires.
    """

    def __init__(
        self,
        *,
        max_per_window: int = WECOM_RATE_LIMIT_PER_MINUTE,
        window_seconds: float = WECOM_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self._max = max_per_window
        self._window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            while True:
                now = loop.time()
                threshold = now - self._window
                while self._timestamps and self._timestamps[0] <= threshold:
                    self._timestamps.popleft()
                if len(self._timestamps) < self._max:
                    self._timestamps.append(now)
                    return
                wait = self._timestamps[0] + self._window - now
                if wait > 0:
                    await asyncio.sleep(wait)


class LogManagementNotifier:
    async def send(self, event: AnalysisResultEvent) -> str:
        delivery_id = f"log-{uuid4()}"
        logger.warning(
            "analysis_result delivery_id=%s alert_id=%s status=%s knowledge_matches=%s",
            delivery_id,
            event.alert.id,
            event.status.value,
            len(event.recommendation.knowledge_matches),
        )
        return delivery_id


class WeComManagementNotifier:
    def __init__(
        self,
        url: str,
        page_base_url: str,
        timeout_seconds: float = 10,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        max_retries: int = 1,
        retry_delay_seconds: float = 1.0,
        rate_limit_per_minute: int = WECOM_RATE_LIMIT_PER_MINUTE,
    ) -> None:
        self._url = url
        self._page_base_url = page_base_url
        self._timeout = timeout_seconds
        self._transport = transport
        self._max_retries = max_retries
        self._retry_delay = retry_delay_seconds
        self._rate_limiter = _WeComRateLimiter(max_per_window=rate_limit_per_minute)

    async def send(self, event: AnalysisResultEvent) -> str | None:
        if not self._url:
            raise NotificationError("WeCom webhook URL is not configured")
        headers = {
            "Content-Type": "application/json",
            "X-Alert-Id": str(event.alert.id),
            "X-Analysis-Status": event.status.value,
            "Idempotency-Key": f"{event.alert.id}:analysis-result",
        }
        payload = {
            "msgtype": "template_card",
            "template_card": build_wecom_template_card(
                event,
                page_base_url=self._page_base_url,
            ),
        }

        response: httpx.Response | None = None
        for attempt in range(self._max_retries + 1):
            await self._rate_limiter.acquire()
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout, transport=self._transport
                ) as client:
                    response = await client.post(
                        self._url, json=payload, headers=headers
                    )
                    response.raise_for_status()
                break
            except httpx.HTTPStatusError as exc:
                # Non-retryable: WeCom returned an HTTP error status.
                raise NotificationError(
                    f"WeCom webhook returned HTTP {exc.response.status_code}"
                ) from exc
            except (httpx.TimeoutException, httpx.HTTPError) as exc:
                if attempt < self._max_retries:
                    logger.warning(
                        "wecom_send_retry alert_id=%s attempt=%s error=%s",
                        event.alert.id,
                        attempt + 1,
                        type(exc).__name__,
                    )
                    await asyncio.sleep(self._retry_delay)
                    continue
                if isinstance(exc, httpx.TimeoutException):
                    raise NotificationError("WeCom webhook timed out") from exc
                raise NotificationError(
                    f"WeCom webhook request failed: {type(exc).__name__}"
                ) from exc

        assert response is not None  # noqa: S101 - reached only on success

        try:
            result = response.json()
        except ValueError as exc:
            raise NotificationError("WeCom webhook returned invalid JSON") from exc
        if not isinstance(result, dict) or "errcode" not in result:
            raise NotificationError("WeCom webhook response is missing errcode")
        if result["errcode"] != 0:
            error_code = _safe_text(result["errcode"], limit=40)
            errmsg = _safe_text(result.get("errmsg", ""), limit=200, fallback="")
            raise NotificationError(
                f"WeCom webhook rejected message: errcode={error_code} errmsg={errmsg}"
            )
        message_id = result.get("msgid")
        if message_id is not None:
            return str(message_id)
        return response.headers.get("X-Request-Id") or response.headers.get("X-Delivery-Id")
