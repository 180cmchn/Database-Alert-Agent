from __future__ import annotations

import asyncio
import html
import logging
import re
from collections import deque
from typing import Any
from uuid import uuid4

import httpx

from app.application.sanitization import sanitize_text
from app.domain.errors import NotificationError
from app.domain.models import AnalysisBasisSource, AnalysisResultEvent

logger = logging.getLogger(__name__)

WECOM_MARKDOWN_MAX_BYTES = 3800
WECOM_RATE_LIMIT_PER_MINUTE = 20
WECOM_RATE_LIMIT_WINDOW_SECONDS = 60.0
_WHITESPACE = re.compile(r"\s+")


def _safe_line(value: Any, *, limit: int = 500) -> str:
    cleaned = _WHITESPACE.sub(" ", sanitize_text(str(value))).strip()
    escaped = html.escape(cleaned, quote=False)
    return escaped[:limit]


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


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    suffix = "\n> 内容已截断，请按告警 ID 在管理台查看完整详情。"
    suffix_bytes = suffix.encode("utf-8")
    available = max(0, max_bytes - len(suffix_bytes))
    prefix = encoded[:available].decode("utf-8", errors="ignore").rstrip()
    return f"{prefix}{suffix}"


def format_wecom_markdown(event: AnalysisResultEvent) -> str:
    """Render a bounded, sanitized WeCom message without raw alert payloads."""

    alert = event.alert
    severity_color = (
        "warning" if alert.severity.value in {"CRITICAL", "WARNING"} else "info"
    )
    lines = [
        "### 数据库告警 · AI 分析结果",
        (
            "> 等级："
            f'<font color="{severity_color}">{_safe_line(alert.severity.value)}</font>'
        ),
        f"> 标题：{_safe_line(alert.title)}",
        f"> 原因：{_safe_line(alert.reason)}",
        f"> 来源：{_safe_line(alert.source)}",
        f"> 外部 ID：{_safe_line(alert.external_id)}",
        f"> 环境：{_safe_line(alert.environment)}",
        f"> 服务：{_safe_line(alert.service_name)}",
    ]
    if alert.database and alert.database.instance:
        lines.append(f"> 实例：{_safe_line(alert.database.instance)}")
    lines.extend(
        [
            f"> 发生时间：{_safe_line(alert.occurred_at.isoformat())}",
            f"> 告警 ID：{_safe_line(alert.id)}",
            "",
            f"**状态说明**  {_safe_line(event.message, limit=1000)}",
        ]
    )
    recommendation = event.recommendation
    lines.extend(
        [
            "",
            "**AI 分析摘要**",
            _safe_line(recommendation.summary, limit=1200),
            "",
            (
                f"> 分析状态：{_safe_line(event.status.value)}　"
                f"置信度：{recommendation.confidence:.0%}"
            ),
        ]
    )
    if recommendation.likely_causes:
        lines.extend(["", "**可能原因**"])
        for index, cause in enumerate(recommendation.likely_causes[:5], start=1):
            lines.append(f"{index}. {_safe_line(cause, limit=700)}")
    if recommendation.analysis_bases:
        lines.extend(["", "**判断依据（手册优先，AI 其次）**"])
        for index, basis in enumerate(recommendation.analysis_bases[:8], start=1):
            label = "手册" if basis.source == AnalysisBasisSource.RUNBOOK else "AI"
            reference = ""
            if basis.source_ref:
                reference = (
                    f"（{_safe_line(basis.source_ref.runbook_id)}/"
                    f"{_safe_line(basis.source_ref.section)}）"
                )
            lines.append(
                f"{index}. [{label}]{reference} {_safe_line(basis.statement, limit=700)}"
            )
    if recommendation.steps:
        lines.extend(["", "**建议核查步骤（前 3 条）**"])
        for index, step in enumerate(recommendation.steps[:3], start=1):
            lines.append(f"{index}. {_safe_line(step.action, limit=700)}")

    return _truncate_utf8("\n".join(lines), WECOM_MARKDOWN_MAX_BYTES)


class LogManagementNotifier:
    async def send(self, event: AnalysisResultEvent) -> str:
        delivery_id = f"log-{uuid4()}"
        logger.warning(
            "analysis_result delivery_id=%s alert_id=%s status=%s "
            "manual_matched=%s requires_human=%s",
            delivery_id,
            event.alert.id,
            event.status.value,
            event.recommendation.manual_matched,
            event.recommendation.requires_human,
        )
        return delivery_id


class WeComManagementNotifier:
    def __init__(
        self,
        url: str,
        timeout_seconds: float = 10,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        max_retries: int = 1,
        retry_delay_seconds: float = 1.0,
        rate_limit_per_minute: int = WECOM_RATE_LIMIT_PER_MINUTE,
    ) -> None:
        self._url = url
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
            "msgtype": "markdown",
            "markdown": {"content": format_wecom_markdown(event)},
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
            error_code = _safe_line(result["errcode"], limit=40)
            errmsg = _safe_line(result.get("errmsg", ""), limit=200)
            raise NotificationError(
                f"WeCom webhook rejected message: errcode={error_code} errmsg={errmsg}"
            )
        message_id = result.get("msgid")
        if message_id is not None:
            return str(message_id)
        return response.headers.get("X-Request-Id") or response.headers.get("X-Delivery-Id")
