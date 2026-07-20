from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import httpx

from app.application.sanitization import sanitize_text
from app.domain.routing import (
    DeliveryResult,
    DeliveryState,
    RoutingAction,
    RoutingContext,
)

logger = logging.getLogger(__name__)


class EnterpriseWeComDirectory:
    """Draft adapter for the future company roster/calendar API.

    Expected JSON fields are deliberately small: ``on_call`` and
    ``is_working_time``. Until the endpoint is supplied, it falls back to Sona
    and Monday-Friday 09:00-18:00 in the configured timezone.
    """

    def __init__(
        self,
        url: str,
        bearer_token: str,
        fallback_oncall: str,
        timezone: str = "Asia/Shanghai",
        timeout_seconds: float = 5,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self.bearer_token = bearer_token
        self.fallback_oncall = fallback_oncall
        self.timezone = ZoneInfo(timezone)
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def get_on_call(self, at: datetime) -> str:
        payload = await self._fetch(at)
        value = payload.get("on_call") if payload else None
        return str(value).strip() if value else self.fallback_oncall

    async def is_non_working_time(self, at: datetime) -> bool:
        payload = await self._fetch(at)
        if payload and isinstance(payload.get("is_working_time"), bool):
            return not payload["is_working_time"]
        local = at.astimezone(self.timezone)
        return local.weekday() >= 5 or not (9 <= local.hour < 18)

    async def _fetch(self, at: datetime) -> dict[str, Any]:
        if not self.url:
            return {}
        headers = {"Accept": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport
            ) as client:
                response = await client.get(
                    self.url, params={"at": at.isoformat()}, headers=headers
                )
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, dict) else {}
        except (httpx.HTTPError, ValueError):
            logger.warning("WeCom on-call/calendar API unavailable; using fallback")
            return {}


class EscalationDispatcher:
    def __init__(
        self,
        *,
        group_webhook_urls: dict[str, str],
        card_api_url: str,
        card_api_bearer_token: str,
        ack_callback_base_url: str,
        ack_callback_token: str,
        phone_api_url: str,
        phone_api_bearer_token: str,
        directory: EnterpriseWeComDirectory,
        timeout_seconds: float = 10,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.group_webhook_urls = {
            key.upper(): value for key, value in group_webhook_urls.items()
        }
        self.card_api_url = card_api_url
        self.card_api_bearer_token = card_api_bearer_token
        self.ack_callback_base_url = ack_callback_base_url
        self.ack_callback_token = ack_callback_token
        self.phone_api_url = phone_api_url
        self.phone_api_bearer_token = phone_api_bearer_token
        self.directory = directory
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def send(
        self, action: RoutingAction, context: RoutingContext
    ) -> DeliveryResult:
        if action.severities and context.alert.severity not in action.severities:
            return DeliveryResult(state=DeliveryState.SKIPPED)
        recipient = await self._recipient(action.recipient, context.alert.occurred_at)
        if action.mention_on_call and not recipient:
            recipient = await self.directory.get_on_call(context.alert.occurred_at)
        if action.channel == "wecom_group":
            result = await self._send_group(action, context, recipient)
        elif action.channel == "wecom_card":
            result = await self._send_card(context, recipient)
        elif action.channel == "phone":
            result = await self._call_phone(context, recipient)
        else:  # pragma: no cover - RoutingAction validates the channel
            result = DeliveryResult(
                state=DeliveryState.FAILED, error="Unsupported channel"
            )
        return result.model_copy(update={"recipient": recipient})

    async def _recipient(self, value: str | None, at: datetime) -> str | None:
        if value == "on_call":
            return await self.directory.get_on_call(at)
        return value

    async def _send_group(
        self,
        action: RoutingAction,
        context: RoutingContext,
        recipient: str | None,
    ) -> DeliveryResult:
        target = (action.target or "").upper()
        url = self.group_webhook_urls.get(target)
        if not url:
            return DeliveryResult(
                state=DeliveryState.SKIPPED,
                error=f"No webhook configured for group {target}",
            )
        mention = ""
        if action.mention_on_call:
            mention = recipient or ""
        content = self._message(context, mention)
        return await self._post_wecom(
            url,
            {"msgtype": "markdown", "markdown": {"content": content}},
            idempotency_key=(
                f"{context.incident.id}:{context.incident.current_step}:group:{target}"
            ),
        )

    async def _send_card(
        self, context: RoutingContext, recipient: str | None
    ) -> DeliveryResult:
        if not self.card_api_url:
            return DeliveryResult(
                state=DeliveryState.SKIPPED, error="WECOM_CARD_API_URL is not configured"
            )
        if not self.ack_callback_base_url or not self.ack_callback_token:
            return DeliveryResult(
                state=DeliveryState.SKIPPED,
                error=(
                    "WECOM_ACK_CALLBACK_BASE_URL and WECOM_ACK_CALLBACK_TOKEN "
                    "must be configured for cards"
                ),
            )
        callback_url = urljoin(
            self.ack_callback_base_url.rstrip("/") + "/",
            f"api/v1/integrations/wecom/alerts/{context.incident.id}/ack",
        )
        payload = {
            "schema_version": 1,
            "recipient": recipient,
            "incident_id": str(context.incident.id),
            "alert_id": str(context.alert.id),
            "severity": context.alert.severity.value,
            "title": sanitize_text(context.alert.title),
            "policy": context.policy.id,
            "ack": {
                "callback_url": callback_url,
                "method": "POST",
                "bearer_token": self.ack_callback_token,
            },
        }
        return await self._post_json(
            self.card_api_url,
            payload,
            self.card_api_bearer_token,
            idempotency_key=(
                f"{context.incident.id}:{context.incident.current_step}:card:{recipient}"
            ),
        )

    async def _call_phone(
        self, context: RoutingContext, recipient: str | None
    ) -> DeliveryResult:
        if not self.phone_api_url:
            return DeliveryResult(
                state=DeliveryState.SKIPPED,
                error="PHONE_NOTIFICATION_API_URL is not configured",
            )
        payload = {
            "schema_version": 1,
            "recipient": recipient,
            "incident_id": str(context.incident.id),
            "alert_id": str(context.alert.id),
            "severity": context.alert.severity.value,
            "title": sanitize_text(context.alert.title),
        }
        result, response_data = await self._post_json_with_data(
            self.phone_api_url,
            payload,
            self.phone_api_bearer_token,
            idempotency_key=(
                f"{context.incident.id}:{context.incident.current_step}:phone:{recipient}"
            ),
        )
        if result.state != DeliveryState.SENT:
            return result
        connected = response_data.get("connected") is True
        return result.model_copy(
            update={
                "acknowledged": connected,
                "acknowledged_by": recipient if connected else None,
            }
        )

    async def _post_wecom(
        self, url: str, payload: dict[str, Any], *, idempotency_key: str
    ) -> DeliveryResult:
        result, data = await self._post_json_with_data(
            url, payload, "", idempotency_key=idempotency_key
        )
        if result.state == DeliveryState.SENT and data.get("errcode") not in {None, 0}:
            return DeliveryResult(
                state=DeliveryState.FAILED,
                error=f"WeCom rejected message: errcode={data.get('errcode')}",
            )
        return result

    async def _post_json(
        self,
        url: str,
        payload: dict[str, Any],
        bearer_token: str,
        *,
        idempotency_key: str,
    ) -> DeliveryResult:
        result, _ = await self._post_json_with_data(
            url, payload, bearer_token, idempotency_key=idempotency_key
        )
        return result

    async def _post_json_with_data(
        self,
        url: str,
        payload: dict[str, Any],
        bearer_token: str,
        *,
        idempotency_key: str,
    ) -> tuple[DeliveryResult, dict[str, Any]]:
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
        }
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport
            ) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                delivery_id = (
                    data.get("delivery_id")
                    or data.get("request_id")
                    or response.headers.get("X-Request-Id")
                )
                return (
                    DeliveryResult(
                        state=DeliveryState.SENT,
                        external_delivery_id=str(delivery_id) if delivery_id else None,
                    ),
                    data,
                )
        except httpx.HTTPError as exc:
            return (
                DeliveryResult(
                    state=DeliveryState.FAILED,
                    error=f"{type(exc).__name__}: {sanitize_text(str(exc))}",
                ),
                {},
            )

    @staticmethod
    def _message(context: RoutingContext, mention: str | None) -> str:
        alert = context.alert
        lines = [
            f"### 数据库告警 · {alert.severity.value}",
            f"> 标题：{sanitize_text(alert.title)}",
            f"> 告警：{sanitize_text(alert.alert_name)}",
            f"> 集群：{sanitize_text(alert.cluster or '-')}",
            f"> 策略：{sanitize_text(context.policy.name)}",
            f"> 告警 ID：{alert.id}",
        ]
        if mention:
            lines.append(f"> 值班人：@{sanitize_text(mention)}")
        return "\n".join(lines)
