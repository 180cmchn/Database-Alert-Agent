from __future__ import annotations

import logging
from uuid import uuid4

import httpx

from app.domain.errors import NotificationError
from app.domain.models import NotificationEvent

logger = logging.getLogger(__name__)


class LogManagementNotifier:
    async def send(self, event: NotificationEvent) -> str:
        delivery_id = f"log-{uuid4()}"
        logger.warning(
            "management_notification delivery_id=%s phase=%s alert_id=%s payload=%s",
            delivery_id,
            event.phase,
            event.alert.id,
            event.model_dump(mode="json"),
        )
        return delivery_id


class WebhookManagementNotifier:
    def __init__(self, url: str, bearer_token: str = "", timeout_seconds: float = 10) -> None:
        self._url = url
        self._bearer_token = bearer_token
        self._timeout = timeout_seconds

    async def send(self, event: NotificationEvent) -> str | None:
        if not self._url:
            raise NotificationError("Management webhook URL is not configured")
        headers = {"Content-Type": "application/json"}
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._url, json=event.model_dump(mode="json"), headers=headers
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise NotificationError(f"Management webhook failed: {exc}") from exc
        return response.headers.get("X-Request-Id") or response.headers.get("X-Delivery-Id")
