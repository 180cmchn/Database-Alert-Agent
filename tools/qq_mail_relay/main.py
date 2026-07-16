from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from app.domain.models import NotificationEvent
from tools.qq_mail_relay.formatter import build_email
from tools.qq_mail_relay.mailer import MailDeliveryError, Mailer, QQSMTPMailer
from tools.qq_mail_relay.settings import RelaySettings
from tools.qq_mail_relay.storage import SQLiteDeliveryStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeliveryResult:
    delivery_id: str
    duplicate: bool


class NotificationRelay:
    def __init__(
        self,
        settings: RelaySettings,
        store: SQLiteDeliveryStore,
        mailer: Mailer,
    ) -> None:
        self._settings = settings
        self._store = store
        self._mailer = mailer
        # This test relay intentionally runs as one process. Serializing delivery
        # closes the common same-process race before the SQLite success record exists.
        self._delivery_lock = asyncio.Lock()

    async def deliver(self, event: NotificationEvent) -> DeliveryResult:
        event_key = f"{event.alert.id}:{event.phase.value}"
        digest = hashlib.sha256(event_key.encode()).hexdigest()[:32]
        delivery_id = f"qqmail-{digest}"

        async with self._delivery_lock:
            existing = await self._store.get_success(event_key)
            if existing:
                return DeliveryResult(delivery_id=existing, duplicate=True)

            message = build_email(event, self._settings, delivery_id)
            await self._mailer.send(message)
            await self._store.save_success(event_key, delivery_id)
            return DeliveryResult(delivery_id=delivery_id, duplicate=False)


def create_app(
    settings: RelaySettings | None = None,
    *,
    store: SQLiteDeliveryStore | None = None,
    mailer: Mailer | None = None,
) -> FastAPI:
    settings = settings or RelaySettings()
    store = store or SQLiteDeliveryStore(settings.database_path)
    mailer = mailer or QQSMTPMailer(settings)
    relay = NotificationRelay(settings, store, mailer)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await store.initialize()
        yield

    app = FastAPI(title="QQ Mail Notification Relay", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.relay = relay

    async def require_bearer(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        configured = settings.bearer_token.get_secret_value()
        if not configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Relay authentication is not configured",
            )
        scheme, separator, supplied = (authorization or "").partition(" ")
        valid = (
            bool(separator)
            and scheme.casefold() == "bearer"
            and hmac.compare_digest(
                supplied.encode("utf-8"),
                configured.encode("utf-8"),
            )
        )
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        issues = settings.readiness_issues()
        try:
            await store.ping()
        except Exception:
            logger.warning("qq_mail_relay readiness database check failed", exc_info=True)
            issues.append("SQLite delivery store is unavailable")
        code = status.HTTP_200_OK if not issues else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(
            status_code=code,
            content={"status": "ready" if not issues else "not_ready", "issues": issues},
        )

    @app.post("/api/v1/notifications", dependencies=[Depends(require_bearer)])
    async def receive_notification(event: NotificationEvent) -> JSONResponse:
        issues = settings.readiness_issues()
        if issues:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "not_ready", "issues": issues},
            )
        try:
            result = await relay.deliver(event)
        except MailDeliveryError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="SMTP delivery failed",
            ) from exc
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            headers={"X-Delivery-Id": result.delivery_id},
            content={
                "errcode": 0,
                "errmsg": "ok",
                "delivery_id": result.delivery_id,
                "duplicate": result.duplicate,
            },
        )

    return app


app = create_app()
