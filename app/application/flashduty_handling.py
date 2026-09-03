from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from app.adapters.flashduty import FlashDutyError, FlashDutyResponse
from app.domain.models import NormalizedAlert

logger = logging.getLogger(__name__)

FLASHDUTY_HANDLING_TIMEOUT_SECONDS = 15.0
FLASHDUTY_MEMBER_NAME_CACHE_TTL_SECONDS = 300.0
_INCIDENT_DETAILS_UNAVAILABLE = "INCIDENT_DETAILS_UNAVAILABLE"
_OBJECT_ID_LENGTH = 24
_MEMBER_PAGE_LIMIT = 100


class FlashDutyHandlingError(RuntimeError):
    """Base error for the current FlashDuty handling projection."""


class FlashDutyHandlingNotApplicableError(FlashDutyHandlingError):
    """The stored alert is not backed by FlashDuty."""


class FlashDutyHandlingInvalidResponseError(FlashDutyHandlingError):
    """FlashDuty returned data that cannot form a trustworthy projection."""


class FlashDutyHandlingTimeoutError(FlashDutyHandlingError):
    """The alert lookup did not finish within the interactive request budget."""


class FlashDutyProgress(StrEnum):
    TRIGGERED = "Triggered"
    PROCESSING = "Processing"
    CLOSED = "Closed"


@dataclass(frozen=True)
class FlashDutyHandler:
    person_id: int
    person_name: str | None
    assigned_at: datetime | None
    acknowledged_at: datetime


@dataclass(frozen=True)
class FlashDutyHandlingResult:
    linked_incident: bool
    incident_id: str | None
    progress: FlashDutyProgress | None
    handlers: tuple[FlashDutyHandler, ...]
    handlers_complete: bool
    refreshed_at: datetime
    warning_code: str | None = None


@dataclass(frozen=True)
class _CachedMemberName:
    value: str | None
    expires_at: float


class FlashDutyMemberNameResolver:
    """Resolve responder IDs without retaining member directory PII."""

    def __init__(
        self,
        *,
        ttl_seconds: float = FLASHDUTY_MEMBER_NAME_CACHE_TTL_SECONDS,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl_seconds = ttl_seconds
        self._cache: dict[int, _CachedMemberName] = {}
        self._client: FlashDutyHandlingClient | None = None
        self._lock = asyncio.Lock()

    def _cached(
        self,
        person_ids: set[int],
        now: float,
    ) -> tuple[dict[int, str], set[int]]:
        names: dict[int, str] = {}
        unresolved: set[int] = set()
        for person_id in person_ids:
            cached = self._cache.get(person_id)
            if cached is None or cached.expires_at <= now:
                self._cache.pop(person_id, None)
                unresolved.add(person_id)
            elif cached.value is not None:
                names[person_id] = cached.value
        return names, unresolved

    async def resolve(
        self,
        client: FlashDutyHandlingClient,
        person_ids: set[int],
        *,
        deadline: float,
    ) -> dict[int, str]:
        if not person_ids:
            return {}

        loop = asyncio.get_running_loop()
        if client is self._client:
            names, unresolved = self._cached(person_ids, loop.time())
        else:
            names, unresolved = {}, set(person_ids)
        if not unresolved:
            return names

        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError

        async with asyncio.timeout(remaining):
            async with self._lock:
                if client is not self._client:
                    self._client = client
                    self._cache.clear()
                cached_names, unresolved = self._cached(unresolved, loop.time())
                names.update(cached_names)
                if not unresolved:
                    return names

                page = 1
                reached_end = False
                resolved_names: dict[int, str] = {}
                while unresolved:
                    response = await client.list_members(
                        page=page,
                        limit=_MEMBER_PAGE_LIMIT,
                        retry_until_cancelled=False,
                    )
                    members, total = _member_page(response, page)
                    for member in members:
                        member_id = member.get("member_id")
                        if (
                            isinstance(member_id, bool)
                            or not isinstance(member_id, int)
                            or member_id <= 0
                        ):
                            raise FlashDutyHandlingInvalidResponseError(
                                f"FlashDuty member list page {page}.member_id must be "
                                "a positive integer"
                            )
                        if member_id not in unresolved:
                            continue
                        member_name_value = member.get("member_name")
                        if member_name_value is not None and not isinstance(member_name_value, str):
                            raise FlashDutyHandlingInvalidResponseError(
                                f"FlashDuty member {member_id}.member_name must be a string"
                            )
                        member_name = member_name_value.strip() if member_name_value else None
                        if member_name:
                            resolved_names[member_id] = member_name
                            unresolved.remove(member_id)

                    if page * _MEMBER_PAGE_LIMIT >= total or not members:
                        reached_end = True
                        break
                    page += 1

                expires_at = loop.time() + self._ttl_seconds
                for member_id, member_name in resolved_names.items():
                    self._cache[member_id] = _CachedMemberName(member_name, expires_at)
                if reached_end:
                    for member_id in unresolved:
                        self._cache[member_id] = _CachedMemberName(None, expires_at)
                names.update(resolved_names)
                return names


class FlashDutyHandlingClient(Protocol):
    async def alert_info(
        self,
        alert_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse: ...

    async def incident_info(
        self,
        incident_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse: ...

    async def list_members(
        self,
        *,
        page: int,
        limit: int = 100,
        retry_until_cancelled: bool = False,
    ) -> FlashDutyResponse: ...


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FlashDutyHandlingInvalidResponseError(f"FlashDuty {label} must be an object")
    return value


def _object_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _OBJECT_ID_LENGTH
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise FlashDutyHandlingInvalidResponseError(
            f"FlashDuty {label} must be a 24-character ObjectID"
        )
    return value


def _progress(value: Any) -> FlashDutyProgress:
    try:
        return FlashDutyProgress(value)
    except (TypeError, ValueError) as exc:
        raise FlashDutyHandlingInvalidResponseError(
            "FlashDuty incident progress must be Triggered, Processing, or Closed"
        ) from exc


def _timestamp(value: Any, label: str, *, zero_is_none: bool = False) -> datetime | None:
    if value is None and zero_is_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise FlashDutyHandlingInvalidResponseError(f"FlashDuty {label} must be Unix seconds")
    if zero_is_none and value == 0:
        return None
    if value <= 0:
        raise FlashDutyHandlingInvalidResponseError(
            f"FlashDuty {label} must be a positive Unix timestamp"
        )
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise FlashDutyHandlingInvalidResponseError(
            f"FlashDuty {label} is outside the supported timestamp range"
        ) from exc


def _linked_incident(
    alert_data: Mapping[str, Any],
    expected_alert_id: str,
) -> tuple[str, FlashDutyProgress] | None:
    returned_alert_id = _object_id(alert_data.get("alert_id"), "alert_id")
    if returned_alert_id != expected_alert_id:
        raise FlashDutyHandlingInvalidResponseError(
            "FlashDuty alert detail identity does not match the stored alert"
        )

    incident_value = alert_data.get("incident")
    if incident_value is None or incident_value == {}:
        return None
    incident = _mapping(incident_value, "alert incident")
    return (
        _object_id(incident.get("incident_id"), "incident_id"),
        _progress(incident.get("progress")),
    )


def _incident_detail(
    response: FlashDutyResponse,
    expected_incident_id: str,
) -> tuple[Mapping[str, Any], FlashDutyProgress]:
    incident = _mapping(response.data, "incident detail")
    returned_incident_id = _object_id(incident.get("incident_id"), "incident_id")
    if returned_incident_id != expected_incident_id:
        raise FlashDutyHandlingInvalidResponseError(
            "FlashDuty incident detail identity does not match the linked incident"
        )
    return incident, _progress(incident.get("progress"))


def _member_page(
    response: FlashDutyResponse,
    page: int,
) -> tuple[list[Mapping[str, Any]], int]:
    data = _mapping(response.data, f"member list page {page}")
    items_value = data.get("items")
    if not isinstance(items_value, list):
        raise FlashDutyHandlingInvalidResponseError(
            f"FlashDuty member list page {page}.items must be a list"
        )
    total = data.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise FlashDutyHandlingInvalidResponseError(
            f"FlashDuty member list page {page}.total must be a non-negative integer"
        )
    return [
        _mapping(item, f"member list page {page}.items[{index}]")
        for index, item in enumerate(items_value)
    ], total


def _handlers(incident: Mapping[str, Any]) -> tuple[FlashDutyHandler, ...]:
    responders_value = incident.get("responders", [])
    if responders_value is None:
        responders_value = []
    if not isinstance(responders_value, list):
        raise FlashDutyHandlingInvalidResponseError("FlashDuty responders must be a list")

    handlers: list[FlashDutyHandler] = []
    for index, responder_value in enumerate(responders_value):
        responder = _mapping(responder_value, f"responder[{index}]")
        person_id = responder.get("person_id")
        if isinstance(person_id, bool) or not isinstance(person_id, int) or person_id <= 0:
            raise FlashDutyHandlingInvalidResponseError(
                f"FlashDuty responder[{index}].person_id must be a positive integer"
            )
        acknowledged_at = _timestamp(
            responder.get("acknowledged_at"),
            f"responder[{index}].acknowledged_at",
            zero_is_none=True,
        )
        if acknowledged_at is None:
            continue
        assigned_at = _timestamp(
            responder.get("assigned_at"),
            f"responder[{index}].assigned_at",
            zero_is_none=True,
        )
        person_name_value = responder.get("person_name")
        if person_name_value is not None and not isinstance(person_name_value, str):
            raise FlashDutyHandlingInvalidResponseError(
                f"FlashDuty responder[{index}].person_name must be a string"
            )
        person_name = person_name_value.strip() if person_name_value else None
        handlers.append(
            FlashDutyHandler(
                person_id=person_id,
                person_name=person_name or None,
                assigned_at=assigned_at,
                acknowledged_at=acknowledged_at,
            )
        )

    handlers.sort(key=lambda item: (item.acknowledged_at, item.person_id))
    return tuple(handlers)


async def read_flashduty_handling(
    client: FlashDutyHandlingClient,
    alert: NormalizedAlert,
    *,
    member_name_resolver: FlashDutyMemberNameResolver,
    timeout_seconds: float = FLASHDUTY_HANDLING_TIMEOUT_SECONDS,
) -> FlashDutyHandlingResult:
    """Read the linked incident's current progress and acknowledged responders."""

    if alert.source.casefold() != "flashduty":
        raise FlashDutyHandlingNotApplicableError(
            "Current FlashDuty handling is available only for FlashDuty alerts"
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    external_alert_id = _object_id(alert.external_id, "stored alert_id")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    try:
        async with asyncio.timeout(max(0, deadline - loop.time())):
            alert_response = await client.alert_info(
                external_alert_id,
                retry_until_cancelled=False,
            )
    except TimeoutError as exc:
        raise FlashDutyHandlingTimeoutError(
            "FlashDuty alert detail lookup exceeded the interactive timeout"
        ) from exc

    alert_data = _mapping(alert_response.data, "alert detail")
    linked = _linked_incident(alert_data, external_alert_id)
    if linked is None:
        return FlashDutyHandlingResult(
            linked_incident=False,
            incident_id=None,
            progress=None,
            handlers=(),
            handlers_complete=True,
            refreshed_at=datetime.now(UTC),
        )

    incident_id, alert_progress = linked
    remaining = deadline - loop.time()
    if remaining <= 0:
        return FlashDutyHandlingResult(
            linked_incident=True,
            incident_id=incident_id,
            progress=alert_progress,
            handlers=(),
            handlers_complete=False,
            refreshed_at=datetime.now(UTC),
            warning_code=_INCIDENT_DETAILS_UNAVAILABLE,
        )

    try:
        async with asyncio.timeout(remaining):
            incident_response = await client.incident_info(
                incident_id,
                retry_until_cancelled=False,
            )
        incident, incident_progress = _incident_detail(incident_response, incident_id)
    except (TimeoutError, FlashDutyError, FlashDutyHandlingInvalidResponseError) as exc:
        logger.warning(
            "flashduty_incident_detail_unavailable alert_id=%s incident_id=%s error=%s",
            external_alert_id,
            incident_id,
            type(exc).__name__,
        )
        return FlashDutyHandlingResult(
            linked_incident=True,
            incident_id=incident_id,
            progress=alert_progress,
            handlers=(),
            handlers_complete=False,
            refreshed_at=datetime.now(UTC),
            warning_code=_INCIDENT_DETAILS_UNAVAILABLE,
        )

    try:
        handlers = _handlers(incident)
    except FlashDutyHandlingInvalidResponseError as exc:
        logger.warning(
            "flashduty_incident_responders_unavailable alert_id=%s incident_id=%s error=%s",
            external_alert_id,
            incident_id,
            type(exc).__name__,
        )
        return FlashDutyHandlingResult(
            linked_incident=True,
            incident_id=incident_id,
            progress=incident_progress,
            handlers=(),
            handlers_complete=False,
            refreshed_at=datetime.now(UTC),
            warning_code=_INCIDENT_DETAILS_UNAVAILABLE,
        )

    if handlers:
        try:
            member_names = await member_name_resolver.resolve(
                client,
                {handler.person_id for handler in handlers},
                deadline=deadline,
            )
        except (TimeoutError, FlashDutyError, FlashDutyHandlingInvalidResponseError) as exc:
            logger.warning(
                "flashduty_member_names_unavailable alert_id=%s incident_id=%s error=%s",
                external_alert_id,
                incident_id,
                type(exc).__name__,
            )
        else:
            handlers = tuple(
                replace(
                    handler,
                    person_name=member_names.get(handler.person_id, handler.person_name),
                )
                for handler in handlers
            )
    return FlashDutyHandlingResult(
        linked_incident=True,
        incident_id=incident_id,
        progress=incident_progress,
        handlers=handlers,
        handlers_complete=True,
        refreshed_at=datetime.now(UTC),
    )
