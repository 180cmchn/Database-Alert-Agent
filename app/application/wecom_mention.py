"""Resolve WeCom @ mention targets for the "请查收@xxx" follow-up message.

This module is the only place that decides *who* gets pinged after a WeCom
notification card is delivered. It stays independent from
``app.adapters.notification`` (pure HTTP transport, no DB/FlashDuty access)
and from ``app.application.service`` (owns the outbox delivery loop).

Two admin-selected modes are supported:

* ``DATABASE_OWNER``: match the alert's normalized database engine against an
  admin-maintained engine -> WeCom identity table.
* ``ON_CALL_PERSON``: read the FlashDuty incident linked to the alert, take
  the currently assigned/acknowledged person(s), and map their FlashDuty
  ``person_id`` through an admin-maintained FlashDuty member -> WeCom identity
  table (FlashDuty exposes no WeCom userid itself).

Resolution is best-effort by design: every "this mode does not apply" state
(no engine, non-FlashDuty alert, no linked incident, no admin mapping) simply
returns an empty tuple. Only genuine transport/response failures raise
``WeComMentionError`` so the caller can log a distinct "resolution failed"
outcome without ever affecting the already-delivered notification card.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Protocol

from app.domain.models import NormalizedAlert, WeComMentionMode, WeComMentionTarget
from app.domain.ports import AlertRepository

logger = logging.getLogger(__name__)

WECOM_MENTION_RESOLUTION_TIMEOUT_SECONDS = 10.0
_OBJECT_ID_LENGTH = 24


class WeComMentionError(RuntimeError):
    """Base error for @ mention target resolution."""


class WeComMentionInvalidResponseError(WeComMentionError):
    """FlashDuty returned data that cannot be trusted to resolve a mention target."""


class WeComMentionFlashDutyResponse(Protocol):
    data: Any


class WeComMentionFlashDutyClient(Protocol):
    """The subset of FlashDutyClient this resolver depends on."""

    async def alert_info(
        self,
        alert_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> WeComMentionFlashDutyResponse: ...

    async def incident_info(
        self,
        incident_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> WeComMentionFlashDutyResponse: ...


def _is_object_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _OBJECT_ID_LENGTH
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WeComMentionInvalidResponseError(f"FlashDuty {label} must be an object")
    return value


def _linked_incident_id(alert_data: Mapping[str, Any]) -> str | None:
    incident_value = alert_data.get("incident")
    if incident_value is None or incident_value == {}:
        return None
    incident = _mapping(incident_value, "alert incident")
    incident_id = incident.get("incident_id")
    if not _is_object_id(incident_id):
        raise WeComMentionInvalidResponseError(
            "FlashDuty incident.incident_id must be a 24-character ObjectID"
        )
    return incident_id


def _assigned_person_ids(incident: Mapping[str, Any]) -> list[int]:
    assigned_to = incident.get("assigned_to")
    if not isinstance(assigned_to, Mapping):
        return []
    person_ids = assigned_to.get("person_ids")
    if person_ids is None:
        return []
    if not isinstance(person_ids, list):
        raise WeComMentionInvalidResponseError(
            "FlashDuty incident.assigned_to.person_ids must be a list"
        )
    resolved: list[int] = []
    for value in person_ids:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise WeComMentionInvalidResponseError(
                "FlashDuty incident.assigned_to.person_ids must contain positive integers"
            )
        resolved.append(value)
    return resolved


def _latest_responder_person_id(incident: Mapping[str, Any]) -> int | None:
    """Fall back to the most recently acknowledged responder when unassigned."""

    responders_value = incident.get("responders")
    if responders_value is None:
        return None
    if not isinstance(responders_value, list):
        raise WeComMentionInvalidResponseError("FlashDuty incident.responders must be a list")

    latest: tuple[int, int] | None = None  # (acknowledged_at, person_id)
    for item in responders_value:
        if not isinstance(item, Mapping):
            continue
        person_id = item.get("person_id")
        acknowledged_at = item.get("acknowledged_at")
        if isinstance(person_id, bool) or not isinstance(person_id, int) or person_id <= 0:
            continue
        if (
            isinstance(acknowledged_at, bool)
            or not isinstance(acknowledged_at, int)
            or acknowledged_at <= 0
        ):
            continue
        if latest is None or acknowledged_at > latest[0]:
            latest = (acknowledged_at, person_id)
    return latest[1] if latest is not None else None


async def _resolve_on_call_person(
    alert: NormalizedAlert,
    *,
    repository: AlertRepository,
    flashduty_client: WeComMentionFlashDutyClient | None,
    timeout_seconds: float,
) -> tuple[WeComMentionTarget, ...]:
    if alert.source.casefold() != "flashduty":
        return ()
    if flashduty_client is None:
        return ()
    if not _is_object_id(alert.external_id):
        return ()

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds

    async with asyncio.timeout(timeout_seconds):
        alert_response = await flashduty_client.alert_info(
            alert.external_id,
            retry_until_cancelled=False,
        )
    alert_data = _mapping(alert_response.data, "alert detail")
    incident_id = _linked_incident_id(alert_data)
    if incident_id is None:
        return ()

    remaining = deadline - loop.time()
    if remaining <= 0:
        return ()
    async with asyncio.timeout(remaining):
        incident_response = await flashduty_client.incident_info(
            incident_id,
            retry_until_cancelled=False,
        )
    incident = _mapping(incident_response.data, "incident detail")

    person_ids = _assigned_person_ids(incident)
    if not person_ids:
        fallback_person_id = _latest_responder_person_id(incident)
        person_ids = [fallback_person_id] if fallback_person_id is not None else []
    if not person_ids:
        return ()

    members = await repository.get_wecom_mention_flashduty_members(set(person_ids))
    targets: list[WeComMentionTarget] = []
    for person_id in person_ids:
        member = members.get(person_id)
        if member is None:
            logger.info(
                "wecom_mention_flashduty_member_unmapped alert_id=%s incident_id=%s person_id=%s",
                alert.id,
                incident_id,
                person_id,
            )
            continue
        targets.append(member.target)
    return tuple(targets)


async def resolve_wecom_mention_targets(
    alert: NormalizedAlert,
    *,
    mode: WeComMentionMode,
    repository: AlertRepository,
    flashduty_client: WeComMentionFlashDutyClient | None,
    timeout_seconds: float = WECOM_MENTION_RESOLUTION_TIMEOUT_SECONDS,
) -> tuple[WeComMentionTarget, ...]:
    """Best-effort resolve the @ mention targets for one notification event.

    Returns an empty tuple whenever the selected mode legitimately does not
    apply to this alert. Raises ``WeComMentionError`` (or lets a FlashDuty
    transport error / ``TimeoutError`` propagate) only for genuine failures,
    so the caller can log "resolution failed" distinctly from "nothing to
    mention" without ever affecting the already-delivered notification card.
    """

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if mode == WeComMentionMode.DATABASE_OWNER:
        engine = alert.database.engine if alert.database else None
        if not engine or not engine.strip():
            return ()
        owner = await repository.get_wecom_mention_engine_owner(engine.strip().lower())
        if owner is None:
            return ()
        return (owner.target,)

    return await _resolve_on_call_person(
        alert,
        repository=repository,
        flashduty_client=flashduty_client,
        timeout_seconds=timeout_seconds,
    )
