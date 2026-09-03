from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.adapters.flashduty import (
    FlashDutyAlertSourceAdapter,
    FlashDutyAPIError,
    FlashDutyResponse,
)
from app.application.flashduty_handling import (
    FlashDutyHandlingInvalidResponseError,
    FlashDutyHandlingNotApplicableError,
    FlashDutyHandlingTimeoutError,
    FlashDutyMemberNameResolver,
    FlashDutyProgress,
    read_flashduty_handling,
)

ALERT_ID = "663a1b2c3d4e5f6789abcdef"
INCIDENT_ID = "69da451ef77b1b51f40e83ee"


def make_alert():  # type: ignore[no-untyped-def]
    return FlashDutyAlertSourceAdapter().normalize(
        {
            "data": {
                "alert_id": ALERT_ID,
                "title": "Database latency",
                "alert_severity": "Warning",
                "start_time": 1_712_650_000,
                "labels": {"env": "test", "service": "orders-db"},
            }
        }
    )


class StubHandlingClient:
    def __init__(
        self,
        *,
        alert_data: Any,
        incident_data: Any = None,
        incident_error: Exception | None = None,
        member_pages: dict[int, Any] | None = None,
        member_error: Exception | None = None,
    ) -> None:
        self.alert_data = alert_data
        self.incident_data = incident_data
        self.incident_error = incident_error
        self.member_pages = member_pages or {}
        self.member_error = member_error
        self.calls: list[tuple[str, str, bool]] = []
        self.member_calls: list[tuple[int, int, bool]] = []

    async def alert_info(
        self,
        alert_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.calls.append(("alert", alert_id, retry_until_cancelled))
        return FlashDutyResponse("req-alert", self.alert_data)

    async def incident_info(
        self,
        incident_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.calls.append(("incident", incident_id, retry_until_cancelled))
        if self.incident_error is not None:
            raise self.incident_error
        return FlashDutyResponse("req-incident", self.incident_data)

    async def list_members(
        self,
        *,
        page: int,
        limit: int = 100,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.member_calls.append((page, limit, retry_until_cancelled))
        if self.member_error is not None:
            raise self.member_error
        data = self.member_pages.get(page, {"items": [], "total": 0})
        return FlashDutyResponse(f"req-members-{page}", data)


@pytest.mark.asyncio
async def test_handling_uses_latest_incident_progress_and_acknowledged_responders() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Triggered"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Processing",
            "responders": [
                {
                    "person_id": 8,
                    "person_name": "Later",
                    "assigned_at": 1_712_650_020,
                    "acknowledged_at": 1_712_650_040,
                },
                {
                    "person_id": 3,
                    "person_name": " Earlier ",
                    "assigned_at": 1_712_650_010,
                    "acknowledged_at": 1_712_650_030,
                },
                {
                    "person_id": 5,
                    "person_name": "Assigned only",
                    "assigned_at": 1_712_650_015,
                    "acknowledged_at": 0,
                },
            ],
        },
        member_pages={
            1: {
                "total": 3,
                "items": [
                    {
                        "member_id": 3,
                        "member_name": "dylan.du",
                        "email": "must-not-leak@example.com",
                    },
                    {
                        "member_id": 8,
                        "member_name": "alice.chen",
                        "phone": "+86********1234",
                    },
                    {"member_id": 5, "member_name": "assigned.only"},
                ],
            }
        },
    )

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.progress is FlashDutyProgress.PROCESSING
    assert result.handlers_complete is True
    assert [handler.person_id for handler in result.handlers] == [3, 8]
    assert [handler.person_name for handler in result.handlers] == ["dylan.du", "alice.chen"]
    assert not hasattr(result.handlers[0], "email")
    assert result.handlers[0].acknowledged_at.isoformat() == "2024-04-09T08:07:10+00:00"
    assert client.calls == [
        ("alert", ALERT_ID, False),
        ("incident", INCIDENT_ID, False),
    ]
    assert client.member_calls == [(1, 100, False)]


@pytest.mark.asyncio
async def test_handling_reports_alert_without_linked_incident() -> None:
    client = StubHandlingClient(alert_data={"alert_id": ALERT_ID})

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.linked_incident is False
    assert result.incident_id is None
    assert result.progress is None
    assert result.handlers == ()
    assert result.handlers_complete is True
    assert client.calls == [("alert", ALERT_ID, False)]
    assert client.member_calls == []


@pytest.mark.asyncio
async def test_handling_keeps_alert_progress_when_incident_detail_fails() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Triggered"},
        },
        incident_error=FlashDutyAPIError(
            "incident unavailable",
            code="UpstreamError",
            request_id="req-incident",
        ),
    )

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.linked_incident is True
    assert result.progress is FlashDutyProgress.TRIGGERED
    assert result.handlers == ()
    assert result.handlers_complete is False
    assert result.warning_code == "INCIDENT_DETAILS_UNAVAILABLE"


@pytest.mark.asyncio
async def test_malformed_responder_marks_handler_projection_incomplete() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Triggered"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Closed",
            "responders": ["not-an-object"],
        },
    )

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.progress is FlashDutyProgress.CLOSED
    assert result.handlers_complete is False
    assert result.warning_code == "INCIDENT_DETAILS_UNAVAILABLE"


@pytest.mark.asyncio
async def test_closed_incident_keeps_acknowledged_handler() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Processing"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Closed",
            "responders": [
                {
                    "person_id": 7,
                    "person_name": None,
                    "assigned_at": 0,
                    "acknowledged_at": 1_712_650_030,
                }
            ],
        },
        member_pages={
            1: {
                "total": 1,
                "items": [
                    {
                        "member_id": 7,
                        "member_name": "dylan.du",
                        "ref_id": "sso-private-reference",
                    }
                ],
            }
        },
    )

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.progress is FlashDutyProgress.CLOSED
    assert result.handlers[0].person_id == 7
    assert result.handlers[0].person_name == "dylan.du"
    assert result.handlers[0].assigned_at is None


@pytest.mark.asyncio
async def test_member_directory_overrides_placeholder_and_caches_paginated_match() -> None:
    resolver = FlashDutyMemberNameResolver()
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Processing"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Processing",
            "responders": [
                {
                    "person_id": 7,
                    "person_name": "用户 #7",
                    "assigned_at": 1_712_650_010,
                    "acknowledged_at": 1_712_650_030,
                }
            ],
        },
        member_pages={
            1: {
                "total": 250,
                "items": [{"member_id": 99, "member_name": "someone.else"}],
            },
            2: {
                "total": 250,
                "items": [
                    {
                        "member_id": 7,
                        "member_name": " dylan.du ",
                        "email": "private@example.com",
                        "ref_id": "private-sso-id",
                    }
                ],
            },
        },
    )

    first = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=resolver,
    )
    second = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=resolver,
    )

    assert first.handlers[0].person_name == "dylan.du"
    assert second.handlers[0].person_name == "dylan.du"
    assert client.member_calls == [(1, 100, False), (2, 100, False)]


@pytest.mark.asyncio
async def test_member_directory_failure_keeps_incident_name_and_complete_handlers() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Processing"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Processing",
            "responders": [
                {
                    "person_id": 7,
                    "person_name": "Incident fallback",
                    "assigned_at": 1_712_650_010,
                    "acknowledged_at": 1_712_650_030,
                }
            ],
        },
        member_error=FlashDutyAPIError(
            "directory unavailable",
            code="UpstreamError",
            request_id="req-members",
        ),
    )

    result = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=FlashDutyMemberNameResolver(),
    )

    assert result.handlers[0].person_name == "Incident fallback"
    assert result.handlers_complete is True
    assert result.warning_code is None
    assert client.member_calls == [(1, 100, False)]


@pytest.mark.asyncio
async def test_missing_member_uses_negative_cache_and_numeric_ui_fallback() -> None:
    resolver = FlashDutyMemberNameResolver()
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Closed"},
        },
        incident_data={
            "incident_id": INCIDENT_ID,
            "progress": "Closed",
            "responders": [
                {
                    "person_id": 7,
                    "person_name": None,
                    "assigned_at": 0,
                    "acknowledged_at": 1_712_650_030,
                }
            ],
        },
        member_pages={
            1: {
                "total": 1,
                "items": [{"member_id": 99, "member_name": "someone.else"}],
            }
        },
    )

    first = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=resolver,
    )
    second = await read_flashduty_handling(
        client,
        make_alert(),
        member_name_resolver=resolver,
    )

    assert first.handlers[0].person_name is None
    assert second.handlers[0].person_name is None
    assert client.member_calls == [(1, 100, False)]


@pytest.mark.asyncio
async def test_member_name_cache_is_isolated_when_client_changes() -> None:
    resolver = FlashDutyMemberNameResolver()

    def client_for(name: str) -> StubHandlingClient:
        return StubHandlingClient(
            alert_data={
                "alert_id": ALERT_ID,
                "incident": {"incident_id": INCIDENT_ID, "progress": "Processing"},
            },
            incident_data={
                "incident_id": INCIDENT_ID,
                "progress": "Processing",
                "responders": [
                    {
                        "person_id": 7,
                        "person_name": None,
                        "assigned_at": 1_712_650_010,
                        "acknowledged_at": 1_712_650_030,
                    }
                ],
            },
            member_pages={
                1: {
                    "total": 1,
                    "items": [{"member_id": 7, "member_name": name}],
                }
            },
        )

    first_client = client_for("tenant-one.user")
    second_client = client_for("tenant-two.user")

    first = await read_flashduty_handling(
        first_client,
        make_alert(),
        member_name_resolver=resolver,
    )
    second = await read_flashduty_handling(
        second_client,
        make_alert(),
        member_name_resolver=resolver,
    )

    assert first.handlers[0].person_name == "tenant-one.user"
    assert second.handlers[0].person_name == "tenant-two.user"
    assert first_client.member_calls == [(1, 100, False)]
    assert second_client.member_calls == [(1, 100, False)]


@pytest.mark.asyncio
async def test_invalid_alert_progress_is_not_invented() -> None:
    client = StubHandlingClient(
        alert_data={
            "alert_id": ALERT_ID,
            "incident": {"incident_id": INCIDENT_ID, "progress": "Resolved"},
        }
    )

    with pytest.raises(FlashDutyHandlingInvalidResponseError, match="incident progress"):
        await read_flashduty_handling(
            client,
            make_alert(),
            member_name_resolver=FlashDutyMemberNameResolver(),
        )


@pytest.mark.asyncio
async def test_non_flashduty_alert_is_not_applicable() -> None:
    alert = make_alert().model_copy(update={"source": "canonical"})
    client = StubHandlingClient(alert_data={})

    with pytest.raises(FlashDutyHandlingNotApplicableError):
        await read_flashduty_handling(
            client,
            alert,
            member_name_resolver=FlashDutyMemberNameResolver(),
        )

    assert client.calls == []


@pytest.mark.asyncio
async def test_alert_lookup_obeys_interactive_timeout() -> None:
    class SlowClient(StubHandlingClient):
        async def alert_info(
            self,
            alert_id: str,
            *,
            retry_until_cancelled: bool = True,
        ) -> FlashDutyResponse:
            await asyncio.sleep(1)
            return await super().alert_info(
                alert_id,
                retry_until_cancelled=retry_until_cancelled,
            )

    client = SlowClient(alert_data={"alert_id": ALERT_ID})

    with pytest.raises(FlashDutyHandlingTimeoutError):
        await read_flashduty_handling(
            client,
            make_alert(),
            member_name_resolver=FlashDutyMemberNameResolver(),
            timeout_seconds=0.001,
        )
