from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.adapters.flashduty import FlashDutyAPIError, FlashDutyResponse
from app.application.wecom_mention import (
    WeComMentionInvalidResponseError,
    resolve_wecom_mention_targets,
)
from app.domain.models import (
    DatabaseTarget,
    NormalizedAlert,
    Severity,
    WeComMentionEngineOwner,
    WeComMentionFlashDutyMember,
    WeComMentionMode,
    WeComMentionTarget,
)

_OBJECT_ID = "5f8d0d55b54764421b7156c9"


def make_alert(
    *,
    source: str = "flashduty",
    external_id: str = _OBJECT_ID,
    engine: str | None = "postgresql",
) -> NormalizedAlert:
    return NormalizedAlert(
        external_id=external_id,
        source=source,
        raw_severity="CRITICAL",
        severity=Severity.CRITICAL,
        environment="production",
        service_name="orders-api",
        title="连接数接近上限",
        reason="connection_exhausted",
        occurred_at=datetime(2026, 9, 3, 20, 15, 30, tzinfo=UTC),
        database=DatabaseTarget(engine=engine, instance="orders-primary") if engine else None,
    )


def make_target(
    label: str, *, userid: str | None = "u1", mobile: str | None = None
) -> WeComMentionTarget:
    return WeComMentionTarget(display_label=label, wecom_userid=userid, wecom_mobile=mobile)


class FakeRepository:
    def __init__(
        self,
        *,
        engine_owners: dict[str, WeComMentionEngineOwner] | None = None,
        flashduty_members: dict[str, WeComMentionFlashDutyMember] | None = None,
    ) -> None:
        self._engine_owners = engine_owners or {}
        self._flashduty_members = flashduty_members or {}
        self.requested_member_names: set[str] | None = None

    async def get_wecom_mention_engine_owner(self, engine: str) -> WeComMentionEngineOwner | None:
        return self._engine_owners.get(engine)

    async def get_wecom_mention_flashduty_members(
        self, member_names: set[str]
    ) -> dict[str, WeComMentionFlashDutyMember]:
        self.requested_member_names = member_names
        return {
            member_name: member
            for member_name, member in self._flashduty_members.items()
            if member_name in member_names
        }


class FakeFlashDutyClient:
    def __init__(
        self,
        *,
        alert_data: object,
        incident_data: object | None = None,
        member_names: dict[int, str] | None = None,
        member_error: Exception | None = None,
    ) -> None:
        self._alert_data = alert_data
        self._incident_data = incident_data
        self._member_names = member_names or {}
        self._member_error = member_error
        self.alert_info_calls: list[str] = []
        self.incident_info_calls: list[str] = []
        self.member_calls: list[int] = []

    async def alert_info(
        self, alert_id: str, *, retry_until_cancelled: bool = True
    ) -> FlashDutyResponse:
        self.alert_info_calls.append(alert_id)
        return FlashDutyResponse(request_id="req-alert", data=self._alert_data)

    async def incident_info(
        self, incident_id: str, *, retry_until_cancelled: bool = True
    ) -> FlashDutyResponse:
        self.incident_info_calls.append(incident_id)
        return FlashDutyResponse(request_id="req-incident", data=self._incident_data)

    async def list_members(
        self,
        *,
        page: int,
        limit: int = 100,
        retry_until_cancelled: bool = False,
    ) -> FlashDutyResponse:
        self.member_calls.append(page)
        if self._member_error is not None:
            raise self._member_error
        items = [
            {"member_id": person_id, "member_name": name}
            for person_id, name in self._member_names.items()
        ]
        return FlashDutyResponse(
            request_id=f"req-members-{page}",
            data={"items": items, "total": len(items)},
        )


@pytest.mark.asyncio
async def test_database_owner_mode_matches_engine() -> None:
    target = make_target("MySQL 值班组")
    repository = FakeRepository(
        engine_owners={
            "postgresql": WeComMentionEngineOwner(engine="postgresql", target=target),
        },
    )
    alert = make_alert(engine="postgresql")

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.DATABASE_OWNER,
        repository=repository,
        flashduty_client=None,
    )

    assert resolved == (target,)


@pytest.mark.asyncio
async def test_database_owner_mode_returns_empty_when_unmapped() -> None:
    repository = FakeRepository(engine_owners={})
    alert = make_alert(engine="mongodb")

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.DATABASE_OWNER,
        repository=repository,
        flashduty_client=None,
    )

    assert resolved == ()


@pytest.mark.asyncio
async def test_database_owner_mode_returns_empty_when_no_engine() -> None:
    repository = FakeRepository(
        engine_owners={
            "postgresql": WeComMentionEngineOwner(engine="postgresql", target=make_target("x")),
        },
    )
    alert = make_alert(engine=None)

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.DATABASE_OWNER,
        repository=repository,
        flashduty_client=None,
    )

    assert resolved == ()


@pytest.mark.asyncio
async def test_on_call_person_mode_prefers_assigned_to_over_responders() -> None:
    target = make_target("张三")
    repository = FakeRepository(
        flashduty_members={
            "zhangsan": WeComMentionFlashDutyMember(flashduty_member_name="zhangsan", target=target),
        },
    )
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={
            "assigned_to": {"person_ids": [101]},
            "responders": [{"person_id": 202, "acknowledged_at": 1700000000}],
        },
        member_names={101: "zhangsan", 202: "lisi"},
    )
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == (target,)
    assert repository.requested_member_names == {"zhangsan"}


@pytest.mark.asyncio
async def test_on_call_person_mode_falls_back_to_latest_responder() -> None:
    target = make_target("李四")
    repository = FakeRepository(
        flashduty_members={
            "lisi": WeComMentionFlashDutyMember(flashduty_member_name="lisi", target=target),
        },
    )
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={
            "responders": [
                {"person_id": 101, "acknowledged_at": 1700000000},
                {"person_id": 202, "acknowledged_at": 1700000500},
            ],
        },
        member_names={101: "zhangsan", 202: "lisi"},
    )
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == (target,)


@pytest.mark.asyncio
async def test_on_call_person_mode_falls_back_to_unacknowledged_assignee() -> None:
    """Dispatch-only responders (no assigned_to, not yet acknowledged) still resolve.

    Regression for the reported bug: the alert detail page shows "参与处理人
    xxx 未认领 分派于 xxx" purely from responders[].assigned_at, but the old
    fallback only scanned acknowledged_at and silently produced no mention.
    """
    target = make_target("王五")
    repository = FakeRepository(
        flashduty_members={
            "wangwu": WeComMentionFlashDutyMember(flashduty_member_name="wangwu", target=target),
        },
    )
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={
            "responders": [
                {"person_id": 303, "assigned_at": 1700000000},
            ],
        },
        member_names={303: "wangwu"},
    )
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == (target,)


@pytest.mark.asyncio
async def test_on_call_person_mode_prefers_newer_unacknowledged_over_older_acknowledged() -> None:
    """A more recent re-dispatch outranks an older acknowledgement."""
    target = make_target("赵六")
    repository = FakeRepository(
        flashduty_members={
            "zhaoliu": WeComMentionFlashDutyMember(flashduty_member_name="zhaoliu", target=target),
        },
    )
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={
            "responders": [
                {"person_id": 101, "acknowledged_at": 1700000000},
                {"person_id": 404, "assigned_at": 1700000500},
            ],
        },
        member_names={101: "zhangsan", 404: "zhaoliu"},
    )
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == (target,)

@pytest.mark.asyncio
async def test_on_call_person_mode_skips_unmapped_person() -> None:
    repository = FakeRepository(flashduty_members={})
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={"assigned_to": {"person_ids": [999]}},
        member_names={999: "unmapped-user"},
    )
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == ()


@pytest.mark.asyncio
async def test_on_call_person_mode_returns_empty_for_non_flashduty_source() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(alert_data={})
    alert = make_alert(source="canonical")

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == ()
    assert client.alert_info_calls == []


@pytest.mark.asyncio
async def test_on_call_person_mode_returns_empty_without_flashduty_client() -> None:
    repository = FakeRepository()
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=None,
    )

    assert resolved == ()


@pytest.mark.asyncio
async def test_on_call_person_mode_returns_empty_for_non_object_id_external_id() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(alert_data={})
    alert = make_alert(external_id="not-an-object-id")

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == ()
    assert client.alert_info_calls == []


@pytest.mark.asyncio
async def test_on_call_person_mode_returns_empty_when_no_linked_incident() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(alert_data={"incident": {}})
    alert = make_alert()

    resolved = await resolve_wecom_mention_targets(
        alert,
        mode=WeComMentionMode.ON_CALL_PERSON,
        repository=repository,
        flashduty_client=client,
    )

    assert resolved == ()
    assert client.incident_info_calls == []


@pytest.mark.asyncio
async def test_on_call_person_mode_raises_on_malformed_person_ids() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={"assigned_to": {"person_ids": ["not-an-int"]}},
    )
    alert = make_alert()

    with pytest.raises(WeComMentionInvalidResponseError):
        await resolve_wecom_mention_targets(
            alert,
            mode=WeComMentionMode.ON_CALL_PERSON,
            repository=repository,
            flashduty_client=client,
        )


@pytest.mark.asyncio
async def test_on_call_person_mode_raises_on_malformed_incident_id() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(alert_data={"incident": {"incident_id": "too-short"}})
    alert = make_alert()

    with pytest.raises(WeComMentionInvalidResponseError):
        await resolve_wecom_mention_targets(
            alert,
            mode=WeComMentionMode.ON_CALL_PERSON,
            repository=repository,
            flashduty_client=client,
        )


@pytest.mark.asyncio
async def test_on_call_person_mode_propagates_member_directory_failure() -> None:
    repository = FakeRepository()
    client = FakeFlashDutyClient(
        alert_data={"incident": {"incident_id": _OBJECT_ID}},
        incident_data={"assigned_to": {"person_ids": [101]}},
        member_error=FlashDutyAPIError("member list unavailable"),
    )
    alert = make_alert()

    with pytest.raises(FlashDutyAPIError):
        await resolve_wecom_mention_targets(
            alert,
            mode=WeComMentionMode.ON_CALL_PERSON,
            repository=repository,
            flashduty_client=client,
        )


def test_wecom_mention_target_requires_userid_or_mobile() -> None:
    with pytest.raises(ValueError, match="userid or a mobile"):
        WeComMentionTarget(display_label="无身份", wecom_userid=None, wecom_mobile=None)


@pytest.mark.asyncio
async def test_resolve_wecom_mention_targets_rejects_non_positive_timeout() -> None:
    repository = FakeRepository()
    alert = make_alert()

    with pytest.raises(ValueError, match="timeout_seconds must be positive"):
        await resolve_wecom_mention_targets(
            alert,
            mode=WeComMentionMode.DATABASE_OWNER,
            repository=repository,
            flashduty_client=None,
            timeout_seconds=0,
        )
