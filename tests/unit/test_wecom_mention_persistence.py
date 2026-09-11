from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters.persistence import SQLAlchemyAlertRepository
from app.domain.models import WeComMentionTarget


def sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


@pytest.mark.asyncio
async def test_engine_owner_upsert_get_list_and_delete_round_trip(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "engine-owners.db"))
    await repository.initialize()
    try:
        target = WeComMentionTarget(
            display_label="MySQL 值班组", wecom_userid="mysql_owner", wecom_mobile=None
        )
        created = await repository.upsert_wecom_mention_engine_owner(
            "mysql", target, updated_by="admin-a"
        )
        assert created.engine == "mysql"
        assert created.target == target
        assert created.updated_by == "admin-a"

        fetched = await repository.get_wecom_mention_engine_owner("mysql")
        assert fetched is not None
        assert fetched.target == target

        assert await repository.get_wecom_mention_engine_owner("postgresql") is None

        updated_target = WeComMentionTarget(
            display_label="MySQL 新值班组", wecom_userid=None, wecom_mobile="13800000000"
        )
        updated = await repository.upsert_wecom_mention_engine_owner(
            "mysql", updated_target, updated_by="admin-b"
        )
        assert updated.target == updated_target
        assert updated.updated_by == "admin-b"

        await repository.upsert_wecom_mention_engine_owner(
            "postgresql",
            WeComMentionTarget(
                display_label="PG 值班组", wecom_userid="pg_owner", wecom_mobile=None
            ),
            updated_by="admin-a",
        )
        listed = await repository.list_wecom_mention_engine_owners()
        assert [owner.engine for owner in listed] == ["mysql", "postgresql"]

        deleted = await repository.delete_wecom_mention_engine_owner("mysql")
        assert deleted is True
        assert await repository.get_wecom_mention_engine_owner("mysql") is None

        deleted_again = await repository.delete_wecom_mention_engine_owner("mysql")
        assert deleted_again is False
    finally:
        await repository.close()


@pytest.mark.asyncio
async def test_flashduty_member_upsert_batch_get_list_and_delete_round_trip(
    tmp_path: Path,
) -> None:
    repository = SQLAlchemyAlertRepository(sqlite_url(tmp_path / "flashduty-members.db"))
    await repository.initialize()
    try:
        target_a = WeComMentionTarget(
            display_label="张三", wecom_userid="zhangsan", wecom_mobile=None
        )
        target_b = WeComMentionTarget(
            display_label="李四", wecom_userid=None, wecom_mobile="13900000000"
        )

        created_a = await repository.upsert_wecom_mention_flashduty_member(
            101, "Zhang San", target_a, updated_by="admin-a"
        )
        assert created_a.flashduty_person_id == 101
        assert created_a.flashduty_member_name == "Zhang San"
        assert created_a.target == target_a

        await repository.upsert_wecom_mention_flashduty_member(
            202, "Li Si", target_b, updated_by="admin-a"
        )

        batch = await repository.get_wecom_mention_flashduty_members({101, 202, 303})
        assert set(batch.keys()) == {101, 202}
        assert batch[101].target == target_a
        assert batch[202].target == target_b

        empty_batch = await repository.get_wecom_mention_flashduty_members(set())
        assert empty_batch == {}

        updated_target = WeComMentionTarget(
            display_label="张三（新）", wecom_userid="zhangsan2", wecom_mobile=None
        )
        updated = await repository.upsert_wecom_mention_flashduty_member(
            101, "Zhang San", updated_target, updated_by="admin-b"
        )
        assert updated.target == updated_target
        assert updated.updated_by == "admin-b"

        listed = await repository.list_wecom_mention_flashduty_members()
        assert [member.flashduty_person_id for member in listed] == [101, 202]

        deleted = await repository.delete_wecom_mention_flashduty_member(101)
        assert deleted is True
        remaining = await repository.get_wecom_mention_flashduty_members({101})
        assert remaining == {}

        deleted_again = await repository.delete_wecom_mention_flashduty_member(101)
        assert deleted_again is False
    finally:
        await repository.close()
