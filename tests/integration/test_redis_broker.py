import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from redis.asyncio import Redis

pytestmark = pytest.mark.integration


def redis_client() -> Redis:
    return Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        username=os.getenv("REDIS_USERNAME") or None,
        password=os.getenv("REDIS_PASSWORD") or None,
        decode_responses=False,
        protocol=2,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(os.getenv("RUN_REDIS_TESTS") != "1", reason="Redis integration disabled")
async def test_redis_stream_message_uses_shared_pipeline(tmp_path: Path) -> None:
    from app.application.factory import build_runtime
    from app.config import Settings
    from app.domain.models import AlertStatus
    from app.workers.redis import RedisAlertWorker

    suffix = uuid4().hex
    stream = f"{{database-alert-agent}}:test:{suffix}:jobs"
    dlq = f"{{database-alert-agent}}:test:{suffix}:dlq"
    group = f"test-{suffix}"
    consumer = f"consumer-{suffix}"
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'redis.db'}",
        redis_enabled=True,
        redis_stream_name=stream,
        redis_dlq_stream_name=dlq,
        redis_consumer_group=group,
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    client = redis_client()
    try:
        await client.ping()
        await client.xgroup_create(stream, group, id="0-0", mkstream=True)
        external_id = uuid4().hex
        envelope = {
            "source": "canonical",
            "payload": {
                "external_id": external_id,
                "severity": "WARNING",
                "title": "Redis alert",
                "reason": "integration_test",
            },
        }
        await client.xadd(stream, {"envelope": json.dumps(envelope)})
        response = await client.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=1,
            block=1000,
        )
        assert response
        _stream_name, messages = response[0]
        message_id, fields = messages[0]
        worker = RedisAlertWorker(
            settings,
            runtime.service,
            client=client,
            consumer_name=consumer,
        )
        await worker._process_message(message_id, fields)

        completed = await runtime.repository.list_by_status({AlertStatus.INCONCLUSIVE})
        assert [stored.alert.external_id for stored in completed] == [external_id]
        assert await client.xpending_range(stream, group, "-", "+", 10) == []
        assert await client.xrange(stream, "-", "+") == []
    finally:
        await client.delete(stream, dlq)
        await client.aclose()
        await runtime.repository.close()  # type: ignore[attr-defined]
