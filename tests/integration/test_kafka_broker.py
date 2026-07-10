import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
@pytest.mark.skipif(os.getenv("RUN_KAFKA_TESTS") != "1", reason="Kafka integration disabled")
async def test_kafka_broker_message_uses_shared_pipeline(tmp_path: Path) -> None:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    from app.application.factory import build_runtime
    from app.config import Settings
    from app.domain.models import AlertStatus
    from app.workers.kafka import process_envelope

    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
    topic = f"database-alert-test-{uuid4().hex}"
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'kafka.db'}",
        runbook_dir=runbooks,
    )
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    producer = AIOKafkaProducer(bootstrap_servers=bootstrap)
    consumer = AIOKafkaConsumer(
        topic, bootstrap_servers=bootstrap, auto_offset_reset="earliest", group_id=uuid4().hex
    )
    await producer.start()
    await consumer.start()
    try:
        envelope = {
            "source": "canonical",
            "payload": {
                "external_id": uuid4().hex,
                "severity": "HIGH",
                "title": "Kafka alert",
                "reason": "integration_test",
            },
        }
        await producer.send_and_wait(topic, json.dumps(envelope).encode())
        record = await consumer.getone()
        result = await process_envelope(runtime.service, json.loads(record.value))
        assert result.status == AlertStatus.COMPLETED
    finally:
        await producer.stop()
        await consumer.stop()
        await runtime.repository.close()  # type: ignore[attr-defined]
