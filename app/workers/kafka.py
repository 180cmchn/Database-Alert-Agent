from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import TopicPartition

from app.application.admin import RuntimeSettingsManager
from app.application.factory import Runtime, apply_runtime_settings, build_runtime
from app.application.sanitization import sanitize
from app.application.service import AlertAnalysisService
from app.config import Settings, get_settings
from app.domain.errors import (
    InvalidAlertPayloadError,
    InvestigationLeaseUnavailableError,
    UnknownAlertSourceError,
)
from app.domain.models import AlertSignalState, AlertStatus, StoredAlert
from app.logging_config import configure_logging

logger = logging.getLogger(__name__)

DlqSender = Callable[[dict[str, Any]], Awaitable[None]]


def parse_envelope(value: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise InvalidAlertPayloadError(f"Kafka message is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InvalidAlertPayloadError("Kafka message must be an object")
    if value.get("job_type") == "investigate":
        alert_id = value.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise InvalidAlertPayloadError("Investigation job requires alert_id")
        return {
            "schema_version": value.get("schema_version", 1),
            "job_type": "investigate",
            "alert_id": alert_id,
        }
    source = value.get("source")
    payload = value.get("payload")
    if not isinstance(source, str) or not source.strip():
        raise InvalidAlertPayloadError("Kafka envelope requires a non-empty source")
    if not isinstance(payload, dict):
        raise InvalidAlertPayloadError("Kafka envelope requires an object payload")
    return {"source": source, "payload": payload}


async def process_envelope(
    service: AlertAnalysisService, envelope: dict[str, Any]
) -> StoredAlert:
    parsed = parse_envelope(envelope)
    if parsed.get("job_type") == "investigate":
        result = await service.analyze_by_id(parsed["alert_id"])
    else:
        result = await service.analyze(
            parsed["source"], parsed["payload"], retry_failed=True
        )
    if (
        getattr(result.alert, "signal_state", AlertSignalState.FIRING)
        == AlertSignalState.RESOLVED
    ):
        return result
    if result.status == AlertStatus.FAILED:
        raise RuntimeError(result.error or "Previously failed alert analysis")
    if result.status in {AlertStatus.QUEUED, AlertStatus.ANALYZING}:
        raise InvestigationLeaseUnavailableError(str(result.alert.id))
    return result


async def process_with_retries(
    service: AlertAnalysisService,
    envelope: dict[str, Any],
    *,
    max_retries: int,
    dlq_sender: DlqSender,
) -> StoredAlert | None:
    error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return await process_envelope(service, envelope)
        except InvestigationLeaseUnavailableError:
            # A live worker still owns this alert. Do not exhaust the ordinary
            # retry budget, send the job to the DLQ, or allow its offset to be
            # committed; the caller must defer the same Kafka record.
            raise
        except (InvalidAlertPayloadError, UnknownAlertSourceError) as exc:
            error = exc
            break
        except Exception as exc:
            error = exc
            if attempt < max_retries:
                await asyncio.sleep(min(2 ** (attempt - 1), 10))

    await dlq_sender(
        {
            "original": sanitize(envelope),
            "error": f"{type(error).__name__}: {error}" if error else "Unknown error",
            "attempts": max_retries,
        }
    )
    return None


class KafkaAlertWorker:
    def __init__(
        self,
        settings: Settings,
        service: AlertAnalysisService,
        *,
        runtime: Runtime | None = None,
    ) -> None:
        self.settings = settings
        self.service = service
        self.runtime = runtime
        self.runtime_settings = (
            RuntimeSettingsManager(settings.runtime_settings_path) if runtime else None
        )
        self.consumer = AIOKafkaConsumer(
            settings.kafka_alert_topic,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode(),
        )

    async def run(self) -> None:
        await self.consumer.start()
        await self.producer.start()
        logger.info(
            "Kafka worker started topic=%s group=%s",
            self.settings.kafka_alert_topic,
            self.settings.kafka_consumer_group,
        )
        try:
            async for record in self.consumer:
                try:
                    await self._refresh_runtime_settings()
                    envelope = parse_envelope(record.value)
                    await process_with_retries(
                        self.service,
                        envelope,
                        max_retries=self.settings.kafka_max_retries,
                        dlq_sender=self._send_dlq,
                    )
                except InvestigationLeaseUnavailableError as exc:
                    logger.info("Deferring leased investigation: %s", exc)
                    self.consumer.seek(
                        TopicPartition(record.topic, record.partition), record.offset
                    )
                    await asyncio.sleep(1)
                    continue
                except InvalidAlertPayloadError as exc:
                    await self._send_dlq(
                        {
                            "original": sanitize(record.value.decode(errors="replace")),
                            "error": str(exc),
                        }
                    )
                await self.consumer.commit()
        finally:
            await self.consumer.stop()
            await self.producer.stop()

    async def _send_dlq(self, payload: dict[str, Any]) -> None:
        await self.producer.send_and_wait(self.settings.kafka_dlq_topic, payload)

    async def _refresh_runtime_settings(self) -> None:
        if not self.runtime or not self.runtime_settings:
            return
        updated, changed, revision = await self.runtime_settings.reload_if_changed(
            self.runtime.settings
        )
        if changed:
            apply_runtime_settings(self.runtime, updated)
            self.settings = updated
            logger.info("Applied runtime settings revision=%s", revision)


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    if not settings.kafka_enabled:
        raise RuntimeError("KAFKA_ENABLED must be true to start the Kafka worker")
    runtime = build_runtime(settings)
    await runtime.repository.initialize()
    worker = KafkaAlertWorker(settings, runtime.service, runtime=runtime)
    try:
        if runtime.escalation_scheduler is not None:
            await runtime.escalation_scheduler.start()
        await worker.run()
    finally:
        if runtime.escalation_scheduler is not None:
            await runtime.escalation_scheduler.stop()
        close = getattr(runtime.repository, "close", None)
        if close:
            await close()


if __name__ == "__main__":
    asyncio.run(main())
