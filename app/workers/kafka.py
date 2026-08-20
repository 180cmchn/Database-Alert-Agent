from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.application.admin import RuntimeSettingsManager
from app.application.factory import Runtime, apply_runtime_settings, build_runtime
from app.application.sanitization import sanitize
from app.application.service import AlertAnalysisService
from app.config import Settings, get_deployment_settings
from app.domain.errors import (
    InvalidAlertPayloadError,
    InvestigationLeaseUnavailableError,
    UnknownAlertSourceError,
)
from app.domain.models import AlertStatus, StoredAlert
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
        runtime_settings_manager: RuntimeSettingsManager | None = None,
    ) -> None:
        self.runtime = runtime
        self.runtime_settings = (
            runtime_settings_manager
            or RuntimeSettingsManager(
                (runtime.deployment_settings or settings).runtime_settings_path,
                deployment_baseline=runtime.deployment_settings or settings,
            )
            if runtime
            else None
        )
        if runtime is not None and self.runtime_settings is not None:
            effective_settings = self.runtime_settings.effective_settings()
            if (
                runtime.settings.model_dump(mode="python")
                != effective_settings.model_dump(mode="python")
            ):
                apply_runtime_settings(runtime, effective_settings)
            settings = effective_settings
            service = runtime.service
        self.settings = settings
        self.service = service
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
            "Kafka worker started topic=%s group=%s concurrency=%s",
            self.settings.kafka_alert_topic,
            self.settings.kafka_consumer_group,
            self.settings.scheduler_workers,
        )
        try:
            while True:
                await self._refresh_runtime_settings()
                batches = await self.consumer.getmany(
                    timeout_ms=1000,
                    max_records=self.settings.scheduler_workers,
                )
                records = [record for batch in batches.values() for record in batch]
                if not records:
                    continue

                outcomes = await asyncio.gather(
                    *(self._process_record(record) for record in records),
                    return_exceptions=True,
                )
                failures = [
                    outcome for outcome in outcomes if isinstance(outcome, BaseException)
                ]
                if failures:
                    for failure in failures:
                        if isinstance(failure, InvestigationLeaseUnavailableError):
                            logger.info("Deferring leased investigation: %s", failure)
                        else:
                            logger.error(
                                "Kafka record batch failed error_type=%s",
                                type(failure).__name__,
                            )
                    # Do not commit a partially successful batch. Rewind every
                    # involved partition; terminal duplicates are idempotent and
                    # this preserves at-least-once processing for the failed item.
                    for partition, batch in batches.items():
                        if batch:
                            self.consumer.seek(partition, batch[0].offset)
                    await asyncio.sleep(1)
                    continue
                await self.consumer.commit()
        finally:
            await self.consumer.stop()
            await self.producer.stop()

    async def _process_record(self, record: Any) -> None:
        try:
            envelope = parse_envelope(record.value)
            await process_with_retries(
                self.service,
                envelope,
                max_retries=self.settings.kafka_max_retries,
                dlq_sender=self._send_dlq,
            )
        except InvestigationLeaseUnavailableError:
            raise
        except InvalidAlertPayloadError as exc:
            raw_value = (
                record.value.decode(errors="replace")
                if isinstance(record.value, bytes)
                else record.value
            )
            await self._send_dlq(
                {
                    "original": sanitize(raw_value),
                    "error": str(exc),
                }
            )

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
    deployment_settings = get_deployment_settings()
    runtime_settings = RuntimeSettingsManager(
        deployment_settings.runtime_settings_path,
        deployment_baseline=deployment_settings,
    )
    settings = runtime_settings.effective_settings()
    configure_logging(settings.log_level)
    if not settings.kafka_enabled:
        raise RuntimeError("KAFKA_ENABLED must be true to start the Kafka worker")
    runtime = build_runtime(settings, deployment_settings=deployment_settings)
    await runtime.repository.initialize()
    worker = KafkaAlertWorker(
        settings,
        runtime.service,
        runtime=runtime,
        runtime_settings_manager=runtime_settings,
    )
    try:
        await worker.run()
    finally:
        await runtime.service.close()
        close = getattr(runtime.repository, "close", None)
        if close:
            await close()


if __name__ == "__main__":
    asyncio.run(main())
