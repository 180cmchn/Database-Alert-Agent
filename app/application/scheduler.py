from __future__ import annotations

import asyncio
import json
import logging
import time

from aiokafka import AIOKafkaProducer

from app.adapters.flashduty import FlashDutyClient
from app.application.service import AlertAnalysisService
from app.config import Settings
from app.domain.models import AlertStatus

logger = logging.getLogger(__name__)


class FlashDutyAlertPoller:
    """Poll scoped FlashDuty collaboration spaces through the read-only API."""

    def __init__(
        self,
        settings: Settings,
        service: AlertAnalysisService,
        scheduler: InMemoryAnalysisScheduler | KafkaAnalysisScheduler | ManualAnalysisScheduler,
        client: FlashDutyClient | None,
    ) -> None:
        self.settings = settings
        self.service = service
        self.scheduler = scheduler
        self.client = client
        self._task: asyncio.Task[None] | None = None
        self._watermark: int | None = None

    @property
    def enabled(self) -> bool:
        return bool(
            self.settings.flashduty_enabled
            and self.settings.flashduty_polling_enabled
            and bool(self.settings.flashduty_poll_channel_ids)
            and self.client is not None
        )

    async def start(self) -> None:
        if not self.enabled or self._task is not None:
            return
        self._task = asyncio.create_task(
            self._loop(), name="flashduty-alert-poller"
        )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    async def run_once(self, *, now: int | None = None) -> int:
        if not self.enabled or self.client is None:
            return 0
        end_time = int(time.time()) if now is None else now
        overlap = self.settings.flashduty_poll_lookback_seconds
        start_time = (
            end_time - overlap
            if self._watermark is None
            else max(0, self._watermark - overlap)
        )
        cursor: str | None = None
        seen_cursors: set[str] = set()
        created_count = 0

        for _page in range(100):
            response = await self.client.list_alerts(
                start_time=start_time,
                end_time=end_time,
                limit=100,
                search_after_ctx=cursor,
                channel_ids=self.settings.flashduty_poll_channel_ids,
                integration_ids=self.settings.flashduty_poll_integration_ids,
                is_active=True,
                by_updated_at=True,
            )
            data = response.data if isinstance(response.data, dict) else {}
            items = data.get("items")
            if not isinstance(items, list):
                raise RuntimeError("FlashDuty /alert/list response did not contain items")

            for item in items:
                if not isinstance(item, dict):
                    continue
                alert_id = item.get("alert_id")
                if not isinstance(alert_id, str):
                    continue
                try:
                    try:
                        detail = await self.client.alert_info(alert_id)
                        ingest_payload = {
                            "request_id": detail.request_id,
                            "data": detail.data,
                        }
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        # AlertItem is documented as a complete alert object. Use it
                        # when the per-item detail request is transiently unavailable
                        # so polling still fulfills its loss-recovery purpose.
                        logger.warning(
                            "flashduty_poll_alert_info_failed_using_list_item "
                            "external_alert_id=%s error_type=%s",
                            alert_id,
                            type(exc).__name__,
                        )
                        ingest_payload = {
                            "request_id": response.request_id,
                            "data": item,
                        }
                    stored, created = await self.service.ingest(
                        "flashduty", ingest_payload
                    )
                    if created or stored.status in {
                        AlertStatus.QUEUED,
                        AlertStatus.FAILED,
                    }:
                        await self.scheduler.enqueue(str(stored.alert.id))
                    created_count += int(created)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "flashduty_poll_alert_ingest_failed external_alert_id=%s",
                        alert_id,
                    )

            next_cursor = data.get("search_after_ctx")
            has_next = data.get("has_next_page") is True
            if not has_next or not isinstance(next_cursor, str) or not next_cursor:
                break
            if next_cursor in seen_cursors:
                raise RuntimeError("FlashDuty /alert/list returned a repeated cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise RuntimeError("FlashDuty /alert/list exceeded the 100-page safety limit")

        self._watermark = end_time
        logger.info(
            "flashduty_poll_completed start_time=%s end_time=%s created=%s",
            start_time,
            end_time,
            created_count,
        )
        return created_count

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Keep the prior watermark so the next successful pass retries the
                # complete overlap window rather than silently advancing past loss.
                logger.exception("flashduty_poll_failed")
            await asyncio.sleep(self.settings.flashduty_poll_interval_seconds)


class InMemoryAnalysisScheduler:
    """Development scheduler; production should use Kafka or another durable queue."""

    def __init__(
        self,
        service: AlertAnalysisService,
        workers: int = 1,
        lease_retry_delay_seconds: float = 1.0,
    ) -> None:
        self.service = service
        self.workers = workers
        self.lease_retry_delay_seconds = lease_retry_delay_seconds
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []
        self._retry_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"alert-investigator-{index}")
            for index in range(self.workers)
        ]
        pending = await self.service.repository.list_by_status(
            {AlertStatus.QUEUED, AlertStatus.ANALYZING}
        )
        for stored in pending:
            await self.enqueue(str(stored.alert.id))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._retry_tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await asyncio.gather(*self._retry_tasks, return_exceptions=True)
        self._tasks.clear()
        self._retry_tasks.clear()

    async def enqueue(self, alert_id: str) -> None:
        if alert_id in self._queued:
            return
        self._queued.add(alert_id)
        await self.queue.put(alert_id)

    async def join(self) -> None:
        await self.queue.join()

    async def _worker(self) -> None:
        while True:
            alert_id = await self.queue.get()
            try:
                result = await self.service.analyze_by_id(alert_id)
                if result.status in {AlertStatus.QUEUED, AlertStatus.ANALYZING}:
                    self._schedule_lease_retry(alert_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Asynchronous investigation failed alert_id=%s", alert_id)
            finally:
                self._queued.discard(alert_id)
                self.queue.task_done()

    def _schedule_lease_retry(self, alert_id: str) -> None:
        async def retry_later() -> None:
            await asyncio.sleep(self.lease_retry_delay_seconds)
            await self.enqueue(alert_id)

        task = asyncio.create_task(
            retry_later(), name=f"alert-lease-retry-{alert_id}"
        )
        self._retry_tasks.add(task)
        task.add_done_callback(self._retry_tasks.discard)


class KafkaAnalysisScheduler:
    def __init__(self, settings: Settings, service: AlertAnalysisService) -> None:
        self.settings = settings
        self.service = service
        # aiokafka binds clients to the currently running event loop. FastAPI's
        # module-level app factory runs before Uvicorn starts that loop, so defer
        # client creation to the asynchronous lifespan hook.
        self.producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode(),
        )
        await self.producer.start()
        pending = await self.service.repository.list_by_status(
            {AlertStatus.QUEUED, AlertStatus.ANALYZING}
        )
        for stored in pending:
            await self.enqueue(str(stored.alert.id))

    async def stop(self) -> None:
        if self.producer is not None:
            await self.producer.stop()
            self.producer = None

    async def enqueue(self, alert_id: str) -> None:
        if self.producer is None:
            raise RuntimeError("Kafka analysis scheduler is not started")
        await self.producer.send_and_wait(
            self.settings.kafka_alert_topic,
            {
                "schema_version": 1,
                "job_type": "investigate",
                "alert_id": alert_id,
            },
        )


class ManualAnalysisScheduler:
    """Test/development scheduler that records jobs until explicitly executed."""

    def __init__(self) -> None:
        self.jobs: list[str] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def enqueue(self, alert_id: str) -> None:
        if alert_id not in self.jobs:
            self.jobs.append(alert_id)
