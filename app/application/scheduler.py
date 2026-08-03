from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass

from aiokafka import AIOKafkaProducer

from app.adapters.flashduty import FlashDutyClient
from app.application.service import AlertAnalysisService
from app.config import Settings
from app.domain.models import AlertStatus, StoredAlert

logger = logging.getLogger(__name__)


def _remaining_poll_delay(
    interval_seconds: int, *, started_at: float, finished_at: float
) -> float:
    return max(0.0, interval_seconds - (finished_at - started_at))


class _ResizableConcurrencyLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.active = 0
        self._condition = asyncio.Condition()

    async def acquire(self) -> None:
        async with self._condition:
            await self._condition.wait_for(lambda: self.active < self.limit)
            self.active += 1

    async def release(self) -> None:
        async with self._condition:
            self.active -= 1
            self._condition.notify_all()

    async def resize(self, limit: int) -> None:
        async with self._condition:
            self.limit = limit
            self._condition.notify_all()


@dataclass(frozen=True)
class FlashDutyPollItemResult:
    stored: StoredAlert
    created: bool


@dataclass(frozen=True)
class FlashDutyPollResult:
    start_time: int
    end_time: int
    pages: int
    items: tuple[FlashDutyPollItemResult, ...]

    @property
    def total_count(self) -> int:
        return len(self.items)

    @property
    def new_count(self) -> int:
        return sum(int(item.created) for item in self.items)

    @property
    def deduplicated_count(self) -> int:
        return self.total_count - self.new_count


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
        self._poll_lock = asyncio.Lock()

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
        self._task = asyncio.create_task(self._loop(), name="flashduty-alert-poller")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    async def sync_settings(self, settings: Settings) -> None:
        """Apply updated runtime settings to the poller.

        Interval and lookback changes take effect on the next loop iteration.
        A polling_enabled transition starts or stops the background task.
        """
        self.settings = settings
        if self.enabled and self._task is None:
            self._task = asyncio.create_task(self._loop(), name="flashduty-alert-poller")
        elif not self.enabled and self._task is not None:
            await self.stop()

    async def run_once(self, *, now: int | None = None) -> int:
        if not self.enabled or self.client is None:
            return 0
        result = await self.poll_window(now=now)
        return result.new_count

    async def poll_window(
        self,
        *,
        now: int | None = None,
        client: FlashDutyClient | None = None,
    ) -> FlashDutyPollResult:
        """Fetch and ingest one complete, fixed FlashDuty occurrence-time window."""

        poll_client = client or self.client
        if poll_client is None:
            raise RuntimeError("FlashDuty client is not configured")

        # Manual and background polls share this instance. Serializing them avoids
        # duplicate queue publications while preserving database-level idempotency.
        async with self._poll_lock:
            end_time = int(time.time()) if now is None else now
            overlap = self.settings.flashduty_poll_lookback_seconds
            start_time = max(0, end_time - overlap)
            fetched, pages = await self._fetch_complete_window(
                poll_client,
                start_time=start_time,
                end_time=end_time,
            )

            processed: list[FlashDutyPollItemResult] = []
            failed_alert_ids: list[str] = []
            for alert_id, (request_id, item) in fetched.items():
                try:
                    # FlashDuty documents AlertItem as a complete alert object.
                    # Ingesting the captured list item keeps pagination fast and
                    # prevents per-alert detail calls from causing data loss.
                    stored, created = await self.service.ingest(
                        "flashduty",
                        {"request_id": request_id, "data": item},
                    )
                    if created or stored.status in {
                        AlertStatus.RECEIVED,
                        AlertStatus.QUEUED,
                        AlertStatus.FAILED,
                    }:
                        await self.scheduler.enqueue(str(stored.alert.id))
                    processed.append(
                        FlashDutyPollItemResult(stored=stored, created=created)
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    failed_alert_ids.append(alert_id)
                    logger.exception(
                        "flashduty_poll_alert_ingest_failed external_alert_id=%s",
                        alert_id,
                    )

            if failed_alert_ids:
                logger.error(
                    "flashduty_poll_incomplete start_time=%s end_time=%s "
                    "fetched=%s processed=%s failed=%s",
                    start_time,
                    end_time,
                    len(fetched),
                    len(processed),
                    len(failed_alert_ids),
                )
                raise RuntimeError(
                    "FlashDuty poll did not ingest every fetched alert "
                    f"({len(failed_alert_ids)} of {len(fetched)} failed)"
                )

            result = FlashDutyPollResult(
                start_time=start_time,
                end_time=end_time,
                pages=pages,
                items=tuple(processed),
            )
            logger.info(
                "flashduty_poll_completed start_time=%s end_time=%s pages=%s "
                "fetched=%s created=%s deduplicated=%s",
                start_time,
                end_time,
                pages,
                result.total_count,
                result.new_count,
                result.deduplicated_count,
            )
            return result

    async def _fetch_complete_window(
        self,
        client: FlashDutyClient,
        *,
        start_time: int,
        end_time: int,
    ) -> tuple[dict[str, tuple[str, dict[str, object]]], int]:
        """Exhaust cursor pagination before performing slower per-alert work."""

        cursor: str | None = None
        seen_cursors: set[str] = set()
        fetched: dict[str, tuple[str, dict[str, object]]] = {}
        reported_total = 0
        pages = 0

        while True:
            response = await client.list_alerts(
                start_time=start_time,
                end_time=end_time,
                limit=100,
                search_after_ctx=cursor,
                channel_ids=self.settings.flashduty_poll_channel_ids,
                integration_ids=self.settings.flashduty_poll_integration_ids,
                is_active=None,
                by_updated_at=False,
            )
            data = response.data if isinstance(response.data, dict) else {}
            items = data.get("items")
            if not isinstance(items, list):
                raise RuntimeError("FlashDuty /alert/list response did not contain items")
            pages += 1

            total = data.get("total")
            if total is not None:
                if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                    raise RuntimeError("FlashDuty /alert/list returned an invalid total")
                reported_total = max(reported_total, total)

            fetched_before_page = len(fetched)
            for item in items:
                if not isinstance(item, dict):
                    raise RuntimeError(
                        "FlashDuty /alert/list returned a non-object alert item"
                    )
                alert_id = item.get("alert_id")
                if not isinstance(alert_id, str) or not alert_id:
                    raise RuntimeError(
                        "FlashDuty /alert/list returned an invalid alert_id"
                    )
                fetched.setdefault(alert_id, (response.request_id, item))

            next_cursor = data.get("search_after_ctx")
            has_next = data.get("has_next_page")
            if not isinstance(has_next, bool):
                raise RuntimeError(
                    "FlashDuty /alert/list returned an invalid has_next_page"
                )
            if not has_next:
                break
            if len(fetched) == fetched_before_page:
                raise RuntimeError(
                    "FlashDuty /alert/list pagination made no alert progress"
                )
            if not isinstance(next_cursor, str) or not next_cursor:
                raise RuntimeError(
                    "FlashDuty /alert/list omitted the next-page cursor"
                )
            if next_cursor == cursor or next_cursor in seen_cursors:
                raise RuntimeError("FlashDuty /alert/list returned a repeated cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        if len(fetched) < reported_total:
            raise RuntimeError(
                "FlashDuty /alert/list pagination was incomplete "
                f"(expected at least {reported_total}, fetched {len(fetched)})"
            )
        return fetched, pages

    async def _loop(self) -> None:
        while True:
            started_at = time.monotonic()
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # The next pass uses its own complete lookback window.
                logger.exception("flashduty_poll_failed")
            await asyncio.sleep(
                _remaining_poll_delay(
                    self.settings.flashduty_poll_interval_seconds,
                    started_at=started_at,
                    finished_at=time.monotonic(),
                )
            )


class InMemoryAnalysisScheduler:
    """Development scheduler; production should use Kafka or another durable queue."""

    def __init__(
        self,
        service: AlertAnalysisService,
        workers: int = 1,
        max_workers: int = 16,
        lease_retry_delay_seconds: float = 1.0,
    ) -> None:
        if not 1 <= workers <= max_workers:
            raise ValueError("workers must be between 1 and max_workers")
        self.service = service
        self.workers = workers
        self.max_workers = max_workers
        self.lease_retry_delay_seconds = lease_retry_delay_seconds
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []
        self._retry_tasks: set[asyncio.Task[None]] = set()
        self._limiter = _ResizableConcurrencyLimiter(workers)

    async def start(self) -> None:
        if self._tasks:
            return
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"alert-investigator-{index}")
            for index in range(self.max_workers)
        ]
        pending = await self.service.repository.list_by_status(
            {AlertStatus.RECEIVED, AlertStatus.QUEUED, AlertStatus.ANALYZING}
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

    async def sync_workers(self, workers: int) -> None:
        if not 1 <= workers <= self.max_workers:
            raise ValueError("workers must be between 1 and max_workers")
        self.workers = workers
        await self._limiter.resize(workers)

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
                await self._limiter.acquire()
                try:
                    result = await self.service.analyze_by_id(alert_id)
                    if result.status in {AlertStatus.QUEUED, AlertStatus.ANALYZING}:
                        self._schedule_lease_retry(alert_id)
                finally:
                    await self._limiter.release()
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

        task = asyncio.create_task(retry_later(), name=f"alert-lease-retry-{alert_id}")
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
            {AlertStatus.RECEIVED, AlertStatus.QUEUED, AlertStatus.ANALYZING}
        )
        for stored in pending:
            await self.enqueue(str(stored.alert.id))

    async def stop(self) -> None:
        if self.producer is not None:
            await self.producer.stop()
            self.producer = None

    async def sync_workers(self, workers: int) -> None:
        # Analysis concurrency is applied by the Kafka consumer process when it
        # reloads the shared runtime settings before the next record batch.
        return None

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

    async def sync_workers(self, workers: int) -> None:
        return None

    async def enqueue(self, alert_id: str) -> None:
        if alert_id not in self.jobs:
            self.jobs.append(alert_id)
