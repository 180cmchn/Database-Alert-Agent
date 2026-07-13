from __future__ import annotations

import asyncio
import json
import logging

from aiokafka import AIOKafkaProducer

from app.application.service import AlertAnalysisService
from app.config import Settings
from app.domain.models import AlertStatus

logger = logging.getLogger(__name__)


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
