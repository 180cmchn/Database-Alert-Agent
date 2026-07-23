"""LangGraph-based scheduler for alert investigation.

This module provides schedulers that use LangGraph for alert investigation,
replacing the original InMemoryAnalysisScheduler and KafkaAnalysisScheduler.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import uuid4

from aiokafka import AIOKafkaProducer

from app.adapters.investigation import InvestigationToolRegistry, ToolExecutor
from app.agents.graph import InvestigationAgent
from app.agents.state import AgentState, create_initial_state
from app.config import Settings
from app.domain.models import AlertStatus, InvestigationStage, RunStatus
from app.domain.ports import AIAdvisor, AlertRepository, ConclusionValidator, InvestigationStrategyProvider, ManagementNotifier, RunbookProvider

logger = logging.getLogger(__name__)


class LangGraphScheduler:
    """LangGraph-based scheduler for alert investigation.
    
    This scheduler uses the LangGraph InvestigationAgent to process alerts.
    It can operate in memory or be backed by Kafka for production use.
    """
    
    def __init__(
        self,
        *,
        agent: InvestigationAgent,
        repository: AlertRepository,
        notifier: ManagementNotifier,
        source_registry: Any,  # AlertSourceRegistry
        alert_sanitizer: Any,  # Callable[[NormalizedAlert], NormalizedAlert]
        investigation_lease_seconds: int = 300,
        max_dynamic_turns: int = 0,
        validation_enabled: bool = True,
        shadow_enabled: bool = False,
        ai_fallback_enabled: bool = True,
        workers: int = 1,
        lease_retry_delay_seconds: float = 1.0,
    ) -> None:
        self.agent = agent
        self.repository = repository
        self.notifier = notifier
        self.source_registry = source_registry
        self.alert_sanitizer = alert_sanitizer
        self.investigation_lease_seconds = investigation_lease_seconds
        self.max_dynamic_turns = max_dynamic_turns
        self.validation_enabled = validation_enabled
        self.shadow_enabled = shadow_enabled
        self.ai_fallback_enabled = ai_fallback_enabled
        self.workers = workers
        self.lease_retry_delay_seconds = lease_retry_delay_seconds
        
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []
        self._retry_tasks: set[asyncio.Task[None]] = set()
    
    async def start(self) -> None:
        """Start the scheduler workers."""
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"langgraph-investigator-{index}")
            for index in range(self.workers)
        ]
        # Recover pending alerts
        pending = await self.repository.list_by_status(
            {AlertStatus.QUEUED, AlertStatus.ANALYZING}
        )
        for stored in pending:
            await self.enqueue(str(stored.alert.id))
    
    async def stop(self) -> None:
        """Stop the scheduler workers."""
        for task in self._tasks:
            task.cancel()
        for task in self._retry_tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await asyncio.gather(*self._retry_tasks, return_exceptions=True)
        self._tasks.clear()
        self._retry_tasks.clear()
    
    async def enqueue(self, alert_id: str) -> None:
        """Enqueue an alert for investigation."""
        if alert_id in self._queued:
            return
        self._queued.add(alert_id)
        await self.queue.put(alert_id)
    
    async def join(self) -> None:
        """Wait for all queued alerts to be processed."""
        await self.queue.join()
    
    async def _worker(self) -> None:
        """Worker coroutine that processes alerts from the queue."""
        while True:
            alert_id = await self.queue.get()
            try:
                await self._investigate(alert_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("langgraph_investigation_failed alert_id=%s", alert_id)
            finally:
                self._queued.discard(alert_id)
                self.queue.task_done()
    
    async def _investigate(self, alert_id: str) -> None:
        """Run the LangGraph investigation for an alert."""
        stored = await self.repository.get(alert_id)
        if not stored:
            logger.warning("alert_not_found alert_id=%s", alert_id)
            return
        
        if stored.status in {AlertStatus.COMPLETED, AlertStatus.REVIEW_REQUIRED}:
            logger.debug("alert_already_completed alert_id=%s", alert_id)
            return
        
        # Create investigation run
        run = await self.repository.create_run(
            alert_id,
            lease_owner=f"langgraph-worker-{uuid4()}",
            lease_seconds=self.investigation_lease_seconds,
        )
        if run is None:
            # Another worker has the lease, retry later
            self._schedule_lease_retry(alert_id)
            return
        
        # Create initial state
        initial_state = create_initial_state(
            alert_id=alert_id,
            alert=stored.alert,
            stored_alert=stored,
            run=run,
            max_dynamic_turns=self.max_dynamic_turns,
            validation_enabled=self.validation_enabled,
            shadow_enabled=self.shadow_enabled,
            ai_fallback_enabled=self.ai_fallback_enabled,
        )
        
        # Record initial progress
        await self.repository.append_progress(
            alert_id,
            self._create_progress(run.id, InvestigationStage.RECEIVED, "调查 Worker 已领取任务。"),
        )
        
        try:
            # Run the LangGraph investigation
            final_state = await self.agent.run(initial_state)
            
            # Send notification
            if final_state.recommendation and final_state.alert:
                await self._send_result(final_state)
                
        except Exception as exc:
            logger.exception("langgraph_investigation_error alert_id=%s", alert_id)
            error_msg = f"{type(exc).__name__}: {str(exc)}"
            await self.repository.update_run(
                str(run.id),
                status=RunStatus.FAILED.value,
                stage=InvestigationStage.FAILED,
                error=error_msg,
            )
            await self.repository.append_progress(
                alert_id,
                self._create_progress(run.id, InvestigationStage.FAILED, "调查执行失败。", {"error": error_msg}),
            )
            await self.repository.save_analysis(
                alert_id, AlertStatus.FAILED, runbooks=[], error=error_msg
            )
    
    def _schedule_lease_retry(self, alert_id: str) -> None:
        """Schedule a retry for lease acquisition."""
        async def retry_later() -> None:
            await asyncio.sleep(self.lease_retry_delay_seconds)
            await self.enqueue(alert_id)
        
        task = asyncio.create_task(retry_later(), name=f"lease-retry-{alert_id}")
        self._retry_tasks.add(task)
        task.add_done_callback(self._retry_tasks.discard)
    
    async def _send_result(self, state: AgentState) -> None:
        """Send analysis result notification."""
        from app.domain.models import AnalysisResultEvent
        
        if not state.alert or not state.recommendation:
            return
        
        passed = state.status == AlertStatus.COMPLETED
        message = (
            "数据库告警分析已完成。" if passed else
            "数据库告警已生成影子分析，请人工复核。" if self.shadow_enabled else
            "数据库告警已生成候选分析，请人工复核。"
        )
        
        event = AnalysisResultEvent(
            alert=state.alert,
            recommendation=state.recommendation,
            status=state.status,
            message=message,
        )
        try:
            await self.notifier.send(event)
        except Exception as exc:
            logger.warning(
                "langgraph_result_send_failed alert_id=%s error=%s",
                state.alert_id,
                type(exc).__name__,
            )
    
    def _create_progress(
        self, run_id: Any, stage: InvestigationStage, message: str, details: dict[str, Any] | None = None
    ) -> Any:
        """Create a progress record."""
        from app.domain.models import ProgressRecord
        return ProgressRecord(
            run_id=run_id,
            stage=stage,
            message=message,
            details=details or {},
        )


class KafkaLangGraphScheduler:
    """Kafka-backed scheduler using LangGraph for investigation.
    
    This scheduler enqueues jobs to Kafka and has separate consumers
    that process the jobs using the LangGraph InvestigationAgent.
    """
    
    def __init__(self, settings: Settings, agent: InvestigationAgent) -> None:
        self.settings = settings
        self.agent = agent
        self.producer: AIOKafkaProducer | None = None
    
    async def start(self) -> None:
        """Start the Kafka producer."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode(),
        )
        await self.producer.start()
        
        # Recover pending alerts
        pending = await self.agent.ctx.repository.list_by_status(
            {AlertStatus.QUEUED, AlertStatus.ANALYZING}
        )
        for stored in pending:
            await self.enqueue(str(stored.alert.id))
    
    async def stop(self) -> None:
        """Stop the Kafka producer."""
        if self.producer is not None:
            await self.producer.stop()
            self.producer = None
    
    async def enqueue(self, alert_id: str) -> None:
        """Enqueue an alert to Kafka for investigation."""
        if self.producer is None:
            raise RuntimeError("Kafka scheduler is not started")
        await self.producer.send_and_wait(
            self.settings.kafka_alert_topic,
            {
                "schema_version": 1,
                "job_type": "investigate",
                "alert_id": alert_id,
            },
        )


class ManualLangGraphScheduler:
    """Manual scheduler for testing with LangGraph.
    
    Records jobs until explicitly executed, useful for testing.
    """
    
    def __init__(self, agent: InvestigationAgent) -> None:
        self.agent = agent
        self.jobs: list[str] = []
    
    async def start(self) -> None:
        pass
    
    async def stop(self) -> None:
        pass
    
    async def enqueue(self, alert_id: str) -> None:
        if alert_id not in self.jobs:
            self.jobs.append(alert_id)
    
    async def run_next(self) -> bool:
        """Run the next queued job. Returns True if a job was run."""
        if not self.jobs:
            return False
        alert_id = self.jobs.pop(0)
        
        stored = await self.agent.ctx.repository.get(alert_id)
        if not stored:
            return False
        
        run = await self.agent.ctx.repository.create_run(
            alert_id,
            lease_owner=f"manual-{uuid4()}",
            lease_seconds=300,
        )
        if run is None:
            return False
        
        initial_state = create_initial_state(
            alert_id=alert_id,
            alert=stored.alert,
            stored_alert=stored,
            run=run,
        )
        
        await self.agent.run(initial_state)
        return True