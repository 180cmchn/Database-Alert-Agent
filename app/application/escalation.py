from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from uuid import uuid4

from app.adapters.escalation import EnterpriseWeComDirectory, EscalationDispatcher
from app.application.routing_policy import RoutingPolicyEngine
from app.domain.models import AlertSignalState, NormalizedAlert, utc_now
from app.domain.ports import AlertRepository, AlertRoutingRepository
from app.domain.routing import (
    AlertIncident,
    EscalationDelivery,
    IncidentState,
    RoutingContext,
)

logger = logging.getLogger(__name__)


class AlertRoutingService:
    def __init__(
        self,
        *,
        repository: AlertRoutingRepository,
        policy_engine: RoutingPolicyEngine,
        directory: EnterpriseWeComDirectory,
    ) -> None:
        self.repository = repository
        self.policy_engine = policy_engine
        self.directory = directory

    async def handle_signal(self, alert: NormalizedAlert) -> AlertIncident | None:
        now = utc_now()
        if alert.signal_state == AlertSignalState.RESOLVED:
            return await self.repository.resolve_incident(alert.dedup_key, now)

        non_working = await self.directory.is_non_working_time(now)
        policy = self.policy_engine.select(
            alert, is_non_working_time=non_working
        )
        if policy is None:
            logger.warning("No routing policy matched alert_id=%s", alert.id)
            return None
        first_action_at = now + timedelta(seconds=policy.hold_seconds)
        incident, _ = await self.repository.upsert_firing_incident(
            alert,
            policy,
            self.policy_engine.policy_set.version,
            first_action_at,
        )
        return incident

    async def acknowledge(self, incident_id: str, actor: str) -> AlertIncident | None:
        return await self.repository.acknowledge_incident(
            incident_id, actor, utc_now()
        )

    async def get_incident(self, incident_id: str) -> AlertIncident | None:
        return await self.repository.get_incident(incident_id)

    async def get_incident_for_alert(self, alert_id: str) -> AlertIncident | None:
        return await self.repository.get_incident_for_alert(alert_id)


class DurableEscalationScheduler:
    """Poll durable actions; all wait times remain independent of AI investigation."""

    def __init__(
        self,
        *,
        routing_repository: AlertRoutingRepository,
        alert_repository: AlertRepository,
        routing_service: AlertRoutingService,
        dispatcher: EscalationDispatcher,
        poll_seconds: float = 2,
        lease_seconds: int = 60,
    ) -> None:
        self.routing_repository = routing_repository
        self.alert_repository = alert_repository
        self.routing_service = routing_service
        self.dispatcher = dispatcher
        self.poll_seconds = poll_seconds
        self.lease_seconds = lease_seconds
        self.owner = f"routing-{uuid4()}"
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(
                self._run(), name="durable-alert-escalation"
            )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    async def run_once(self) -> int:
        now = utc_now()
        incidents = await self.routing_repository.claim_due_incidents(
            self.owner, now, self.lease_seconds
        )
        for incident in incidents:
            try:
                await self._process_incident(incident)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Escalation step failed incident_id=%s", incident.id)
                await self.routing_repository.release_incident_claim(
                    str(incident.id), self.owner, utc_now() + timedelta(seconds=30)
                )
        return len(incidents)

    async def _run(self) -> None:
        while True:
            await self.run_once()
            await asyncio.sleep(self.poll_seconds)

    async def _process_incident(self, incident: AlertIncident) -> None:
        policy = incident.policy_snapshot
        if policy is None or incident.current_step >= len(policy.steps):
            await self.routing_repository.complete_incident_step(
                str(incident.id),
                self.owner,
                incident.current_step,
                next_action_at=None,
                state=IncidentState.FIRING,
            )
            return
        stored = await self.alert_repository.get(str(incident.alert_id))
        if stored is None:
            raise RuntimeError(f"Alert {incident.alert_id} no longer exists")

        step_index = incident.current_step
        step = policy.steps[step_index]
        context = RoutingContext(incident=incident, alert=stored.alert, policy=policy)
        for action_index, action in enumerate(step.actions):
            result = await self.dispatcher.send(action, context)
            await self.routing_repository.save_escalation_delivery(
                EscalationDelivery(
                    incident_id=incident.id,
                    step_index=step_index,
                    action_index=action_index,
                    channel=action.channel,
                    target=action.target,
                    recipient=result.recipient or action.recipient,
                    state=result.state,
                    attempts=1,
                    external_delivery_id=result.external_delivery_id,
                    error=result.error,
                )
            )
            if result.acknowledged:
                await self.routing_service.acknowledge(
                    str(incident.id), result.acknowledged_by or "phone-connected"
                )
                return

        next_index = step_index + 1
        next_action_at = None
        if next_index < len(policy.steps):
            next_action_at = utc_now() + timedelta(
                seconds=policy.steps[next_index].delay_seconds
            )
        await self.routing_repository.complete_incident_step(
            str(incident.id),
            self.owner,
            step_index,
            next_action_at=next_action_at,
            state=IncidentState.FIRING,
        )
