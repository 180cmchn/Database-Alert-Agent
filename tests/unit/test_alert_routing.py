from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.persistence import SQLAlchemyAlertRepository
from app.application.escalation import AlertRoutingService, DurableEscalationScheduler
from app.application.routing_policy import (
    RoutingPolicyEngine,
    RoutingPolicyError,
    RoutingPolicyLoader,
)
from app.config import DEFAULT_SEVERITY_MAPPING
from app.domain.models import AlertSignalState, NormalizedAlert, Severity, utc_now
from app.domain.routing import (
    DeliveryResult,
    DeliveryState,
    EscalationStep,
    IncidentState,
    RoutingAction,
    RoutingCondition,
    RoutingPolicy,
    RoutingPolicySet,
)

POLICY_PATH = Path(__file__).parents[2] / "policies" / "alert-routing.yaml"


class StaticDirectory:
    async def get_on_call(self, _at):
        return "sona"

    async def is_non_working_time(self, _at):
        return False


class ConnectedPhoneDispatcher:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def send(self, action, _context):
        self.actions.append(action.channel)
        return DeliveryResult(
            state=DeliveryState.SENT,
            acknowledged=True,
            acknowledged_by="sona",
        )


def normalize(**overrides):
    payload = {
        "external_id": "routing-test",
        "severity": "CRITICAL",
        "title": "routing test",
        "reason": "routing_test",
        **overrides,
    }
    return CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(payload)


def test_flowchart_policies_are_first_match_wins_in_top_to_bottom_order() -> None:
    policy_set = RoutingPolicyLoader(POLICY_PATH).load()
    engine = RoutingPolicyEngine(policy_set)

    mysql = normalize(alert_name="mysql_repl_delay_more_than_60")
    assert engine.select(mysql, is_non_working_time=True).id == "mysql_data_replica_delay"

    wukong = normalize(resource_type="OCEANBASE", cluster="prod-wukong-01")
    assert engine.select(wukong, is_non_working_time=True).id == "wukong_ob_test"

    sc_ob = normalize(resource_type="OCEANBASE", cluster="sc_store_standby")
    assert engine.select(sc_ob, is_non_working_time=True).id == "sc_ob_critical"

    generic = normalize()
    assert engine.select(generic, is_non_working_time=True).id == "non_working_time_critical"
    assert engine.select(generic, is_non_working_time=False).id == "critical_warning"

    info = normalize(severity="INFO")
    assert engine.select(info, is_non_working_time=False).id == "info"


def test_policy_loader_rejects_priority_that_disagrees_with_file_order(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text(
        """
version: test
policies:
  - id: first
    name: first
    priority: 1
    match: {field: severity, equals: CRITICAL}
    steps:
      - name: first
        actions: [{channel: wecom_group, target: A}]
  - id: second
    name: second
    priority: 2
    match: {field: severity, equals: INFO}
    steps:
      - name: second
        actions: [{channel: wecom_group, target: B}]
""",
        encoding="utf-8",
    )
    with pytest.raises(RoutingPolicyError, match="high to low priority"):
        RoutingPolicyLoader(invalid).load()


def test_normalization_builds_three_level_signal_and_dedup_fields() -> None:
    alert = normalize(
        severity="HIGH",
        status="resolved",
        alert_name="replica_lag",
        cluster="cluster-a",
        database={"instance": "db-01"},
        environment="prod",
    )
    assert alert.severity is Severity.WARNING
    assert alert.signal_state is AlertSignalState.RESOLVED
    assert alert.alert_name == "replica_lag"
    assert alert.cluster == "cluster-a"
    assert alert.dedup_key.startswith("dedup-v1-")

    historical = alert.model_dump(mode="json")
    historical["severity"] = "HIGH"
    assert NormalizedAlert.model_validate(historical).severity is Severity.WARNING


@pytest.mark.asyncio
async def test_phone_connection_acknowledges_without_waiting_for_ai(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'routing.db'}"
    )
    await repository.initialize()
    policy = RoutingPolicy(
        id="phone",
        name="phone",
        priority=1,
        hold_seconds=0,
        match=RoutingCondition(field="severity", equals="CRITICAL"),
        steps=[
            EscalationStep(
                name="call",
                actions=[RoutingAction(channel="phone", recipient="on_call")],
            )
        ],
    )
    engine = RoutingPolicyEngine(
        RoutingPolicySet(version="test", policies=[policy])
    )
    directory = StaticDirectory()
    routing = AlertRoutingService(
        repository=repository, policy_engine=engine, directory=directory
    )
    dispatcher = ConnectedPhoneDispatcher()
    scheduler = DurableEscalationScheduler(
        routing_repository=repository,
        alert_repository=repository,
        routing_service=routing,
        dispatcher=dispatcher,
    )
    alert = normalize(external_id="phone-ack")
    await repository.create_or_get(alert)
    incident = await routing.handle_signal(alert)
    assert incident is not None
    assert incident.next_action_at is not None
    assert incident.next_action_at <= utc_now() + timedelta(seconds=1)

    assert await scheduler.run_once() == 1
    saved = await routing.get_incident(str(incident.id))
    assert saved is not None
    assert saved.state is IncidentState.ACKNOWLEDGED
    assert saved.acknowledged_by == "sona"
    assert dispatcher.actions == ["phone"]
    await repository.close()


@pytest.mark.asyncio
async def test_resolved_signal_cancels_pending_escalation(tmp_path: Path) -> None:
    repository = SQLAlchemyAlertRepository(
        f"sqlite+aiosqlite:///{tmp_path / 'resolved.db'}"
    )
    await repository.initialize()
    policy = RoutingPolicy(
        id="delayed",
        name="delayed",
        priority=1,
        hold_seconds=300,
        match=RoutingCondition(field="severity", equals="WARNING"),
        steps=[
            EscalationStep(
                name="notify",
                actions=[RoutingAction(channel="wecom_group", target="DATABASE_ALERTS")],
            )
        ],
    )
    routing = AlertRoutingService(
        repository=repository,
        policy_engine=RoutingPolicyEngine(
            RoutingPolicySet(version="test", policies=[policy])
        ),
        directory=StaticDirectory(),
    )
    firing = normalize(
        external_id="signal-firing",
        severity="WARNING",
        alert_name="replica_lag",
        cluster="cluster-a",
    )
    await repository.create_or_get(firing)
    incident = await routing.handle_signal(firing)
    assert incident is not None
    assert incident.state is IncidentState.PENDING

    resolved = normalize(
        external_id="signal-resolved",
        severity="WARNING",
        status="resolved",
        alert_name="replica_lag",
        cluster="cluster-a",
    )
    await repository.create_or_get(resolved)
    saved = await routing.handle_signal(resolved)
    assert saved is not None
    assert saved.state is IncidentState.RESOLVED
    assert saved.next_action_at is None
    await repository.close()
