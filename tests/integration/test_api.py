from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.flashduty import FlashDutyAPIError, FlashDutyResponse
from app.api.main import create_app
from app.application.factory import Runtime, build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings


def create_test_client(
    tmp_path: Path,
    **setting_overrides: object,
) -> tuple[TestClient, Runtime, ManualAnalysisScheduler]:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        runtime_settings_path=tmp_path / "runtime-settings.json",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        **setting_overrides,
    )
    runtime = build_runtime(settings)
    scheduler = ManualAnalysisScheduler()
    return (
        TestClient(create_app(settings, runtime, scheduler)),
        runtime,
        scheduler,
    )


def test_analyze_and_get_alert(tmp_path: Path) -> None:
    client, runtime, scheduler = create_test_client(tmp_path)
    with client:
        response = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "api-1",
                "severity": "WARNING",
                "title": "Database latency",
                "reason": "latency",
            },
        )
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "QUEUED"
        assert body["event_id"] == "api-1"
        assert body["deduplicated"] is False
        assert scheduler.jobs == [body["alert_id"]]

        queued = client.get(body["detail_url"])
        assert queued.status_code == 200
        assert queued.json()["status"] == "QUEUED"
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, body["alert_id"])

        detail = client.get(body["detail_url"])
        assert detail.status_code == 200
        detail_body = detail.json()
        assert detail_body["status"] == "INCONCLUSIVE"
        assert detail_body["alert"]["external_id"] == "api-1"
        assert detail_body["recommendation"]["knowledge_matches"] == []
        assert "requires_human" not in detail_body["recommendation"]
        assert "feedback" not in detail_body
        assert "knowledge_matches" not in detail_body
        assert all(item["passed"] for item in detail_body["validations"])
        assert all(not item["evidence_sufficient"] for item in detail_body["validations"])


def test_analysis_filter_persists_without_scheduling_or_run(tmp_path: Path) -> None:
    client, _, scheduler = create_test_client(
        tmp_path,
        alert_analysis_filter_enabled=True,
        alert_analysis_filter_max_severity="INFO",
    )
    with client:
        filtered = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "api-filtered-info",
                "severity": "INFO",
                "title": "Stored only alert",
                "reason": "test",
            },
        )
        assert filtered.status_code == 202
        filtered_body = filtered.json()
        assert filtered_body["status"] == "FILTERED"
        assert filtered_body["deduplicated"] is False
        assert scheduler.jobs == []

        detail = client.get(filtered_body["detail_url"])
        assert detail.status_code == 200
        detail_body = detail.json()
        assert detail_body["status"] == "FILTERED"
        assert detail_body["latest_run"] is None
        assert detail_body["all_runs"] == []
        assert detail_body["recommendation"] is None
        assert detail_body["progress"] == []
        assert detail_body["evidence_records"] == []
        assert detail_body["validations"] == []

        duplicate = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "api-filtered-info",
                "severity": "INFO",
                "title": "Stored only alert",
                "reason": "test",
            },
        )
        assert duplicate.status_code == 202
        assert duplicate.json()["status"] == "FILTERED"
        assert duplicate.json()["deduplicated"] is True
        assert scheduler.jobs == []

        admitted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "api-admitted-warning",
                "severity": "WARNING",
                "title": "Admitted alert",
                "reason": "test",
            },
        )
        assert admitted.status_code == 202
        assert admitted.json()["status"] == "QUEUED"
        assert scheduler.jobs == [admitted.json()["alert_id"]]

        dashboard = client.get("/api/v1/dashboard/summary")
        assert dashboard.status_code == 200
        assert dashboard.json()["by_status"]["FILTERED"] == 1
        assert dashboard.json()["active"] == 1


def test_unknown_source_and_invalid_payload(tmp_path: Path) -> None:
    client, _, scheduler = create_test_client(tmp_path)
    with client:
        unknown = client.post("/api/v1/alerts/vendor/analyze", json={})
        assert unknown.status_code == 404
        assert unknown.json()["code"] == "UNKNOWN_ALERT_SOURCE"

        invalid = client.post("/api/v1/alerts/canonical/analyze", json={"severity": "WARNING"})
        assert invalid.status_code == 422
        assert invalid.json()["code"] == "INVALID_ALERT_PAYLOAD"
        assert scheduler.jobs == []


def test_feedback_api_is_not_exposed(tmp_path: Path) -> None:
    client, _, _ = create_test_client(tmp_path)
    with client:
        response = client.post(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000000/feedback",
            json={},
        )
        assert response.status_code == 404
        paths = client.get("/openapi.json").json()["paths"]
        assert not any(path.endswith("/feedback") for path in paths)


def test_flashduty_is_ingested_only_by_the_api_poller(tmp_path: Path) -> None:
    client, _, _ = create_test_client(tmp_path)
    payload = {
        "data": {
            "alert_id": "663a1b2c3d4e5f6789abcdef",
            "title": "Database latency",
            "alert_severity": "Warning",
            "start_time": 1712650000,
        }
    }
    with client:
        webhook = client.post("/api/v1/webhooks/flashduty/alerts", json=payload)
        direct = client.post("/api/v1/alerts/flashduty/analyze", json=payload)

    assert webhook.status_code == 404
    assert direct.status_code == 404
    assert direct.json()["detail"]["code"] == "FLASHDUTY_POLLING_ONLY"


def test_readiness_reports_configuration(tmp_path: Path) -> None:
    client, _, _ = create_test_client(tmp_path)
    with client:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "issues": []}


def test_readiness_does_not_probe_external_knowledge_service(tmp_path: Path) -> None:
    client, runtime, _ = create_test_client(
        tmp_path,
        external_knowledge_base_url="http://knowledge.test",
        knowledge_sources=["external_knowledge"],
    )

    with client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "issues": []}


@pytest.mark.parametrize(
    (
        "filter_enabled",
        "raw_severity",
        "max_severity",
        "expected_status",
        "expected_job_count",
    ),
    [
        (False, "Warning", "INFO", "QUEUED", 1),
        (True, "Warning", "WARNING", "FILTERED", 0),
        (True, "Ok", "INFO", "FILTERED", 0),
        (True, "Warning", "INFO", "QUEUED", 1),
    ],
)
def test_manual_flashduty_poll_applies_analysis_filter(
    tmp_path: Path,
    filter_enabled: bool,
    raw_severity: str,
    max_severity: str,
    expected_status: str,
    expected_job_count: int,
) -> None:
    client, runtime, scheduler = create_test_client(
        tmp_path,
        admin_api_token="test-admin-token",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=False,
        flashduty_poll_lookback_seconds=1200,
        flashduty_poll_channel_ids=[7],
        alert_analysis_filter_enabled=filter_enabled,
        alert_analysis_filter_max_severity=max_severity,
    )
    requests: list[dict] = []

    class RecordingFlashDutyClient:
        async def list_alerts(self, **payload):  # type: ignore[no-untyped-def]
            requests.append(payload)
            return FlashDutyResponse(
                "list-request",
                {
                    "items": [
                        {
                            "alert_id": "663a1b2c3d4e5f6789abcdef",
                            "title": "Database latency",
                            "description": "Latency is above threshold",
                            "alert_severity": raw_severity,
                            "alert_status": raw_severity,
                            "alert_key": "database-latency",
                            "start_time": 900,
                            "labels": {"env": "test", "service": "orders-db"},
                        }
                    ],
                    "total": 1,
                    "has_next_page": False,
                },
            )

        async def alert_info(self, alert_id: str) -> FlashDutyResponse:
            raise AssertionError(f"polling must not call /alert/info for {alert_id}")

    runtime.flashduty_client = RecordingFlashDutyClient()  # type: ignore[assignment]
    with client:
        response = client.post(
            "/api/v1/admin/flashduty/poll",
            headers={"Authorization": "Bearer test-admin-token"},
        )
        alerts = client.get("/api/v1/alerts")

    assert response.status_code == 200
    assert response.json()["new_count"] == 1
    assert response.json()["time_range_seconds"] == 1200
    assert response.json()["end_time"] - response.json()["start_time"] == 1200
    assert len(scheduler.jobs) == expected_job_count
    assert alerts.status_code == 200
    assert alerts.json()["items"][0]["status"] == expected_status
    assert requests[0]["by_updated_at"] is False


def flashduty_ingest_payload() -> dict[str, object]:
    return {
        "data": {
            "alert_id": "663a1b2c3d4e5f6789abcdef",
            "title": "Database latency",
            "alert_severity": "Warning",
            "start_time": 1_712_650_000,
            "labels": {"env": "test", "service": "orders-db"},
        }
    }


class HandlingFlashDutyClient:
    def __init__(
        self,
        *,
        fail_alert: bool = False,
        fail_incident: bool = False,
        fail_members: bool = False,
    ) -> None:
        self.fail_alert = fail_alert
        self.fail_incident = fail_incident
        self.fail_members = fail_members
        self.calls: list[tuple[str, str, bool]] = []
        self.member_calls: list[tuple[int, int, bool]] = []

    async def alert_info(
        self,
        alert_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.calls.append(("alert", alert_id, retry_until_cancelled))
        if self.fail_alert:
            raise FlashDutyAPIError("alert unavailable", code="UpstreamError")
        return FlashDutyResponse(
            "alert-request",
            {
                "alert_id": alert_id,
                "incident": {
                    "incident_id": "69da451ef77b1b51f40e83ee",
                    "progress": "Triggered",
                },
            },
        )

    async def incident_info(
        self,
        incident_id: str,
        *,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.calls.append(("incident", incident_id, retry_until_cancelled))
        if self.fail_incident:
            raise FlashDutyAPIError("incident unavailable", code="UpstreamError")
        return FlashDutyResponse(
            "incident-request",
            {
                "incident_id": incident_id,
                "progress": "Processing",
                "responders": [
                    {
                        "person_id": 11,
                        "person_name": "Database Owner",
                        "assigned_at": 1_712_650_010,
                        "acknowledged_at": 1_712_650_030,
                    },
                    {
                        "person_id": 12,
                        "person_name": "Assigned Only",
                        "assigned_at": 1_712_650_020,
                        "acknowledged_at": 0,
                    },
                ],
            },
        )

    async def list_members(
        self,
        *,
        page: int,
        limit: int = 100,
        retry_until_cancelled: bool = True,
    ) -> FlashDutyResponse:
        self.member_calls.append((page, limit, retry_until_cancelled))
        if self.fail_members:
            raise FlashDutyAPIError("member directory unavailable", code="UpstreamError")
        return FlashDutyResponse(
            "member-request",
            {
                "total": 2,
                "items": [
                    {
                        "member_id": 11,
                        "member_name": "dylan.du",
                        "email": "must-not-leak@example.com",
                        "ref_id": "private-sso-reference",
                    },
                    {"member_id": 12, "member_name": "assigned.only"},
                ],
            },
        )


def test_get_flashduty_handling_projects_current_incident(tmp_path: Path) -> None:
    client, runtime, _ = create_test_client(
        tmp_path,
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
    )
    flashduty = HandlingFlashDutyClient()
    runtime.flashduty_client = flashduty  # type: ignore[assignment]

    with client:
        assert client.portal is not None
        stored, _created = client.portal.call(
            runtime.service.ingest,
            "flashduty",
            flashduty_ingest_payload(),
        )
        response = client.get(f"/api/v1/alerts/{stored.alert.id}/flashduty-handling")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["linked_incident"] is True
    assert body["progress"] == "Processing"
    assert body["handlers_complete"] is True
    assert [(item["person_id"], item["person_name"]) for item in body["handlers"]] == [
        (11, "dylan.du")
    ]
    assert body["warning_code"] is None
    assert flashduty.calls == [
        ("alert", "663a1b2c3d4e5f6789abcdef", False),
        ("incident", "69da451ef77b1b51f40e83ee", False),
    ]
    assert flashduty.member_calls == [(1, 100, False)]


def test_get_flashduty_handling_keeps_partial_alert_progress(tmp_path: Path) -> None:
    client, runtime, _ = create_test_client(
        tmp_path,
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
    )
    runtime.flashduty_client = HandlingFlashDutyClient(  # type: ignore[assignment]
        fail_incident=True
    )

    with client:
        assert client.portal is not None
        stored, _created = client.portal.call(
            runtime.service.ingest,
            "flashduty",
            flashduty_ingest_payload(),
        )
        response = client.get(f"/api/v1/alerts/{stored.alert.id}/flashduty-handling")

    assert response.status_code == 200
    body = response.json()
    assert body["linked_incident"] is True
    assert body["progress"] == "Triggered"
    assert body["handlers"] == []
    assert body["handlers_complete"] is False
    assert body["warning_code"] == "INCIDENT_DETAILS_UNAVAILABLE"


def test_flashduty_handling_failure_does_not_break_stored_detail(tmp_path: Path) -> None:
    client, runtime, _ = create_test_client(
        tmp_path,
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
    )
    runtime.flashduty_client = HandlingFlashDutyClient(  # type: ignore[assignment]
        fail_alert=True
    )

    with client:
        assert client.portal is not None
        stored, _created = client.portal.call(
            runtime.service.ingest,
            "flashduty",
            flashduty_ingest_payload(),
        )
        handling = client.get(f"/api/v1/alerts/{stored.alert.id}/flashduty-handling")
        detail = client.get(f"/api/v1/alerts/{stored.alert.id}")

    assert handling.status_code == 502
    assert handling.json()["detail"]["code"] == "FLASHDUTY_HANDLING_UNAVAILABLE"
    assert detail.status_code == 200


def test_flashduty_handling_rejects_non_flashduty_alert_without_upstream_call(
    tmp_path: Path,
) -> None:
    client, _, _ = create_test_client(tmp_path)

    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "canonical-1",
                "severity": "WARNING",
                "title": "Database latency",
                "reason": "latency",
            },
        )
        response = client.get(f"/api/v1/alerts/{accepted.json()['alert_id']}/flashduty-handling")

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "FLASHDUTY_HANDLING_NOT_APPLICABLE"


def test_flashduty_handling_reports_missing_configuration(tmp_path: Path) -> None:
    client, runtime, _ = create_test_client(tmp_path)

    with client:
        assert client.portal is not None
        stored, _created = client.portal.call(
            runtime.service.ingest,
            "flashduty",
            flashduty_ingest_payload(),
        )
        response = client.get(f"/api/v1/alerts/{stored.alert.id}/flashduty-handling")

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "FLASHDUTY_NOT_CONFIGURED"
