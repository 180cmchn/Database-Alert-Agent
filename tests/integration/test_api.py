from pathlib import Path

from fastapi.testclient import TestClient

from app.adapters.flashduty import FlashDutyResponse
from app.api.main import create_app
from app.application.factory import Runtime, build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings
from tests.pdf_fixtures import create_tikv_runbook_pdf


def create_test_client(
    tmp_path: Path,
    **setting_overrides: object,
) -> tuple[TestClient, Runtime, ManualAnalysisScheduler]:
    runbooks = tmp_path / "runbooks"
    create_tikv_runbook_pdf(runbooks)
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        runbook_pdf_dir=runbooks,
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
        assert detail_body["status"] == "COMPLETED"
        assert detail_body["alert"]["external_id"] == "api-1"
        assert detail_body["recommendation"]["manual_matched"] is False


def test_unknown_source_and_invalid_payload(tmp_path: Path) -> None:
    client, _, scheduler = create_test_client(tmp_path)
    with client:
        unknown = client.post("/api/v1/alerts/vendor/analyze", json={})
        assert unknown.status_code == 404
        assert unknown.json()["code"] == "UNKNOWN_ALERT_SOURCE"

        invalid = client.post(
            "/api/v1/alerts/canonical/analyze", json={"severity": "WARNING"}
        )
        assert invalid.status_code == 422
        assert invalid.json()["code"] == "INVALID_ALERT_PAYLOAD"
        assert scheduler.jobs == []


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


def test_manual_flashduty_poll_persists_and_enqueues_new_alert(tmp_path: Path) -> None:
    client, runtime, scheduler = create_test_client(
        tmp_path,
        admin_api_token="test-admin-token",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_polling_enabled=False,
        flashduty_poll_channel_ids=[7],
    )
    requests: list[dict] = []

    class RecordingFlashDutyClient:
        async def list_alerts(self, **payload):  # type: ignore[no-untyped-def]
            requests.append(payload)
            return FlashDutyResponse(
                "list-request",
                {
                    "items": [{"alert_id": "663a1b2c3d4e5f6789abcdef"}],
                    "has_next_page": False,
                },
            )

        async def alert_info(self, alert_id: str) -> FlashDutyResponse:
            return FlashDutyResponse(
                "detail-request",
                {
                    "alert_id": alert_id,
                    "title": "Database latency",
                    "description": "Latency is above threshold",
                    "alert_severity": "Warning",
                    "alert_status": "Warning",
                    "alert_key": "database-latency",
                    "start_time": 900,
                    "labels": {"env": "test", "service": "orders-db"},
                },
            )

    runtime.flashduty_client = RecordingFlashDutyClient()  # type: ignore[assignment]
    with client:
        response = client.post(
            "/api/v1/admin/flashduty/poll",
            headers={"Authorization": "Bearer test-admin-token"},
        )

    assert response.status_code == 200
    assert response.json()["new_count"] == 1
    assert len(scheduler.jobs) == 1
    assert requests[0]["by_updated_at"] is True
