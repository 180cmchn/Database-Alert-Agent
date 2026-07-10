from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.application.factory import build_runtime
from app.config import Settings


def create_test_client(tmp_path: Path) -> TestClient:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(exist_ok=True)
    settings = Settings(
        ai_provider="fake",
        notifier_mode="log",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        runbook_dir=runbooks,
        notification_retry_backoff_seconds=0,
    )
    return TestClient(create_app(settings, build_runtime(settings)))


def test_analyze_and_get_alert(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "api-1",
                "severity": "HIGH",
                "title": "Database latency",
                "reason": "latency",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "COMPLETED"
        assert body["recommendation"]["manual_matched"] is False

        detail = client.get(f"/api/v1/alerts/{body['alert']['id']}")
        assert detail.status_code == 200
        assert detail.json()["alert"]["external_id"] == "api-1"


def test_unknown_source_and_invalid_payload(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        unknown = client.post("/api/v1/alerts/vendor/analyze", json={})
        assert unknown.status_code == 404
        assert unknown.json()["code"] == "UNKNOWN_ALERT_SOURCE"

        invalid = client.post(
            "/api/v1/alerts/canonical/analyze", json={"severity": "HIGH"}
        )
        assert invalid.status_code == 422
        assert invalid.json()["code"] == "INVALID_ALERT_PAYLOAD"


def test_readiness_reports_configuration(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "issues": []}
