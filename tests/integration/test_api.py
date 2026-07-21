from pathlib import Path
from shutil import copy2

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.application.factory import Runtime, build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings

SOURCE_PDF = (
    Path(__file__).parents[2]
    / "runbooks"
    / "pdfs"
    / "INFRA-2025-07-03TiDB--TiKV_server_report_failure_msg_total-210726-1007-4073.pdf"
)


def create_test_client(
    tmp_path: Path,
) -> tuple[TestClient, Runtime, ManualAnalysisScheduler]:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(exist_ok=True)
    copy2(SOURCE_PDF, runbooks / SOURCE_PDF.name)
    settings = Settings(
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        runbook_pdf_dir=runbooks,
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


def test_readiness_reports_configuration(tmp_path: Path) -> None:
    client, _, _ = create_test_client(tmp_path)
    with client:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "issues": []}
