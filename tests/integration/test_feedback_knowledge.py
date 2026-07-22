from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.application.factory import build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings


def test_confirmed_feedback_becomes_candidate_but_live_check_still_runs(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        http_scheduler="manual",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'feedback.db'}",
        runbook_pdf_dir=runbooks,
        admin_api_token="test-admin-token",
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )
    runtime = build_runtime(settings)
    scheduler = ManualAnalysisScheduler()
    app = create_app(settings, runtime, scheduler)

    with TestClient(app) as client:
        base_payload = {
            "severity": "WARNING",
            "title": "Orders latency reached 123ms",
            "description": "Orders latency reached 123ms",
            "reason": "latency",
            "environment": "prd",
            "service_name": "orders-api",
        }
        first = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={**base_payload, "external_id": "feedback-event-1"},
        ).json()
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, first["alert_id"])
        first_detail = client.get(first["detail_url"]).json()
        evidence_id = first_detail["evidence_records"][0]["id"]

        feedback = client.post(
            f"/api/v1/alerts/{first['alert_id']}/feedback",
            headers={"Authorization": "Bearer test-admin-token"},
            json={
                "idempotency_key": "feedback-1",
                "verdict": "CONFIRMED",
                "reviewer": "test-dba",
                "final_root_cause": "上游延迟抖动",
                "actual_resolution": "上游恢复后告警解除",
                "recovered": True,
                "runbook_match_verdict": "NOT_APPLICABLE",
                "supporting_evidence_ids": [evidence_id],
                "wrong_agent_claims": ["把告警字段直接当成已确认根因"],
                "accepted_step_orders": [1],
            },
        )
        assert feedback.status_code == 201
        assert feedback.json()["runbook_match_verdict"] == "NOT_APPLICABLE"
        assert feedback.json()["supporting_evidence_ids"] == [evidence_id]
        duplicate = client.post(
            f"/api/v1/alerts/{first['alert_id']}/feedback",
            headers={"Authorization": "Bearer test-admin-token"},
            json={
                "idempotency_key": "feedback-1",
                "verdict": "CONFIRMED",
                "reviewer": "test-dba",
                "final_root_cause": "上游延迟抖动",
                "actual_resolution": "上游恢复后告警解除",
                "recovered": True,
            },
        )
        assert duplicate.json()["id"] == feedback.json()["id"]

        second = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                **base_payload,
                "external_id": "feedback-event-2",
                "title": "Orders latency reached 456ms",
                "description": "Orders latency reached 456ms",
            },
        ).json()
        client.portal.call(runtime.service.analyze_by_id, second["alert_id"])
        detail = client.get(second["detail_url"]).json()

        assert len(detail["knowledge_matches"]) == 1
        assert detail["knowledge_matches"][0]["final_root_cause"] == "上游延迟抖动"
        assert detail["knowledge_matches"][0]["supporting_evidence_ids"] == [
            evidence_id
        ]
        assert any(
            item["tool_name"] == "alert_context"
            and item["status"] == "SUCCESS"
            for item in detail["evidence_records"]
        )
