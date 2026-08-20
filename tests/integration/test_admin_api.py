from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from app.adapters.ai import OpenAICompatibleAdvisor, OpenAIResponsesAdvisor
from app.adapters.notification import WeComManagementNotifier
from app.agent_runtime import (
    AgentEvent,
    AgentEventKind,
    AgentTraceEmitter,
    AgentTraceScope,
)
from app.agent_runtime.persistence import RepositoryEventSink
from app.api.main import create_app
from app.application.factory import Runtime, build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings

ADMIN_TOKEN = "integration-admin-token"
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def wait_for_run_terminal(
    client: TestClient,
    endpoint: str,
    run_id: str,
    *,
    timeout_seconds: float = 3,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = client.get(endpoint, params={"run_id": run_id})
        assert response.status_code == 200
        body = response.json()
        if body["selected_run"]["status"] != "RUNNING":
            return body
        time.sleep(0.01)
    raise AssertionError(f"run {run_id} did not reach a terminal state")


def create_admin_client(
    tmp_path: Path,
    *,
    admin_token: str = ADMIN_TOKEN,
) -> tuple[TestClient, Runtime]:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        http_scheduler="manual",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'admin.db'}",
        admin_api_token=admin_token,
        runtime_settings_path=tmp_path / "runtime-settings.json",
        external_knowledge_base_url="http://127.0.0.1:8001",
        knowledge_sources=[],
    )
    runtime = build_runtime(settings)
    app = create_app(settings, runtime, ManualAnalysisScheduler())
    return TestClient(app), runtime


def test_admin_auth_reports_unconfigured_and_rejects_bad_token(tmp_path: Path) -> None:
    client, _ = create_admin_client(tmp_path / "unconfigured", admin_token="")
    with client:
        unavailable = client.get("/api/v1/admin/settings")
        assert unavailable.status_code == 503
        assert unavailable.json()["detail"]["code"] == "ADMIN_AUTH_NOT_CONFIGURED"

    configured = tmp_path / "configured"
    configured.mkdir()
    client, _ = create_admin_client(configured)
    with client:
        assert client.get("/api/v1/admin/settings").status_code == 401
        assert (
            client.get(
                "/api/v1/admin/settings",
                headers={"Authorization": "Bearer wrong-token"},
            ).status_code
            == 401
        )
        assert client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).status_code == 200


def test_frontend_origin_is_allowed_by_cors(tmp_path: Path) -> None:
    client, _ = create_admin_client(tmp_path)
    with client:
        response = client.options(
            "/api/v1/alerts",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_runtime_settings_are_dynamic_persisted_and_secrets_are_write_only(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    secret = "ai-key-that-must-never-be-returned"
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        response = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "ai_provider": "openai_compatible",
                "ai_base_url": "https://models.example.test/v1",
                "ai_api_key": secret,
                "ai_model": "example-model-v2",
                "scheduler_workers": 3,
                "analysis_timeout_seconds": 2400,
                "stream_main_agent_reasoning": True,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ai_api_key_configured"] is True
        assert body["ai_model"] == "example-model-v2"
        assert body["scheduler_workers"] == 3
        assert body["analysis_timeout_seconds"] == 2400
        assert body["stream_main_agent_reasoning"] is True
        assert "archery_mcp_max_agent_steps" not in body
        assert body["apply_status"] == "applied"
        assert body["worker_refresh_mode"] == "before_each_batch"
        assert secret not in response.text
        assert "ai_api_key" not in body
        assert "ai_max_retries" not in body

        current = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS)
        assert secret not in current.text

        unchanged = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "ai_model": "example-model-v2",
                "scheduler_workers": 3,
            },
        )
        assert unchanged.status_code == 200
        assert unchanged.json()["changed_fields"] == []
        assert unchanged.json()["revision"] == body["revision"]

        conflict = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={"expected_revision": "0" * 16, "scheduler_workers": 4},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == ("RUNTIME_SETTINGS_REVISION_CONFLICT")

        removed_notifier_fields = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "notifier_mode": "webhook",
                "management_webhook_url": "",
            },
        )
        assert removed_notifier_fields.status_code == 422
        assert removed_notifier_fields.json()["code"] == ("INVALID_RUNTIME_SETTINGS")

        assert isinstance(runtime.service.advisor, OpenAICompatibleAdvisor)
        assert runtime.service.advisor._model == "example-model-v2"
        assert runtime.settings.scheduler_workers == 3
        assert runtime.settings.analysis_timeout_seconds == 2400
        assert runtime.settings.stream_main_agent_reasoning is True
        assert runtime.service.stream_main_agent_reasoning is True
        assert "validation_enabled" not in body

        removed_validator_setting = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "validation_enabled": False,
            },
        )
        assert removed_validator_setting.status_code == 422

        removed_retry_limit = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "ai_max_retries": 3,
            },
        )
        assert removed_retry_limit.status_code == 422

        rejected = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "ai_base_url": "https://user:password@models.example.test/v1",
            },
        )
        assert rejected.status_code == 422
        assert "password" not in rejected.text

        oversized_secret = "secret-value-" * 800
        rejected_secret = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "ai_api_key": oversized_secret,
            },
        )
        assert rejected_secret.status_code == 422
        assert oversized_secret not in rejected_secret.text
        assert rejected_secret.json()["code"] == "INVALID_RUNTIME_SETTINGS"

    settings_path = tmp_path / "runtime-settings.json"
    if os.name != "nt":
        assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
    else:
        # Windows exposes inherited ACLs rather than POSIX owner/group mode bits.
        assert settings_path.is_file()
    persisted = json.loads(settings_path.read_text(encoding="utf-8"))
    assert persisted["ai_api_key"] == secret
    assert persisted["analysis_timeout_seconds"] == 2400
    assert "archery_mcp_max_agent_steps" not in persisted
    audit = (tmp_path / "runtime-settings.audit.jsonl").read_text(encoding="utf-8")
    assert secret not in audit
    assert "ai_api_key" in audit


def test_runtime_settings_switch_to_openai_responses_with_correct_run_metadata(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    secret = "responses-key-that-must-never-be-returned"

    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        response = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "ai_provider": "openai_responses",
                "ai_base_url": "https://api.openai.com/v1",
                "ai_api_key": secret,
                "ai_model": "responses-test-model",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["ai_provider"] == "openai_responses"
        assert body["ai_api_key_configured"] is True
        assert secret not in response.text
        assert isinstance(runtime.service.advisor, OpenAIResponsesAdvisor)

        snapshot = runtime.service._create_config_snapshot()
        manifest = runtime.service._create_run_manifest(UUID(int=0), snapshot)
        assert snapshot.ai_provider == "openai_responses"
        assert snapshot.ai_model == "responses-test-model"
        assert manifest.model_provider == "openai_responses"

        current = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS)
        assert current.status_code == 200
        assert current.json()["ai_provider"] == "openai_responses"
        assert secret not in current.text


def test_wecom_settings_are_write_only_and_apply_notifier(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    wecom_url = (
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=wecom-key-that-must-never-be-returned"
    )
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        # First, enable WeCom notifications and set the webhook URL
        response = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "wecom_enabled": True,
                "wecom_webhook_url": wecom_url,
                "wecom_page_base_url": "https://alerts.intra.example.com",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["wecom_enabled"] is True
        assert body["wecom_webhook_url_configured"] is True
        assert body["wecom_page_base_url"] == "https://alerts.intra.example.com"
        assert "wecom_webhook_url" not in body
        assert wecom_url not in response.text
        assert isinstance(runtime.service.notifier, WeComManagementNotifier)

        current = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS)
        assert current.status_code == 200
        assert current.json()["wecom_webhook_url_configured"] is True
        assert wecom_url not in current.text

    persisted = (tmp_path / "runtime-settings.json").read_text(encoding="utf-8")
    assert wecom_url in persisted
    assert "https://alerts.intra.example.com" in persisted
    audit = (tmp_path / "runtime-settings.audit.jsonl").read_text(encoding="utf-8")
    assert wecom_url not in audit


def test_runtime_settings_persist_polling_knowledge_selection_and_bound_key(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        response = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "flashduty_polling_enabled": True,
                "flashduty_poll_interval_seconds": 600,
                "flashduty_poll_lookback_seconds": 1200,
                "scheduler_workers": 4,
                "external_knowledge_api_key": "test-knowledge-key",
                "knowledge_sources": ["external_knowledge"],
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["flashduty_polling_enabled"] is True
    assert body["flashduty_poll_interval_seconds"] == 600
    assert body["flashduty_poll_lookback_seconds"] == 1200
    assert body["scheduler_workers"] == 4
    assert body["external_knowledge_enabled"] is True
    assert body["external_knowledge_base_url"] == "http://127.0.0.1:8001"
    assert body["external_knowledge_api_key_configured"] is True
    assert body["knowledge_sources"] == ["external_knowledge"]
    assert set(body["changed_fields"]) == {
        "external_knowledge_api_key",
        "external_knowledge_api_key_base_url",
        "flashduty_poll_interval_seconds",
        "flashduty_poll_lookback_seconds",
        "flashduty_polling_enabled",
        "knowledge_sources",
        "scheduler_workers",
    }
    assert runtime.settings.flashduty_polling_enabled is True
    assert runtime.settings.scheduler_workers == 4
    assert runtime.settings.external_knowledge_enabled is True
    assert runtime.service.knowledge_registry.names() == ["external_knowledge"]

    persisted = json.loads((tmp_path / "runtime-settings.json").read_text(encoding="utf-8"))
    assert persisted["flashduty_polling_enabled"] is True
    assert persisted["flashduty_poll_interval_seconds"] == 600
    assert persisted["flashduty_poll_lookback_seconds"] == 1200
    assert persisted["scheduler_workers"] == 4
    assert "external_knowledge_enabled" not in persisted
    assert "external_knowledge_base_url" not in persisted
    assert persisted["external_knowledge_api_key"] == "test-knowledge-key"
    assert persisted["external_knowledge_api_key_base_url"] == "http://127.0.0.1:8001"
    assert persisted["knowledge_sources"] == ["external_knowledge"]


def test_runtime_knowledge_selection_disables_external_client(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        enabled = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "knowledge_sources": ["external_knowledge"],
            },
        )
        assert enabled.status_code == 200
        assert enabled.json()["external_knowledge_enabled"] is True
        assert runtime.service.knowledge_registry.names() == ["external_knowledge"]

        disabled = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": enabled.json()["revision"],
                "knowledge_sources": [],
            },
        )

    assert disabled.status_code == 200
    assert disabled.json()["external_knowledge_enabled"] is False
    assert disabled.json()["knowledge_sources"] == []
    assert runtime.settings.external_knowledge_enabled is False
    assert runtime.service.knowledge_registry.names() == []

    persisted = json.loads((tmp_path / "runtime-settings.json").read_text(encoding="utf-8"))
    assert persisted["knowledge_sources"] == []
    assert "external_knowledge_enabled" not in persisted


def test_reset_runtime_settings_clears_overrides_back_to_env_baseline(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        patched = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "ai_model": "override-model",
                "scheduler_workers": 2,
                "stream_main_agent_reasoning": True,
            },
        )
        assert patched.status_code == 200
        body = patched.json()
        assert body["ai_model"] == "override-model"
        assert body["scheduler_workers"] == 2
        assert body["stream_main_agent_reasoning"] is True

        reset = client.delete(
            "/api/v1/admin/settings/runtime-overrides",
            headers=ADMIN_HEADERS,
            params={"expected_revision": body["revision"]},
        )
        assert reset.status_code == 200
        reset_body = reset.json()
        # Defaults come from the Settings() built in create_admin_client.
        assert reset_body["ai_model"] == ""
        assert reset_body["scheduler_workers"] == 1
        assert reset_body["stream_main_agent_reasoning"] is False

        persisted = json.loads((tmp_path / "runtime-settings.json").read_text(encoding="utf-8"))
        assert persisted == {}

        conflict = client.delete(
            "/api/v1/admin/settings/runtime-overrides",
            headers=ADMIN_HEADERS,
            params={"expected_revision": "0" * 16},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "RUNTIME_SETTINGS_REVISION_CONFLICT"

        audit = (tmp_path / "runtime-settings.audit.jsonl").read_text(encoding="utf-8")
        assert '"action": "reset"' in audit


def test_alert_list_filters_paginates_and_dashboard_summarizes(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        payloads = [
            {
                "external_id": "list-info",
                "severity": "INFO",
                "title": "Reporting replica latency",
                "reason": "latency",
                "environment": "test",
                "service_name": "reporting-api",
            },
            {
                "external_id": "list-warning",
                "severity": "WARNING",
                "title": "Orders connection usage",
                "reason": "connection_exhausted",
                "environment": "prd",
                "service_name": "orders-api",
            },
            {
                "external_id": "list-critical",
                "severity": "CRITICAL",
                "title": "Payments unavailable",
                "reason": "availability",
                "environment": "production",
                "service_name": "payments-api",
            },
        ]
        accepted = [
            client.post("/api/v1/alerts/canonical/analyze", json=payload).json()
            for payload in payloads
        ]
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, accepted[0]["alert_id"])

        first_page = client.get("/api/v1/alerts?page=1&page_size=2").json()
        assert first_page["total"] == 3
        assert first_page["pages"] == 2
        assert len(first_page["items"]) == 2

        filtered = client.get(
            "/api/v1/alerts",
            params={
                "status": "QUEUED",
                "severity": "WARNING",
                "environment": "production",
                "search": "orders",
            },
        ).json()
        assert filtered["total"] == 1
        assert filtered["items"][0]["external_id"] == "list-warning"

        inconclusive = client.get("/api/v1/alerts", params={"status": "INCONCLUSIVE"}).json()
        assert inconclusive["total"] == 1
        assert inconclusive["items"][0]["external_id"] == "list-info"

        dashboard = client.get("/api/v1/dashboard/summary").json()
        assert dashboard["total"] == 3
        assert dashboard["active"] == 2
        assert dashboard["critical_open"] == 1
        assert dashboard["by_status"]["QUEUED"] == 2
        assert dashboard["by_status"]["INCONCLUSIVE"] == 1


def test_each_reanalysis_keeps_its_own_detail_result(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "run-history-results-1",
                "severity": "CRITICAL",
                "title": "Synthetic replica lag alert",
                "reason": "replica_lag",
                "environment": "test",
                "service_name": "orders-api",
                "database": {"engine": "TiDB"},
            },
        )
        assert accepted.status_code == 202
        alert_id = accepted.json()["alert_id"]
        endpoint = f"/api/v1/alerts/{alert_id}"
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, alert_id)

        first = client.get(endpoint).json()
        first_run_id = first["latest_run"]["id"]
        assert first["selected_run"]["id"] == first_run_id
        assert first["recommendation"]["knowledge_matches"] == []

        runtime.service.knowledge_sources = []
        reanalyzed = client.post(
            f"{endpoint}/reanalyze",
            headers=ADMIN_HEADERS,
            json={"force": False},
        )
        assert reanalyzed.status_code == 202
        second_run_id = reanalyzed.json()["run_id"]

        latest = wait_for_run_terminal(client, endpoint, second_run_id)
        assert latest["latest_run"]["id"] == second_run_id
        assert latest["selected_run"]["id"] == second_run_id
        assert latest["recommendation"]["knowledge_matches"] == []

        historical = client.get(endpoint, params={"run_id": first_run_id})
        assert historical.status_code == 200
        history_body = historical.json()
        assert history_body["latest_run"]["id"] == second_run_id
        assert history_body["selected_run"]["id"] == first_run_id
        assert history_body["selected_run_result_available"] is True
        assert history_body["recommendation"]["knowledge_matches"] == []
        assert all(item["run_id"] == first_run_id for item in history_body["progress"])
        assert all(item["run_id"] == first_run_id for item in history_body["evidence_records"])
        assert all(item["run_id"] == first_run_id for item in history_body["validations"])


def test_agent_trace_api_is_incremental_and_excludes_internal_audit_events(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "trace-api-1",
                "severity": "WARNING",
                "title": "Trace API",
                "reason": "trace_test",
            },
        ).json()
        alert_id = accepted["alert_id"]
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, alert_id)
        detail = client.get(f"/api/v1/alerts/{alert_id}").json()
        run_id = detail["latest_run"]["id"]
        endpoint = f"/api/v1/alerts/{alert_id}/runs/{run_id}/trace"
        existing = client.get(endpoint)
        assert existing.status_code == 200
        baseline_sequence = existing.json()["next_sequence"]
        sink = RepositoryEventSink(runtime.repository)
        emitter = AgentTraceEmitter(
            sink,
            run_id=UUID(run_id),
            actor="main-agent",
            provider="test-provider",
            scope=AgentTraceScope.MAIN_AGENT,
        )
        client.portal.call(emitter.emit_reasoning, "real provider reasoning")
        client.portal.call(
            sink.append,
            AgentEvent(run_id=UUID(run_id), kind=AgentEventKind.CHECKPOINT_SAVED),
        )
        client.portal.call(emitter.emit_action, "call_tool metrics.query")
        internal_emitter = AgentTraceEmitter(
            sink,
            run_id=UUID(run_id),
            actor="archery_mcp_agent",
            provider="archery",
            scope=AgentTraceScope.MCP_INTERNAL,
        )
        client.portal.call(internal_emitter.emit_reasoning, "internal MCP reasoning")

        first = client.get(
            endpoint,
            params={"after_sequence": baseline_sequence, "limit": 2},
        )
        assert first.status_code == 200
        body = first.json()
        assert [item["kind"] for item in body["items"]] == ["REASONING"]
        assert body["items"][0]["content"] == "real provider reasoning"
        assert body["items"][0]["actor"] == "main-agent"
        assert body["items"][0]["scope"] == "main_agent"
        assert body["next_sequence"] == baseline_sequence + 2
        assert body["has_more"] is True

        second = client.get(
            endpoint,
            params={"after_sequence": body["next_sequence"], "limit": 1},
        )
        assert second.status_code == 200
        second_body = second.json()
        assert [item["kind"] for item in second_body["items"]] == ["ACTION"]
        assert second_body["items"][0]["scope"] == "main_agent"
        assert second_body["next_sequence"] == baseline_sequence + 3
        assert second_body["has_more"] is True

        internal = client.get(
            endpoint,
            params={"after_sequence": second_body["next_sequence"], "limit": 2},
        )
        assert internal.status_code == 200
        internal_body = internal.json()
        assert [item["kind"] for item in internal_body["items"]] == ["REASONING"]
        assert internal_body["items"][0]["scope"] == "mcp_internal"
        assert internal_body["items"][0]["content"] == "internal MCP reasoning"
        assert internal_body["has_more"] is False

        empty_tail = client.get(
            endpoint,
            params={"after_sequence": internal_body["next_sequence"]},
        )
        assert empty_tail.status_code == 200
        assert empty_tail.json()["items"] == []
        assert empty_tail.json()["next_sequence"] == baseline_sequence + 4
        assert empty_tail.json()["has_more"] is False

        wrong_alert = client.get(
            f"/api/v1/alerts/00000000-0000-0000-0000-000000000000/runs/{run_id}/trace"
        )
        assert wrong_alert.status_code == 404

        missing_run = client.get(
            f"/api/v1/alerts/{alert_id}/runs/00000000-0000-0000-0000-000000000000/trace",
        )
        assert missing_run.status_code == 404


def test_cancel_run_api_requires_admin_and_enforces_run_state(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "cancel-api-1",
                "severity": "WARNING",
                "title": "Cancel API",
                "reason": "cancel_test",
            },
        ).json()
        alert_id = accepted["alert_id"]
        assert client.portal is not None
        run = client.portal.call(
            runtime.repository.create_run,
            alert_id,
            "cancel-api-worker",
            300,
        )
        assert run is not None
        endpoint = f"/api/v1/alerts/{alert_id}/runs/{run.id}/cancel"

        assert client.post(endpoint).status_code == 401
        accepted_cancel = client.post(endpoint, headers=ADMIN_HEADERS)
        assert accepted_cancel.status_code == 202
        body = accepted_cancel.json()
        assert body["alert_id"] == alert_id
        assert body["run_id"] == str(run.id)
        assert body["status"] == "RUNNING"
        assert body["cancel_requested_at"]

        repeated = client.post(endpoint, headers=ADMIN_HEADERS)
        assert repeated.status_code == 202
        assert repeated.json()["cancel_requested_at"] == body["cancel_requested_at"]

        wrong_alert = client.post(
            f"/api/v1/alerts/00000000-0000-0000-0000-000000000000/runs/{run.id}/cancel",
            headers=ADMIN_HEADERS,
        )
        assert wrong_alert.status_code == 404

        finished = client.portal.call(
            runtime.repository.finalize_requested_cancellation,
            alert_id,
            str(run.id),
        )
        assert finished is not None
        assert finished.status.value == "CANCELLED"
        repeated_terminal = client.post(endpoint, headers=ADMIN_HEADERS)
        assert repeated_terminal.status_code == 202
        assert repeated_terminal.json()["status"] == "CANCELLED"


def test_cancel_run_api_rejects_non_cancelled_terminal_run(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "cancel-api-terminal",
                "severity": "WARNING",
                "title": "Cancel terminal API",
                "reason": "cancel_test",
            },
        ).json()
        alert_id = accepted["alert_id"]
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, alert_id)
        detail = client.get(f"/api/v1/alerts/{alert_id}").json()
        run_id = detail["latest_run"]["id"]

        conflict = client.post(
            f"/api/v1/alerts/{alert_id}/runs/{run_id}/cancel",
            headers=ADMIN_HEADERS,
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "RUN_CANCELLATION_CONFLICT"
