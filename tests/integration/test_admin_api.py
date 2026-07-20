from __future__ import annotations

import json
import stat
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.adapters.ai import OpenAICompatibleAdvisor
from app.adapters.notification import WeComManagementNotifier
from app.adapters.runbook_store import LocalMarkdownRunbookStore
from app.adapters.web_runbooks import AuthenticatedWebRunbookProvider
from app.api.main import create_app
from app.application.factory import Runtime, build_runtime
from app.application.scheduler import ManualAnalysisScheduler
from app.config import Settings

ADMIN_TOKEN = "integration-admin-token"
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def create_admin_client(
    tmp_path: Path,
    *,
    admin_token: str = ADMIN_TOKEN,
    runbook_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[TestClient, Runtime]:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        ai_provider="fake",
        notifier_mode="log",
        http_scheduler="manual",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'admin.db'}",
        runbook_dir=runbooks,
        admin_api_token=admin_token,
        runtime_settings_path=tmp_path / "runtime-settings.json",
        notification_retry_backoff_seconds=0,
    )
    runtime = None
    if runbook_transport is not None:
        runtime = build_runtime(
            settings,
            runbook_provider=AuthenticatedWebRunbookProvider(
                runbooks,
                allowed_hosts=["wiki.corp.example"],
                auth_mode="cookie",
                auth_secret="company_session=authenticated",
                transport=runbook_transport,
            ),
            runbook_store=LocalMarkdownRunbookStore(runbooks),
        )
    else:
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


def test_admin_can_acknowledge_routed_incident(tmp_path: Path) -> None:
    client, _ = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "admin-ack-1",
                "severity": "CRITICAL",
                "title": "Critical database alert",
                "reason": "availability",
            },
        ).json()
        incident = client.get(
            f"/api/v1/alerts/{accepted['alert_id']}/incident"
        ).json()
        response = client.post(
            f"/api/v1/admin/incidents/{incident['id']}/ack",
            headers=ADMIN_HEADERS,
            json={"actor": "dba-operator"},
        )
        assert response.status_code == 200
        assert response.json()["state"] == "ACKNOWLEDGED"
        assert response.json()["acknowledged_by"] == "dba-operator"


def test_runtime_settings_are_dynamic_persisted_and_secrets_are_write_only(
    tmp_path: Path,
) -> None:
    client, runtime = create_admin_client(tmp_path)
    secret = "ai-key-that-must-never-be-returned"
    webhook_secret = "webhook-token-that-must-never-be-returned"
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
                "management_webhook_bearer_token": webhook_secret,
                "runbook_limit": 7,
                "validation_enabled": False,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ai_api_key_configured"] is True
        assert body["management_webhook_bearer_token_configured"] is True
        assert body["ai_model"] == "example-model-v2"
        assert body["runbook_limit"] == 7
        assert body["apply_status"] == "applied"
        assert body["worker_refresh_mode"] == "before_each_job"
        assert secret not in response.text
        assert webhook_secret not in response.text
        assert "ai_api_key" not in body
        assert "management_webhook_bearer_token" not in body

        current = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS)
        assert secret not in current.text
        assert webhook_secret not in current.text

        unchanged = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "ai_model": "example-model-v2",
                "runbook_limit": 7,
            },
        )
        assert unchanged.status_code == 200
        assert unchanged.json()["changed_fields"] == []
        assert unchanged.json()["revision"] == body["revision"]

        conflict = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={"expected_revision": "0" * 16, "runbook_limit": 8},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == (
            "RUNTIME_SETTINGS_REVISION_CONFLICT"
        )

        unusable_notifier = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": body["revision"],
                "notifier_mode": "webhook",
                "management_webhook_url": "",
            },
        )
        assert unusable_notifier.status_code == 422
        assert unusable_notifier.json()["detail"]["code"] == (
            "INVALID_RUNTIME_SETTINGS"
        )

        assert isinstance(runtime.service.advisor, OpenAICompatibleAdvisor)
        assert runtime.service.advisor._model == "example-model-v2"
        assert runtime.service.runbook_limit == 7
        assert runtime.service.validation_enabled is False

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
    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
    persisted = json.loads(settings_path.read_text(encoding="utf-8"))
    assert persisted["ai_api_key"] == secret
    audit = (tmp_path / "runtime-settings.audit.jsonl").read_text(encoding="utf-8")
    assert secret not in audit
    assert webhook_secret not in audit
    assert "ai_api_key" in audit


def test_wecom_settings_are_write_only_and_apply_notifier(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    wecom_url = (
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key="
        "wecom-key-that-must-never-be-returned"
    )
    with client:
        initial = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS).json()
        response = client.patch(
            "/api/v1/admin/settings",
            headers=ADMIN_HEADERS,
            json={
                "expected_revision": initial["revision"],
                "notifier_mode": "wecom",
                "wecom_webhook_url": wecom_url,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["notifier_mode"] == "wecom"
        assert body["wecom_webhook_url_configured"] is True
        assert "wecom_webhook_url" not in body
        assert wecom_url not in response.text
        assert isinstance(runtime.service.notifier, WeComManagementNotifier)

        current = client.get("/api/v1/admin/settings", headers=ADMIN_HEADERS)
        assert current.status_code == 200
        assert current.json()["wecom_webhook_url_configured"] is True
        assert wecom_url not in current.text

    persisted = (tmp_path / "runtime-settings.json").read_text(encoding="utf-8")
    assert wecom_url in persisted
    audit = (tmp_path / "runtime-settings.audit.jsonl").read_text(encoding="utf-8")
    assert wecom_url not in audit


def test_runbook_crud_uses_safe_ids_and_optimistic_versions(tmp_path: Path) -> None:
    client, _ = create_admin_client(tmp_path)
    create_payload = {
        "id": "connection-limit",
        "title": "连接数告警手册",
        "section": "triage",
        "reasons": ["connection_exhausted"],
        "keywords": ["连接数"],
        "severities": ["WARNING", "CRITICAL"],
        "labels": {"team": "dba"},
        "content": "1. 只读检查当前连接数。",
        "metadata": {
            "owner": "database-team",
            "source_url": "https://wiki.corp.example/runbooks/connection-limit",
        },
    }
    with client:
        missing_source = client.post(
            "/api/v1/admin/runbooks",
            headers=ADMIN_HEADERS,
            json={**create_payload, "metadata": {"owner": "database-team"}},
        )
        assert missing_source.status_code == 422
        assert "source_url" in missing_source.text
        assert (
            client.post(
                "/api/v1/admin/runbooks",
                headers=ADMIN_HEADERS,
                json={**create_payload, "id": "../escape"},
            ).status_code
            == 422
        )
        created = client.post(
            "/api/v1/admin/runbooks", headers=ADMIN_HEADERS, json=create_payload
        )
        assert created.status_code == 201
        assert created.json()["version"] == 1

        listed = client.get("/api/v1/admin/runbooks", headers=ADMIN_HEADERS).json()
        assert listed["total"] == 1
        assert listed["items"][0]["id"] == "connection-limit"

        update_payload = {
            key: value for key, value in create_payload.items() if key != "id"
        }
        update_payload["content"] = "1. 只读检查当前和最大连接数。"
        update_payload["expected_version"] = 1
        updated = client.put(
            "/api/v1/admin/runbooks/connection-limit",
            headers=ADMIN_HEADERS,
            json=update_payload,
        )
        assert updated.status_code == 200
        assert updated.json()["version"] == 2

        stale = client.put(
            "/api/v1/admin/runbooks/connection-limit",
            headers=ADMIN_HEADERS,
            json=update_payload,
        )
        assert stale.status_code == 409

        deleted = client.delete(
            "/api/v1/admin/runbooks/connection-limit", headers=ADMIN_HEADERS
        )
        assert deleted.status_code == 204
        assert (
            client.get(
                "/api/v1/admin/runbooks/connection-limit", headers=ADMIN_HEADERS
            ).status_code
            == 404
        )
    assert not (tmp_path / "escape.md").exists()


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

        completed = client.get(
            "/api/v1/alerts", params={"status": "COMPLETED"}
        ).json()
        assert completed["total"] == 1
        assert completed["items"][0]["external_id"] == "list-info"

        dashboard = client.get("/api/v1/dashboard/summary").json()
        assert dashboard["total"] == 3
        assert dashboard["active"] == 2
        assert dashboard["critical_open"] == 1
        assert dashboard["by_status"]["QUEUED"] == 2
        assert dashboard["by_status"]["COMPLETED"] == 1


def test_feedback_requires_admin_and_uses_authenticated_actor(tmp_path: Path) -> None:
    client, runtime = create_admin_client(tmp_path)
    with client:
        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "feedback-auth",
                "severity": "INFO",
                "title": "Latency",
                "reason": "latency",
            },
        ).json()
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, accepted["alert_id"])
        payload = {
            "idempotency_key": "feedback-auth-1",
            "verdict": "REJECTED",
            "reviewer": "forged-reviewer",
        }
        endpoint = f"/api/v1/alerts/{accepted['alert_id']}/feedback"
        assert client.post(endpoint, json=payload).status_code == 401
        saved = client.post(endpoint, headers=ADMIN_HEADERS, json=payload)
        assert saved.status_code == 201
        assert saved.json()["reviewer"] == "admin"


def test_admin_created_runbook_is_used_by_the_visible_investigation_flow(
    tmp_path: Path,
) -> None:
    def runbook_page(request: httpx.Request) -> httpx.Response:
        assert request.headers["cookie"] == "company_session=authenticated"
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<main id='article-content'>通过只读监控确认延迟趋势。</main>",
        )

    client, runtime = create_admin_client(
        tmp_path, runbook_transport=httpx.MockTransport(runbook_page)
    )
    with client:
        runbook = client.post(
            "/api/v1/admin/runbooks",
            headers=ADMIN_HEADERS,
            json={
                "id": "latency-triage",
                "title": "数据库延迟排查手册",
                "section": "read-only-triage",
                "reasons": ["latency"],
                "keywords": ["延迟", "latency"],
                "severities": ["WARNING"],
                "labels": {},
                "content": "本地仅保存索引备注。",
                "metadata": {
                    "source_url": "https://wiki.corp.example/runbooks/latency",
                    "content_selector": "#article-content",
                },
            },
        )
        assert runbook.status_code == 201

        accepted = client.post(
            "/api/v1/alerts/canonical/analyze",
            json={
                "external_id": "console-flow-1",
                "severity": "WARNING",
                "title": "数据库延迟升高",
                "reason": "latency",
                "environment": "test",
                "service_name": "orders-api",
            },
        )
        assert accepted.status_code == 202
        alert_id = accepted.json()["alert_id"]
        assert client.portal is not None
        client.portal.call(runtime.service.analyze_by_id, alert_id)

        detail = client.get(f"/api/v1/alerts/{alert_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["status"] == "COMPLETED"
        assert body["manual_matches"][0]["runbook_id"] == "latency-triage"
        assert body["recommendation"]["manual_matched"] is True
        assert body["recommendation"]["steps"][0]["source_ref"] == {
            "runbook_id": "latency-triage",
            "section": "read-only-triage",
        }
        assert [item["stage"] for item in body["progress"]] == [
            "RECEIVED",
            "FINGERPRINTING",
            "KNOWLEDGE_MATCHING",
            "RUNBOOK_MATCHING",
            "INVESTIGATING",
            "ADVISING",
            "VALIDATING",
            "REPORTING",
            "COMPLETED",
        ]
