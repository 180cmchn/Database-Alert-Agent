from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.notification import WebhookManagementNotifier
from app.domain.models import NotificationEvent
from tools.qq_mail_relay.formatter import build_email
from tools.qq_mail_relay.mailer import MailDeliveryError, QQSMTPMailer
from tools.qq_mail_relay.main import create_app
from tools.qq_mail_relay.settings import RelaySettings
from tools.qq_mail_relay.storage import SQLiteDeliveryStore

TOKEN = "relay-test-token-that-is-at-least-32-characters"


class RecordingMailer:
    def __init__(self, *, fail: bool = False) -> None:
        self.messages: list[EmailMessage] = []
        self.fail = fail

    async def send(self, message: EmailMessage) -> None:
        self.messages.append(message)
        if self.fail:
            raise MailDeliveryError("simulated SMTP failure")


class FakeSMTPClient:
    def __init__(self) -> None:
        self.actions: list[Any] = []

    def __enter__(self) -> FakeSMTPClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def ehlo(self) -> None:
        self.actions.append("ehlo")

    def starttls(self, *, context: object) -> None:
        self.actions.append(("starttls", context))

    def login(self, username: str, password: str) -> None:
        self.actions.append(("login", username, password))

    def send_message(
        self,
        message: EmailMessage,
        *,
        from_addr: str,
        to_addrs: list[str],
    ) -> None:
        self.actions.append(("send", message, from_addr, to_addrs))


def settings_for(tmp_path: Path, **updates: object) -> RelaySettings:
    values: dict[str, object] = {
        "bearer_token": TOKEN,
        "dry_run": True,
        "mail_from": "sender@qq.com",
        "mail_to": "recipient@qq.com",
        "database_path": tmp_path / "relay.db",
    }
    values.update(updates)
    return RelaySettings(**values)


def event_payload(phase: str = "ADVICE_READY") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "phase": phase,
        "alert": {
            "id": "11111111-1111-4111-8111-111111111111",
            "external_id": "qq-mail-relay-test-001",
            "source": "canonical",
            "raw_severity": "P0",
            "severity": "CRITICAL",
            "environment": "test",
            "service_name": "orders-db",
            "title": "复制延迟\r\n伪造标题",
            "reason": "replication_lag_high",
            "description": "延迟 180 秒，password=super-secret",
            "database": {
                "engine": "postgresql",
                "instance": "orders-replica-01",
                "database": "orders",
            },
            "raw_payload": {"api_token": "must-not-appear"},
        },
        "message": "调查完成，请人工复核。",
    }
    if phase == "ADVICE_READY":
        payload["recommendation"] = {
            "summary": "只读确认复制延迟趋势。",
            "likely_causes": ["副本回放速率低于日志生成速率"],
            "evidence": ["replication_lag_seconds=180"],
            "steps": [
                {
                    "order": 1,
                    "action": "检查复制延迟曲线",
                    "expected_result": "确认延迟是否持续增长",
                    "caution": "不要执行写操作",
                    "source_ref": {
                        "runbook_id": "qq-trial-replication-lag",
                        "section": "readonly-triage",
                    },
                }
            ],
            "risks": ["数据读取时效降低"],
            "requires_human": True,
            "confidence": 0.88,
            "manual_matched": True,
            "runbook_references": [
                {
                    "runbook_id": "qq-trial-replication-lag",
                    "section": "readonly-triage",
                }
            ],
        }
    return payload


def authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def test_relay_secret_env_is_excluded_from_docker_build_context() -> None:
    project_root = Path(__file__).resolve().parents[2]
    patterns = {
        line.strip()
        for line in (project_root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "**/.env" in patterns
    assert "tools/qq_mail_relay/.env" in patterns


def test_api_auth_plain_text_and_sqlite_success_deduplication(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    first_mailer = RecordingMailer()

    with TestClient(create_app(settings, mailer=first_mailer)) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").status_code == 200
        assert client.post("/api/v1/notifications", json=event_payload()).status_code == 401

        first = client.post(
            "/api/v1/notifications",
            json=event_payload(),
            headers=authorization(),
        )
        assert first.status_code == 200
        assert first.json()["errcode"] == 0
        assert first.json()["duplicate"] is False
        delivery_id = first.headers["X-Delivery-Id"]

    assert len(first_mailer.messages) == 1
    message = first_mailer.messages[0]
    assert message.get_content_type() == "text/plain"
    assert message.get_content_charset() == "utf-8"
    assert "\n" not in str(message["Subject"])
    body = message.get_content()
    assert "qq-trial-replication-lag / readonly-triage" in body
    assert "password=***REDACTED***" in body
    assert "super-secret" not in body
    assert "must-not-appear" not in body

    # A new application instance proves the successful key is persisted in SQLite,
    # not only retained in the process lock or memory.
    second_mailer = RecordingMailer()
    with TestClient(create_app(settings, mailer=second_mailer)) as client:
        duplicate = client.post(
            "/api/v1/notifications",
            json=event_payload(),
            headers=authorization(),
        )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.headers["X-Delivery-Id"] == delivery_id
    assert second_mailer.messages == []


def test_not_ready_and_failed_delivery_are_not_recorded(tmp_path: Path) -> None:
    not_ready = settings_for(tmp_path, bearer_token="short")
    with TestClient(create_app(not_ready, mailer=RecordingMailer())) as client:
        assert client.get("/health/ready").status_code == 503

    settings = settings_for(tmp_path, database_path=tmp_path / "failed.db")
    failing_mailer = RecordingMailer(fail=True)
    with TestClient(create_app(settings, mailer=failing_mailer)) as client:
        first = client.post(
            "/api/v1/notifications",
            json=event_payload("INITIAL_ALERT"),
            headers=authorization(),
        )
        second = client.post(
            "/api/v1/notifications",
            json=event_payload("INITIAL_ALERT"),
            headers=authorization(),
        )
    assert first.status_code == 502
    assert first.json() == {"detail": "SMTP delivery failed"}
    assert second.status_code == 502
    assert len(failing_mailer.messages) == 2


@pytest.mark.asyncio
async def test_generic_webhook_notifier_delivers_to_relay_contract(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    store = SQLiteDeliveryStore(settings.database_path)
    await store.initialize()
    mailer = RecordingMailer()
    relay_app = create_app(settings, store=store, mailer=mailer)
    notifier = WebhookManagementNotifier(
        "http://qq-mail-relay.test/api/v1/notifications",
        TOKEN,
        transport=httpx.ASGITransport(app=relay_app),
    )

    delivery_id = await notifier.send(
        NotificationEvent.model_validate(event_payload("INITIAL_ALERT"))
    )

    assert delivery_id is not None
    assert delivery_id.startswith("qqmail-")
    assert len(mailer.messages) == 1
    assert "INITIAL_ALERT" in mailer.messages[0].get_content()


@pytest.mark.asyncio
async def test_smtp_ssl_uses_authorization_code_and_fixed_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(
        tmp_path,
        dry_run=False,
        smtp_username="sender@qq.com",
        smtp_auth_code="qq-smtp-authorization-code",
        smtp_security="ssl",
        smtp_port=465,
    )
    event = NotificationEvent.model_validate(event_payload())
    message = build_email(event, settings, "qqmail-test")
    fake_client = FakeSMTPClient()
    tls_context = object()
    connection: dict[str, object] = {}

    def smtp_ssl_factory(
        host: str, port: int, *, timeout: float, context: object
    ) -> FakeSMTPClient:
        connection.update(host=host, port=port, timeout=timeout, context=context)
        return fake_client

    monkeypatch.setattr(
        "tools.qq_mail_relay.mailer.ssl.create_default_context", lambda: tls_context
    )
    monkeypatch.setattr("tools.qq_mail_relay.mailer.smtplib.SMTP_SSL", smtp_ssl_factory)

    await QQSMTPMailer(settings).send(message)

    assert connection == {
        "host": "smtp.qq.com",
        "port": 465,
        "timeout": 10,
        "context": tls_context,
    }
    assert fake_client.actions[0] == (
        "login",
        "sender@qq.com",
        "qq-smtp-authorization-code",
    )
    assert fake_client.actions[1][0] == "send"
    assert fake_client.actions[1][2:] == ("sender@qq.com", ["recipient@qq.com"])


@pytest.mark.asyncio
async def test_smtp_starttls_upgrades_before_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(
        tmp_path,
        dry_run=False,
        smtp_username="sender@qq.com",
        smtp_auth_code="qq-smtp-authorization-code",
        smtp_security="starttls",
        smtp_port=587,
    )
    event = NotificationEvent.model_validate(event_payload("ANALYSIS_FAILED"))
    message = build_email(event, settings, "qqmail-test")
    fake_client = FakeSMTPClient()
    tls_context = object()
    connection: dict[str, object] = {}

    def smtp_factory(host: str, port: int, *, timeout: float) -> FakeSMTPClient:
        connection.update(host=host, port=port, timeout=timeout)
        return fake_client

    monkeypatch.setattr(
        "tools.qq_mail_relay.mailer.ssl.create_default_context", lambda: tls_context
    )
    monkeypatch.setattr("tools.qq_mail_relay.mailer.smtplib.SMTP", smtp_factory)

    await QQSMTPMailer(settings).send(message)

    assert connection == {"host": "smtp.qq.com", "port": 587, "timeout": 10}
    assert fake_client.actions[:4] == [
        "ehlo",
        ("starttls", tls_context),
        "ehlo",
        ("login", "sender@qq.com", "qq-smtp-authorization-code"),
    ]
    assert fake_client.actions[4][0] == "send"


@pytest.mark.asyncio
async def test_default_dry_run_never_constructs_an_smtp_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    event = NotificationEvent.model_validate(event_payload("INITIAL_ALERT"))
    message = build_email(event, settings, "qqmail-test")

    def forbidden_client(*_: object, **__: object) -> None:
        raise AssertionError("dry-run attempted a real SMTP connection")

    monkeypatch.setattr("tools.qq_mail_relay.mailer.smtplib.SMTP_SSL", forbidden_client)
    monkeypatch.setattr("tools.qq_mail_relay.mailer.smtplib.SMTP", forbidden_client)

    await QQSMTPMailer(settings).send(message)
