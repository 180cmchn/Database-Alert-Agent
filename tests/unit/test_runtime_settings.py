from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.application.admin as admin_module
from app.api.schemas import RuntimeSettingsPatch, RuntimeSettingsResponse
from app.application.admin import (
    RuntimeSettingsConflictError,
    RuntimeSettingsManager,
)
from app.config import Settings, get_settings
from tests.pdf_fixtures import create_tikv_runbook_pdf


def test_windows_file_lock_backend_uses_a_stable_lock_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def locking(self, _file_descriptor: int, mode: int, count: int) -> None:
            self.calls.append((mode, count))

    backend = FakeMsvcrt()
    monkeypatch.setattr(admin_module, "_fcntl", None)
    monkeypatch.setattr(admin_module, "_msvcrt", backend)
    lock_path = tmp_path / "runtime-settings.lock"
    file_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        admin_module._acquire_file_lock(file_descriptor)
        admin_module._release_file_lock(file_descriptor)
    finally:
        os.close(file_descriptor)

    assert lock_path.stat().st_size == 1
    assert backend.calls == [(backend.LK_LOCK, 1), (backend.LK_UNLCK, 1)]


def test_get_settings_loads_only_persisted_runtime_whitelist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_path = tmp_path / "runtime-settings.json"
    runtime_path.write_text(
        json.dumps(
            {
                "ai_model": "persisted-model",
                "runbook_limit": 9,
                "database_url": "sqlite+aiosqlite:///must-not-be-used.db",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNTIME_SETTINGS_PATH", str(runtime_path))
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///bootstrap.db")
    monkeypatch.setenv("AI_PROVIDER", "fake")
    monkeypatch.setenv("AI_MODEL", "environment-model")
    get_settings.cache_clear()
    try:
        settings = get_settings()
    finally:
        get_settings.cache_clear()

    assert settings.ai_model == "persisted-model"
    assert settings.runbook_limit == 9
    assert settings.database_url == "sqlite+aiosqlite:///bootstrap.db"


def test_cors_origins_accept_csv_and_production_urls_require_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS", "http://localhost:5173,https://console.example.test"
    )
    settings = Settings(_env_file=None, ai_provider="fake")
    assert settings.cors_allowed_origins == [
        "http://localhost:5173",
        "https://console.example.test",
    ]

    with pytest.raises(ValidationError, match="must use HTTPS in production"):
        Settings(
            _env_file=None,
            app_env="production",
            ai_provider="fake",
            ai_base_url="http://models.example.test/v1",
        )


def test_fake_provider_is_rejected_in_production() -> None:
    with pytest.raises(ValidationError, match="fake is not allowed in production"):
        Settings(
            _env_file=None,
            app_env="production",
            ai_provider="fake",
            ai_base_url="https://models.example.test/v1",
        )


def test_pdf_runbook_readiness_requires_directory_and_pdf(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        runbook_pdf_dir=tmp_path / "missing",
    )

    issues = settings.readiness_issues()

    assert any("PDF runbook directory does not exist" in issue for issue in issues)

    empty = tmp_path / "empty"
    empty.mkdir()
    settings = Settings(_env_file=None, ai_provider="fake", runbook_pdf_dir=empty)
    assert any("No PDF runbooks found" in issue for issue in settings.readiness_issues())


@pytest.mark.parametrize(
    "url",
    [
        "http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key",
        "https://example.test/cgi-bin/webhook/send?key=test-key",
        "https://qyapi.weixin.qq.com/cgi-bin/not-webhook/send?key=test-key",
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send",
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=",
        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key&extra=1",
    ],
)
def test_wecom_url_requires_official_https_group_robot_endpoint(url: str) -> None:
    with pytest.raises(ValidationError, match="official HTTPS WeCom"):
        Settings(_env_file=None, ai_provider="fake", wecom_webhook_url=url)

    valid = Settings(
        _env_file=None,
        ai_provider="fake",
        wecom_webhook_url=(
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"
        ),
    )
    assert valid.wecom_webhook_url.endswith("key=test-key")


def test_settings_validation_error_hides_invalid_wecom_url_secret() -> None:
    secret = "wecom-key-that-must-not-appear-in-validation-errors"
    with pytest.raises(ValidationError) as caught:
        Settings(
            _env_file=None,
            ai_provider="fake",
            wecom_webhook_url=f"not-a-url?key={secret}",
        )

    assert secret not in str(caught.value)


def test_flashduty_polling_interval_and_scope_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ai_provider="fake",
            flashduty_poll_interval_seconds=299,
        )

    monkeypatch.setenv("FLASHDUTY_POLL_CHANNEL_IDS", "7,8")
    monkeypatch.setenv("FLASHDUTY_POLL_INTEGRATION_IDS", "[42,43]")
    settings = Settings(_env_file=None, ai_provider="fake")

    assert settings.flashduty_poll_interval_seconds == 300
    assert settings.flashduty_poll_channel_ids == [7, 8]
    assert settings.flashduty_poll_integration_ids == [42, 43]


def test_flashduty_polling_requires_a_collaboration_space_scope() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_poll_channel_ids=[],
    )

    assert (
        "FLASHDUTY_POLL_CHANNEL_IDS must contain at least one collaboration space ID"
        in settings.readiness_issues()
    )


def runtime_test_settings(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    create_tikv_runbook_pdf(runbooks)
    return Settings(
        _env_file=None,
        ai_provider="fake",
        runbook_pdf_dir=runbooks,
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )


def test_runtime_patch_schema_requires_revision_and_excludes_it_from_updates() -> None:
    with pytest.raises(ValidationError):
        RuntimeSettingsPatch(runbook_limit=7)  # type: ignore[call-arg]

    payload = RuntimeSettingsPatch(
        expected_revision="0123456789abcdef", runbook_limit=7
    )
    assert payload.updates() == {"runbook_limit": 7}


@pytest.mark.asyncio
async def test_runtime_patch_detects_stale_revision_and_merges_latest_disk_values(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    first = RuntimeSettingsManager(settings.runtime_settings_path)
    second = RuntimeSettingsManager(settings.runtime_settings_path)
    initial_revision = first.revision

    first_settings, first_revision, changed = await first.patch(
        settings,
        {"runbook_limit": 7},
        expected_revision=initial_revision,
    )
    assert changed == ["runbook_limit"]
    assert first_revision != initial_revision

    with pytest.raises(RuntimeSettingsConflictError) as conflict:
        await second.patch(
            settings,
            {"validation_enabled": False},
            expected_revision=initial_revision,
        )
    assert conflict.value.expected_revision == initial_revision
    assert conflict.value.current_revision == first_revision

    merged, merged_revision, changed = await second.patch(
        settings,
        {"validation_enabled": False},
        expected_revision=first_revision,
    )
    assert changed == ["validation_enabled"]
    assert merged.runbook_limit == 7
    assert merged.validation_enabled is False
    assert merged_revision not in {initial_revision, first_revision}
    persisted = json.loads(settings.runtime_settings_path.read_text(encoding="utf-8"))
    assert persisted["runbook_limit"] == 7
    assert persisted["validation_enabled"] is False
    assert first_settings.runbook_limit == 7


@pytest.mark.asyncio
async def test_runtime_patch_rejects_unrunnable_provider_and_removed_notifier_fields(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    with pytest.raises(ValueError, match="AI API key.*AI model"):
        await manager.patch(
            settings,
            {"ai_provider": "openai_compatible", "ai_api_key": "", "ai_model": ""},
            expected_revision=manager.revision,
        )
    with pytest.raises(ValueError, match="not editable: management_webhook_url"):
        await manager.patch(
            settings,
            {"notifier_mode": "webhook", "management_webhook_url": ""},
            expected_revision=manager.revision,
        )
    production_fake = settings.model_copy(update={"app_env": "production"})
    with pytest.raises(ValidationError, match="fake is not allowed in production"):
        await manager.patch(
            production_fake,
            {"runbook_limit": 8},
            expected_revision=manager.revision,
        )


@pytest.mark.asyncio
async def test_runtime_patch_requires_external_notifier_in_production(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    create_tikv_runbook_pdf(runbooks)
    settings = Settings(
        _env_file=None,
        app_env="production",
        ai_provider="openai_compatible",
        ai_api_key="configured-test-key",
        ai_model="configured-test-model",
        ai_base_url="https://models.example.test/v1",
        admin_api_token="configured-admin-token",
        production_gate_approved=True,
        runbook_pdf_dir=runbooks,
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    with pytest.raises(ValueError, match="WeCom webhook URL is required"):
        await manager.patch(
            settings,
            {"runbook_limit": 7},
            expected_revision=manager.revision,
        )

    configured, _, changed = await manager.patch(
        settings,
        {
            "wecom_webhook_url": (
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"
            ),
        },
        expected_revision=manager.revision,
    )
    assert configured.wecom_webhook_url.endswith("key=test-key")
    assert changed == ["wecom_webhook_url"]


def test_runtime_settings_response_contains_only_safe_readiness_summary(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    response = RuntimeSettingsResponse.from_settings(settings, revision="0" * 16)
    body = response.model_dump(mode="json")
    assert body["app_env"] == "development"
    assert body["fake_provider_allowed"] is True
    assert body["ready"] is True
    assert body["issues"] == []
    assert body["wecom_webhook_url_configured"] is False
    assert body["ai_fallback_enabled"] is True
    assert body["flashduty_polling_enabled"] is True
    assert body["flashduty_poll_interval_seconds"] == 300
    assert "ai_api_key" not in body
    assert "wecom_webhook_url" not in body

    configured_wecom = settings.model_copy(
        update={
            "wecom_webhook_url": (
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=must-not-leak"
            )
        }
    )
    safe_response = RuntimeSettingsResponse.from_settings(
        configured_wecom, revision="1" * 16
    )
    safe_body = safe_response.model_dump(mode="json")
    assert safe_body["wecom_webhook_url_configured"] is True
    assert "must-not-leak" not in safe_response.model_dump_json()

    incomplete = settings.model_copy(
        update={"ai_provider": "openai_compatible", "ai_api_key": "", "ai_model": ""}
    )
    incomplete_response = RuntimeSettingsResponse.from_settings(
        incomplete, revision="0" * 16
    )
    assert incomplete_response.ready is False
    assert any("AI_API_KEY" in issue for issue in incomplete_response.issues)


def test_production_requires_gate_approval_before_shadow_mode_is_disabled(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    create_tikv_runbook_pdf(runbooks)
    base = {
        "_env_file": None,
        "app_env": "production",
        "ai_provider": "openai_compatible",
        "ai_api_key": "configured-test-key",
        "ai_model": "configured-test-model",
        "ai_base_url": "https://models.example.test/v1",
        "admin_api_token": "configured-admin-token",
        "wecom_webhook_url": (
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"
        ),
        "runbook_pdf_dir": runbooks,
    }

    blocked = Settings(**base, shadow_enabled=False, production_gate_approved=False)
    shadow = Settings(**base, shadow_enabled=True, production_gate_approved=False)

    assert any("PRODUCTION_GATE_APPROVED" in issue for issue in blocked.readiness_issues())
    assert not any(
        "PRODUCTION_GATE_APPROVED" in issue for issue in shadow.readiness_issues()
    )
