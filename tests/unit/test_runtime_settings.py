from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.schemas import RuntimeSettingsPatch, RuntimeSettingsResponse
from app.application.admin import (
    RuntimeSettingsConflictError,
    RuntimeSettingsManager,
)
from app.config import Settings, get_settings


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


def runtime_test_settings(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir(exist_ok=True)
    return Settings(
        _env_file=None,
        ai_provider="fake",
        notifier_mode="log",
        runbook_dir=runbooks,
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
async def test_runtime_patch_rejects_unrunnable_provider_and_notifier_combinations(
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
    with pytest.raises(ValueError, match="webhook URL"):
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
async def test_runtime_patch_requires_webhook_notifier_in_production(
    tmp_path: Path,
) -> None:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    settings = Settings(
        _env_file=None,
        app_env="production",
        ai_provider="openai_compatible",
        ai_api_key="configured-test-key",
        ai_model="configured-test-model",
        ai_base_url="https://models.example.test/v1",
        notifier_mode="log",
        admin_api_token="configured-admin-token",
        runbook_dir=runbooks,
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    with pytest.raises(ValueError, match="Webhook notifier is required"):
        await manager.patch(
            settings,
            {"runbook_limit": 7},
            expected_revision=manager.revision,
        )


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
    assert "ai_api_key" not in body
    assert "management_webhook_bearer_token" not in body

    incomplete = settings.model_copy(
        update={"ai_provider": "openai_compatible", "ai_api_key": "", "ai_model": ""}
    )
    incomplete_response = RuntimeSettingsResponse.from_settings(
        incomplete, revision="0" * 16
    )
    assert incomplete_response.ready is False
    assert any("AI_API_KEY" in issue for issue in incomplete_response.issues)
