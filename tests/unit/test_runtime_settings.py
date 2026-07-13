from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

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
