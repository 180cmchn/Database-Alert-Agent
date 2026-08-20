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
from app.application.factory import _mcp_environment
from app.config import RUNTIME_SETTINGS_KEYS, Settings, get_settings


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
                "scheduler_workers": 4,
                "analysis_timeout_seconds": 2400,
                "stream_main_agent_reasoning": True,
                "archery_mcp_max_agent_steps": 18,
                "database_url": "sqlite+aiosqlite:///must-not-be-used.db",
                "shadow_enabled": True,
                "production_gate_approved": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNTIME_SETTINGS_PATH", str(runtime_path))
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///bootstrap.db")
    monkeypatch.setenv("AI_PROVIDER", "fake")
    monkeypatch.setenv("AI_MODEL", "environment-model")
    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")
    get_settings.cache_clear()
    try:
        settings = get_settings()
    finally:
        get_settings.cache_clear()

    assert settings.ai_model == "persisted-model"
    assert not hasattr(settings, "runbook_limit")
    assert settings.scheduler_workers == 4
    assert settings.analysis_timeout_seconds == 2400
    assert settings.stream_main_agent_reasoning is True
    assert settings.database_url == "sqlite+aiosqlite:///bootstrap.db"
    assert not hasattr(settings, "archery_mcp_max_agent_steps")
    assert not hasattr(settings, "shadow_enabled")
    assert not hasattr(settings, "production_gate_approved")


def test_cors_origins_accept_csv_and_production_urls_require_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,https://console.example.test")
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


def test_openai_responses_provider_is_normalized_and_requires_credentials() -> None:
    configured = Settings(
        _env_file=None,
        ai_provider=" OPENAI_RESPONSES ",
        ai_api_key="test-key",
        ai_model="test-model",
        knowledge_sources=["external_knowledge"],
    )

    assert configured.ai_provider == "openai_responses"
    assert not any("AI_API_KEY" in issue for issue in configured.readiness_issues())
    assert not any("AI_MODEL" in issue for issue in configured.readiness_issues())

    incomplete = configured.model_copy(update={"ai_api_key": "", "ai_model": ""})
    assert {
        "AI_API_KEY is required for openai_responses provider",
        "AI_MODEL is required for openai_responses provider",
    }.issubset(incomplete.readiness_issues())

    unsupported = configured.model_copy(update={"ai_provider": "unknown_protocol"})
    assert "Unsupported AI_PROVIDER: unknown_protocol" in unsupported.readiness_issues()


def test_ai_max_tokens_has_reasoning_safe_default_and_bounds() -> None:
    settings = Settings(_env_file=None, ai_provider="fake")
    assert settings.ai_max_tokens == 16_384

    configured = Settings(
        _env_file=None,
        ai_provider="fake",
        ai_max_tokens=32_768,
    )
    assert configured.ai_max_tokens == 32_768

    with pytest.raises(ValidationError):
        Settings(_env_file=None, ai_provider="fake", ai_max_tokens=1023)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ai_provider="fake", ai_max_tokens=131_073)


def test_ai_retry_count_is_not_a_runtime_setting() -> None:
    settings = Settings(_env_file=None, ai_provider="fake", ai_max_retries=99)

    assert settings.ai_max_retries == 99
    assert "ai_max_retries" not in RUNTIME_SETTINGS_KEYS
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            ai_max_retries=3,
        )


def test_knowledge_sources_are_deduplicated_and_can_be_empty() -> None:
    defaults = Settings(_env_file=None, ai_provider="fake")
    assert defaults.knowledge_sources == []
    assert defaults.external_knowledge_enabled is False

    empty = Settings(_env_file=None, ai_provider="fake", knowledge_sources=[])
    assert empty.knowledge_sources == []
    assert empty.external_knowledge_enabled is False

    external_only = Settings(
        _env_file=None,
        ai_provider="fake",
        knowledge_sources=["external_knowledge"],
    )
    assert external_only.external_knowledge_enabled is True

    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        knowledge_sources=["external_knowledge", "external_knowledge"],
    )
    assert settings.knowledge_sources == ["external_knowledge"]
    assert settings.external_knowledge_enabled is True


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
        wecom_webhook_url=("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"),
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


def test_wecom_page_url_is_validated() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        wecom_page_base_url="http://alerts.intra.example.com",
    )
    assert settings.wecom_page_base_url == "http://alerts.intra.example.com"

    with pytest.raises(ValidationError, match="must not contain a query or fragment"):
        Settings(
            _env_file=None,
            ai_provider="fake",
            wecom_page_base_url="https://alerts.intra.example.com?tenant=dba",
        )

    enabled_without_page = Settings(
        _env_file=None,
        ai_provider="fake",
        wecom_enabled=True,
        wecom_webhook_url=("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"),
    )
    assert any("WECOM_PAGE_BASE_URL" in issue for issue in enabled_without_page.readiness_issues())


def test_flashduty_polling_interval_and_scope_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ai_provider="fake",
            flashduty_poll_interval_seconds=299,
        )

    with pytest.raises(ValidationError, match="must be greater than or equal"):
        Settings(
            _env_file=None,
            ai_provider="fake",
            flashduty_polling_enabled=True,
            flashduty_poll_interval_seconds=600,
            flashduty_poll_lookback_seconds=300,
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
        flashduty_polling_enabled=True,
        flashduty_poll_channel_ids=[],
    )

    assert (
        "FLASHDUTY_POLL_CHANNEL_IDS must contain at least one collaboration space ID"
        in settings.readiness_issues()
    )


def test_generic_mcp_environment_is_loaded_from_dotenv_without_entering_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(
        "NEW_MCP_URL=https://mcp.example.test/sse\n"
        "NEW_MCP_API_KEY=dotenv-secret\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NEW_MCP_API_KEY", "process-secret")
    settings = Settings(
        ai_provider="fake",
        knowledge_sources=["external_knowledge"],
    )

    environment = _mcp_environment(settings)

    assert environment["NEW_MCP_URL"] == "https://mcp.example.test/sse"
    assert environment["NEW_MCP_API_KEY"] == "process-secret"
    assert "new_mcp_url" not in settings.model_dump()
    assert "new_mcp_api_key" not in settings.model_dump()


def test_flashduty_unaudited_capabilities_are_disabled_and_deployment_only() -> None:
    settings = Settings(_env_file=None, ai_provider="fake")

    assert settings.flashduty_monitors_enabled is False
    assert settings.flashduty_changes_enabled is False
    assert "flashduty_monitors_enabled" not in RUNTIME_SETTINGS_KEYS
    assert "flashduty_changes_enabled" not in RUNTIME_SETTINGS_KEYS

    unscoped_changes = Settings(
        _env_file=None,
        ai_provider="fake",
        flashduty_enabled=True,
        flashduty_app_key="test-app-key",
        flashduty_changes_enabled=True,
    )
    assert any(
        "when FlashDuty change queries are enabled" in issue
        for issue in unscoped_changes.readiness_issues()
    )


def test_archery_mcp_connection_is_deployment_only_and_target_comes_from_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="fake",
        archery_mcp_url="https://archery.example.test/mcp",
    )
    assert settings.archery_mcp_enabled is False
    issue = next(
        item
        for item in settings.readiness_issues()
        if "Archery MCP configuration is incomplete" in item
    )
    assert "ARCHERY_MCP_TOKEN" in issue

    configured = Settings(
        _env_file=None,
        ai_provider="fake",
        archery_mcp_url="https://archery.example.test/mcp",
        archery_mcp_token="test-token",
    )
    assert configured.archery_mcp_enabled is True
    assert any("model with tool calling" in issue for issue in configured.readiness_issues())
    assert "archery_mcp_url" not in RUNTIME_SETTINGS_KEYS
    assert "archery_mcp_token" not in RUNTIME_SETTINGS_KEYS
    assert "archery_mcp_max_agent_steps" not in RUNTIME_SETTINGS_KEYS
    assert "mcp_settings_path" not in RUNTIME_SETTINGS_KEYS
    assert configured.archery_slow_log_window_seconds == 300
    assert not hasattr(configured, "archery_mcp_max_agent_steps")

    monkeypatch.setenv("ARCHERY_MCP_HTTP_API_KEY", "existing-server-token")
    monkeypatch.setenv("ARCHERY_SLOW_LOG_WINDOW_SECONDS", "600")
    monkeypatch.setenv("ARCHERY_MCP_MAX_AGENT_STEPS", "18")
    alias_configured = Settings(
        _env_file=None,
        ai_provider="fake",
        archery_mcp_url="https://archery.example.test/mcp",
    )
    assert alias_configured.archery_mcp_enabled is True
    assert alias_configured.archery_mcp_token == "existing-server-token"
    assert alias_configured.archery_slow_log_window_seconds == 600
    assert not hasattr(alias_configured, "archery_mcp_max_agent_steps")

    with pytest.raises(ValidationError, match="full MCP endpoint"):
        Settings(
            _env_file=None,
            ai_provider="fake",
            archery_mcp_url="https://archery.example.test",
            archery_mcp_token="test-token",
        )


def test_openai_responses_is_eligible_for_mcp_tool_calling_readiness(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "settings.json"
    catalog_path.write_text("{}", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        ai_provider="openai_responses",
        ai_api_key="test-key",
        ai_model="test-model",
        knowledge_sources=["external_knowledge"],
        mcp_settings_path=catalog_path,
        archery_mcp_url="https://archery.example.test/mcp",
        archery_mcp_token="test-token",
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
    )

    assert not any(
        "requires a real AI provider model with tool calling" in issue
        for issue in settings.readiness_issues()
    )


def runtime_test_settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="fake",
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )


def test_runtime_patch_schema_requires_revision_and_excludes_it_from_updates() -> None:
    with pytest.raises(ValidationError):
        RuntimeSettingsPatch(runbook_limit=7)  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            external_knowledge_base_url="http://other.test",
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            external_knowledge_enabled=True,
        )

    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            runbook_limit=7,
        )
    payload = RuntimeSettingsPatch(
        expected_revision="0123456789abcdef",
        scheduler_workers=4,
        analysis_timeout_seconds=2400,
    )
    assert payload.updates() == {
        "scheduler_workers": 4,
        "analysis_timeout_seconds": 2400,
    }
    responses_patch = RuntimeSettingsPatch(
        expected_revision="0123456789abcdef",
        ai_provider="openai_responses",
    )
    assert responses_patch.updates() == {"ai_provider": "openai_responses"}
    with pytest.raises(ValidationError):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            ai_provider="unknown_protocol",  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            archery_mcp_max_agent_steps=18,
        )
    with pytest.raises(ValidationError):
        RuntimeSettingsPatch(
            expected_revision="0123456789abcdef",
            scheduler_workers=17,
        )


def test_stream_main_agent_reasoning_requires_valid_deployment_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STREAM_MAIN_AGENT_REASONING", raising=False)
    with pytest.raises(ValidationError, match="STREAM_MAIN_AGENT_REASONING"):
        Settings(_env_file=None, ai_provider="fake")

    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "true")
    assert Settings(_env_file=None, ai_provider="fake").stream_main_agent_reasoning is True

    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")
    assert Settings(_env_file=None, ai_provider="fake").stream_main_agent_reasoning is False

    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "not-a-boolean")
    with pytest.raises(ValidationError, match="STREAM_MAIN_AGENT_REASONING"):
        Settings(_env_file=None, ai_provider="fake")


@pytest.mark.asyncio
async def test_stream_main_agent_reasoning_is_runtime_editable(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    assert settings.stream_main_agent_reasoning is False
    assert "stream_main_agent_reasoning" in RUNTIME_SETTINGS_KEYS

    enabled, _, changed = await manager.patch(
        settings,
        {"stream_main_agent_reasoning": True},
        expected_revision=manager.revision,
    )
    assert enabled.stream_main_agent_reasoning is True
    assert changed == ["stream_main_agent_reasoning"]
    persisted = json.loads(settings.runtime_settings_path.read_text(encoding="utf-8"))
    assert persisted["stream_main_agent_reasoning"] is True


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
        {"react_max_rounds": 7},
        expected_revision=initial_revision,
    )
    assert changed == ["react_max_rounds"]
    assert first_revision != initial_revision

    with pytest.raises(RuntimeSettingsConflictError) as conflict:
        await second.patch(
            settings,
            {"react_max_rounds": 8},
            expected_revision=initial_revision,
        )
    assert conflict.value.expected_revision == initial_revision
    assert conflict.value.current_revision == first_revision

    merged, merged_revision, changed = await second.patch(
        settings,
        {"scheduler_workers": 2},
        expected_revision=first_revision,
    )
    assert changed == ["scheduler_workers"]
    assert merged.react_max_rounds == 7
    assert merged.scheduler_workers == 2
    assert merged_revision not in {initial_revision, first_revision}
    persisted = json.loads(settings.runtime_settings_path.read_text(encoding="utf-8"))
    assert persisted["react_max_rounds"] == 7
    assert persisted["scheduler_workers"] == 2
    assert first_settings.react_max_rounds == 7


@pytest.mark.asyncio
async def test_runtime_patch_rejects_unrunnable_provider_and_removed_notifier_fields(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    for provider in ("openai_compatible", "openai_responses"):
        with pytest.raises(ValueError, match="AI API key.*AI model"):
            await manager.patch(
                settings,
                {"ai_provider": provider, "ai_api_key": "", "ai_model": ""},
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
            {"react_max_rounds": 8},
            expected_revision=manager.revision,
        )


@pytest.mark.asyncio
async def test_runtime_patch_requires_external_notifier_in_production(
    tmp_path: Path,
) -> None:
    settings = Settings(
        _env_file=None,
        app_env="production",
        ai_provider="openai_compatible",
        ai_api_key="configured-test-key",
        ai_model="configured-test-model",
        ai_base_url="https://models.example.test/v1",
        admin_api_token="configured-admin-token",
        wecom_enabled=True,
        wecom_page_base_url="https://alerts.example.test",
        runtime_settings_path=tmp_path / "runtime-settings.json",
    )
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    with pytest.raises(ValueError, match="WeCom webhook URL is required"):
        await manager.patch(
            settings,
            {"react_max_rounds": 7},
            expected_revision=manager.revision,
        )

    configured, _, changed = await manager.patch(
        settings,
        {
            "wecom_webhook_url": ("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"),
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
    assert body["wecom_page_base_url"] == ""
    assert body["ai_fallback_enabled"] is True
    assert body["stream_main_agent_reasoning"] is False
    assert "ai_max_retries" not in body
    assert body["scheduler_workers"] == 1
    assert body["flashduty_polling_enabled"] is False
    assert body["flashduty_poll_interval_seconds"] == 300
    assert body["analysis_timeout_seconds"] == 1800
    assert "archery_mcp_max_agent_steps" not in body
    assert "shadow_enabled" not in body
    assert "production_gate_approved" not in body
    assert "shadow_enabled" not in RUNTIME_SETTINGS_KEYS
    assert "production_gate_approved" not in RUNTIME_SETTINGS_KEYS
    assert "validation_enabled" not in RUNTIME_SETTINGS_KEYS
    assert "validation_enabled" not in body
    assert "prometheus_mcp_use_shared_harness" not in body
    assert "scheduler_workers" in RUNTIME_SETTINGS_KEYS
    assert "wecom_page_base_url" in RUNTIME_SETTINGS_KEYS
    assert "ai_api_key" not in body
    assert "wecom_webhook_url" not in body

    configured_wecom = settings.model_copy(
        update={
            "wecom_webhook_url": (
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=must-not-leak"
            )
        }
    )
    safe_response = RuntimeSettingsResponse.from_settings(configured_wecom, revision="1" * 16)
    safe_body = safe_response.model_dump(mode="json")
    assert safe_body["wecom_webhook_url_configured"] is True
    assert "must-not-leak" not in safe_response.model_dump_json()

    incomplete = settings.model_copy(
        update={"ai_provider": "openai_compatible", "ai_api_key": "", "ai_model": ""}
    )
    incomplete_response = RuntimeSettingsResponse.from_settings(incomplete, revision="0" * 16)
    assert incomplete_response.ready is False
    assert any("AI_API_KEY" in issue for issue in incomplete_response.issues)


@pytest.mark.asyncio
async def test_external_base_url_is_deployment_only_and_runtime_key_is_url_bound(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path).model_copy(
        update={
            "external_knowledge_base_url": "http://127.0.0.1:8001",
            "knowledge_sources": ["external_knowledge"],
        }
    )
    settings = Settings.model_validate(settings.model_dump(mode="python"))
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    with pytest.raises(ValueError, match="not editable"):
        await manager.patch(
            settings,
            {"external_knowledge_base_url": "http://other.test"},
            expected_revision=manager.revision,
        )

    configured, _, changed = await manager.patch(
        settings,
        {"external_knowledge_api_key": "test-knowledge-key"},
        expected_revision=manager.revision,
    )
    assert configured.external_knowledge_enabled is True
    assert configured.external_knowledge_base_url == "http://127.0.0.1:8001"
    assert configured.external_knowledge_api_key == "test-knowledge-key"
    assert "external_knowledge_api_key" in changed
    assert "external_knowledge_api_key_base_url" in changed
    assert configured.external_knowledge_api_key_is_current() is True

    persisted = json.loads(settings.runtime_settings_path.read_text(encoding="utf-8"))
    assert "external_knowledge_enabled" not in persisted
    assert "external_knowledge_base_url" not in persisted
    assert persisted["external_knowledge_api_key"] == "test-knowledge-key"
    assert persisted["external_knowledge_api_key_base_url"] == "http://127.0.0.1:8001"


@pytest.mark.asyncio
async def test_runtime_knowledge_selection_is_the_external_connection_switch(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    enabled, enabled_revision, changed = await manager.patch(
        settings,
        {"knowledge_sources": ["external_knowledge"]},
        expected_revision=manager.revision,
    )
    assert enabled.external_knowledge_enabled is True
    assert changed == ["knowledge_sources"]

    disabled, _, changed = await manager.patch(
        enabled,
        {"knowledge_sources": []},
        expected_revision=enabled_revision,
    )
    assert disabled.external_knowledge_enabled is False
    assert changed == ["knowledge_sources"]

    persisted = json.loads(settings.runtime_settings_path.read_text(encoding="utf-8"))
    assert persisted["knowledge_sources"] == []
    assert "external_knowledge_enabled" not in persisted


def test_runtime_settings_response_does_not_leak_external_knowledge_api_key(
    tmp_path: Path,
) -> None:
    settings = runtime_test_settings(tmp_path)
    with_secret = settings.model_copy(
        update={
            "external_knowledge_base_url": "http://localhost:8001",
            "external_knowledge_api_key": "must-not-leak-knowledge-key",
            "external_knowledge_api_key_base_url": "http://localhost:8001",
            "knowledge_sources": ["external_knowledge"],
        }
    )
    response = RuntimeSettingsResponse.from_settings(with_secret, revision="0" * 16)
    body = response.model_dump(mode="json")
    assert body["external_knowledge_enabled"] is True
    assert body["external_knowledge_base_url"] == "http://localhost:8001"
    assert body["external_knowledge_api_key_configured"] is True
    assert "external_knowledge_api_key" not in body
    assert "must-not-leak-knowledge-key" not in response.model_dump_json()

    changed_url = with_secret.model_copy(
        update={"external_knowledge_base_url": "http://localhost:9001"}
    )
    changed_response = RuntimeSettingsResponse.from_settings(changed_url, revision="1" * 16)
    assert changed_response.external_knowledge_api_key_configured is False
    assert any("must be re-entered" in issue for issue in changed_response.issues)
