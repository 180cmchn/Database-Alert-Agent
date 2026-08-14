import json
from pathlib import Path

import pytest

from app.adapters.ai import (
    OpenAICompatibleAdvisor,
    OpenAIResponsesAdvisor,
)
from app.adapters.archery_mcp import (
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcherySlowLogEvidenceTool,
)
from app.adapters.generic_mcp import GenericMCPEvidenceTool
from app.adapters.prometheus_mcp import (
    PROMETHEUS_METRICS_TOOL_NAME,
    PrometheusMCPEvidenceTool,
)
from app.application.factory import _build_advisor, build_runtime
from app.config import Settings


def _write_mcp_catalog(tmp_path: Path, *, include_custom: bool = False) -> Path:
    catalog_dir = tmp_path / "mcp"
    prompt_references: dict[str, dict[str, str]] = {}
    server_names = ("archery", "prometheus", "custom") if include_custom else (
        "archery",
        "prometheus",
    )
    for server_name in server_names:
        prompt_dir = catalog_dir / "prompts" / server_name
        prompt_dir.mkdir(parents=True)
        prompt_references[server_name] = {}
        for prompt_name in ("role", "purpose", "workflow", "safety"):
            prompt_path = prompt_dir / f"{prompt_name}.md"
            prompt_path.write_text(
                f"{server_name} {prompt_name} test prompt",
                encoding="utf-8",
            )
            prompt_references[server_name][prompt_name] = str(
                prompt_path.relative_to(catalog_dir)
            )

    catalog_path = catalog_dir / "settings.json"
    servers: dict[str, object] = {
        "archery": {
            "url": "${ARCHERY_MCP_URL}",
            "headers": {
                "X-Archery-Token": "${ARCHERY_MCP_TOKEN}",
            },
            "prompts": prompt_references["archery"],
        },
        "prometheus": {
            "url": "${PROMETHEUS_MCP_SSE_URL}",
            "prompts": prompt_references["prometheus"],
        },
    }
    if include_custom:
        servers["custom"] = {
            "enabled": True,
            "url": "${CUSTOM_MCP_URL}",
            "toolTimeoutSeconds": 611,
            "prompts": prompt_references["custom"],
        }
    catalog_path.write_text(
        json.dumps(
            {"mcpServers": servers}
        ),
        encoding="utf-8",
    )
    return catalog_path


@pytest.mark.asyncio
@pytest.mark.parametrize("ai_provider", ["openai_compatible", "openai_responses"])
async def test_special_mcp_tools_use_configured_outer_timeouts(
    tmp_path: Path,
    ai_provider: str,
) -> None:
    runbook_dir = tmp_path / "runbooks"
    runbook_dir.mkdir()
    settings = Settings(
        _env_file=None,
        ai_provider=ai_provider,
        ai_api_key="test-key",
        ai_model="test-model",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbook_dir,
        mcp_settings_path=_write_mcp_catalog(tmp_path),
        archery_mcp_url="https://archery.example.test/mcp",
        archery_mcp_token="test-token",
        archery_mcp_tool_timeout_seconds=611,
        prometheus_mcp_sse_url="https://prometheus.example.test/sse",
        prometheus_mcp_tool_timeout_seconds=733,
    )
    runtime = build_runtime(settings)

    try:
        archery_tool = runtime.service.tool_registry.get(ARCHERY_SLOW_LOG_TOOL_NAME)
        prometheus_tool = runtime.service.tool_registry.get(PROMETHEUS_METRICS_TOOL_NAME)

        assert isinstance(archery_tool, ArcherySlowLogEvidenceTool)
        assert archery_tool.default_timeout_seconds == 611
        assert runtime.service.tool_registry.spec(ARCHERY_SLOW_LOG_TOOL_NAME).timeout == 611

        assert isinstance(prometheus_tool, PrometheusMCPEvidenceTool)
        assert prometheus_tool.default_timeout_seconds == 733
        assert runtime.service.tool_registry.spec(PROMETHEUS_METRICS_TOOL_NAME).timeout == 733
    finally:
        await runtime.service.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("ai_provider", ["openai_compatible", "openai_responses"])
async def test_declarative_mcp_uses_full_catalog_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ai_provider: str,
) -> None:
    runbook_dir = tmp_path / "runbooks"
    runbook_dir.mkdir()
    monkeypatch.setenv("CUSTOM_MCP_URL", "https://custom.example.test/mcp")
    settings = Settings(
        _env_file=None,
        ai_provider=ai_provider,
        ai_api_key="test-key",
        ai_model="test-model",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbook_dir,
        mcp_settings_path=_write_mcp_catalog(tmp_path, include_custom=True),
    )
    runtime = build_runtime(settings)

    try:
        custom_tool = runtime.service.tool_registry.get("query_mcp_custom")

        assert isinstance(custom_tool, GenericMCPEvidenceTool)
        assert custom_tool.default_timeout_seconds == 611
        assert runtime.service.tool_registry.spec("query_mcp_custom").timeout == 611
    finally:
        await runtime.service.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ai_provider", "advisor_type"),
    [
        ("openai_compatible", OpenAICompatibleAdvisor),
        ("openai_responses", OpenAIResponsesAdvisor),
    ],
)
async def test_factory_builds_the_explicit_real_ai_protocol(
    ai_provider: str,
    advisor_type: type[OpenAICompatibleAdvisor] | type[OpenAIResponsesAdvisor],
) -> None:
    settings = Settings(
        _env_file=None,
        ai_provider=ai_provider,
        ai_api_key="test-key",
        ai_model="test-model",
        knowledge_sources=["external_knowledge"],
    )

    advisor = _build_advisor(settings)
    try:
        assert isinstance(advisor, advisor_type)
        assert advisor.provider == ai_provider  # type: ignore[attr-defined]
    finally:
        await advisor.aclose()  # type: ignore[attr-defined]


def test_factory_rejects_an_unknown_ai_provider() -> None:
    settings = Settings(
        _env_file=None,
        ai_provider="unknown_protocol",
        knowledge_sources=["external_knowledge"],
    )

    with pytest.raises(ValueError, match="Unsupported AI_PROVIDER: unknown_protocol"):
        _build_advisor(settings)
