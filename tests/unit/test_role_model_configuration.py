"""Role-specific model configuration for the three model usage points.

Covers: ReAct round decisions (``decide_investigation``), final root-cause
analysis (``advise``) and the MCP tool inner loop (``request_mcp_tool_call``)
plus the per-role reasoning-effort wiring.
"""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import app.adapters.ai as ai_module
from app.adapters.ai import OpenAICompatibleAdvisor
from app.config import RUNTIME_SETTINGS_KEYS, Settings
from tests.unit.test_ai import make_alert


def build_advisor(**overrides: str) -> OpenAICompatibleAdvisor:
    return OpenAICompatibleAdvisor(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model=overrides.get("model", "main-model"),
        max_tokens=1024,
        timeout_seconds=5,
        json_mode=True,
        react_model=overrides.get("react_model"),
        react_reasoning_effort=overrides.get("react_reasoning_effort"),
        mcp_model=overrides.get("mcp_model"),
        mcp_reasoning_effort=overrides.get("mcp_reasoning_effort"),
        reasoning_effort=overrides.get("reasoning_effort"),
    )


def test_advisor_roles_fall_back_to_main_model_by_default() -> None:
    advisor = build_advisor()
    assert advisor.model == "main-model"
    assert advisor.react_model == "main-model"
    assert advisor.mcp_model == "main-model"
    assert advisor.reasoning_effort == ""
    assert advisor.react_reasoning_effort == ""
    assert advisor.mcp_reasoning_effort == ""


def test_advisor_roles_apply_configured_overrides() -> None:
    advisor = build_advisor(
        react_model="react-lite",
        mcp_model="mcp-lite",
        react_reasoning_effort="low",
        reasoning_effort="high",
        mcp_reasoning_effort="max",
    )
    assert advisor.model == "main-model"
    assert advisor.react_model == "react-lite"
    assert advisor.mcp_model == "mcp-lite"
    assert advisor.react_reasoning_effort == "low"
    assert advisor.reasoning_effort == "high"
    assert advisor.mcp_reasoning_effort == "max"


@pytest.mark.asyncio
async def test_decide_investigation_uses_react_model_and_effort() -> None:
    advisor = build_advisor(
        react_model="react-lite",
        react_reasoning_effort="low",
    )
    captured: list[dict[str, object]] = []

    async def complete(  # type: ignore[no-untyped-def]
        messages, *, reasoning_callback=None, model=None, reasoning_effort=None
    ):
        captured.append({"model": model, "reasoning_effort": reasoning_effort})
        metadata = ai_module.AdvisorMetadata(
            provider="test",
            model=model or advisor.model,
            prompt_version="test",
        )
        return '{"action":"finish","reason":"done"}', metadata

    advisor._complete = complete
    result = await advisor.decide_investigation(
        alert=make_alert(),
        knowledge=[],
        knowledge_match_summary="",
        evidence=[],
        available_tools=[],
        react_round=2,
        react_max_rounds=8,
    )
    await advisor.aclose()

    assert result.decision.action == "finish"
    assert captured == [{"model": "react-lite", "reasoning_effort": "low"}]
    assert result.metadata.model == "react-lite"


@pytest.mark.asyncio
async def test_advise_uses_main_model_and_analysis_effort() -> None:
    advisor = build_advisor(
        react_model="react-lite",
        reasoning_effort="high",
    )
    captured: list[dict[str, object]] = []

    async def complete(  # type: ignore[no-untyped-def]
        messages, *, reasoning_callback=None, model=None, reasoning_effort=None
    ):
        captured.append({"model": model, "reasoning_effort": reasoning_effort})
        recommendation = ai_module.Recommendation.model_construct(
            summary="结论",
            analysis_bases=[],
            temporary_solutions=[],
            long_term_optimizations=[],
            confidence=0.5,
        )
        metadata = ai_module.AdvisorMetadata(
            provider="test",
            model=model or advisor.model,
            prompt_version="test",
        )
        return recommendation.model_dump_json(), metadata

    advisor._complete = complete
    await advisor.advise(make_alert(), [])
    await advisor.aclose()

    assert captured == [{"model": None, "reasoning_effort": "high"}]


@pytest.mark.asyncio
async def test_mcp_tool_call_uses_mcp_model_and_effort() -> None:
    advisor = build_advisor(
        mcp_model="mcp-lite",
        mcp_reasoning_effort="medium",
    )
    calls: list[dict[str, object]] = []

    class ToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(dict(kwargs))
            return SimpleNamespace(
                id="mcp-request-1",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    id="tool-call-1",
                                    function=SimpleNamespace(
                                        name="ensure_login_gymJPA",
                                        arguments="{}",
                                    ),
                                )
                            ]
                        )
                    )
                ],
            )

    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=ToolCompletions()))
    result = await advisor.request_mcp_tool_call(
        messages=[{"role": "user", "content": "confirm login"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "ensure_login_gymJPA",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )

    assert result.name == "ensure_login_gymJPA"
    assert calls[0]["model"] == "mcp-lite"
    assert calls[0]["reasoning_effort"] == "medium"


@pytest.mark.asyncio
async def test_mcp_tool_call_omits_effort_when_not_configured() -> None:
    advisor = build_advisor()
    calls: list[dict[str, object]] = []

    class ToolCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(dict(kwargs))
            return SimpleNamespace(
                id="mcp-request-2",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    id="tool-call-2",
                                    function=SimpleNamespace(
                                        name="ensure_login_gymJPA",
                                        arguments="{}",
                                    ),
                                )
                            ]
                        )
                    )
                ],
            )

    advisor._client = SimpleNamespace(chat=SimpleNamespace(completions=ToolCompletions()))
    await advisor.request_mcp_tool_call(
        messages=[{"role": "user", "content": "confirm login"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "ensure_login_gymJPA",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )

    assert calls[0]["model"] == "main-model"
    assert "reasoning_effort" not in calls[0]


def test_responses_request_maps_effort_to_reasoning_configuration() -> None:
    request = ai_module.OpenAIResponsesAdvisor._request_kwargs(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "model": "responses-model",
            "max_tokens": 1024,
            "reasoning_effort": "low",
        }
    )
    assert request["reasoning"] == {"effort": "low"}

    without_effort = ai_module.OpenAIResponsesAdvisor._request_kwargs(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "model": "responses-model",
            "max_tokens": 1024,
        }
    )
    assert "reasoning" not in without_effort
    assert "reasoning_effort" not in without_effort


def test_settings_rejects_unknown_reasoning_effort() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate(
            {"ai_provider": "openai_compatible", "ai_react_reasoning_effort": "ultra"}
        )


def test_settings_normalizes_reasoning_effort() -> None:
    settings = Settings.model_validate(
        {
            "ai_provider": "openai_compatible",
            "ai_react_reasoning_effort": " LOW ",
            "ai_reasoning_effort": "Max",
            "ai_mcp_reasoning_effort": "xHigh",
        }
    )
    assert settings.ai_react_reasoning_effort == "low"
    assert settings.ai_reasoning_effort == "max"
    assert settings.ai_mcp_reasoning_effort == "xhigh"


def test_role_model_settings_are_runtime_editable() -> None:
    assert {
        "ai_react_model",
        "ai_react_reasoning_effort",
        "ai_reasoning_effort",
        "ai_mcp_model",
        "ai_mcp_reasoning_effort",
    }.issubset(RUNTIME_SETTINGS_KEYS)


def test_factory_builds_advisor_with_role_configuration() -> None:
    from app.application.factory import _build_advisor

    settings = Settings.model_validate(
        {
            "ai_provider": "openai_compatible",
            "ai_api_key": "test-key",
            "ai_base_url": "https://models.example.test/v1",
            "ai_model": "main-model",
            "ai_react_model": "react-lite",
            "ai_react_reasoning_effort": "low",
            "ai_mcp_model": "mcp-lite",
            "ai_mcp_reasoning_effort": "medium",
            "ai_reasoning_effort": "high",
        }
    )
    advisor = _build_advisor(settings)
    assert isinstance(advisor, OpenAICompatibleAdvisor)
    assert advisor.model == "main-model"
    assert advisor.react_model == "react-lite"
    assert advisor.react_reasoning_effort == "low"
    assert advisor.mcp_model == "mcp-lite"
    assert advisor.mcp_reasoning_effort == "medium"
    assert advisor.reasoning_effort == "high"


@pytest.mark.asyncio
async def test_runtime_patch_roundtrip_updates_role_configuration(tmp_path) -> None:
    from app.application.admin import RuntimeSettingsManager
    from app.application.factory import _build_advisor

    settings = Settings.model_validate(
        {
            "ai_provider": "openai_compatible",
            "ai_api_key": "test-key",
            "ai_base_url": "https://models.example.test/v1",
            "ai_model": "main-model",
            "runtime_settings_path": str(tmp_path / "runtime-settings.json"),
        }
    )
    manager = RuntimeSettingsManager(settings.runtime_settings_path)

    updated, _, changed = await manager.patch(
        settings,
        {
            "ai_react_model": "react-lite",
            "ai_react_reasoning_effort": "low",
            "ai_mcp_model": "mcp-lite",
            "ai_mcp_reasoning_effort": "medium",
            "ai_reasoning_effort": "high",
        },
        expected_revision=manager.revision,
    )

    assert changed == [
        "ai_mcp_model",
        "ai_mcp_reasoning_effort",
        "ai_react_model",
        "ai_react_reasoning_effort",
        "ai_reasoning_effort",
    ]
    advisor = _build_advisor(updated)
    assert isinstance(advisor, OpenAICompatibleAdvisor)
    assert advisor.react_model == "react-lite"
    assert advisor.mcp_model == "mcp-lite"

    cleared, _, changed = await manager.patch(
        updated,
        {
            "ai_react_model": "",
            "ai_react_reasoning_effort": "",
        },
        expected_revision=manager.revision,
    )
    assert changed == ["ai_react_model", "ai_react_reasoning_effort"]
    reverted = _build_advisor(cleared)
    assert isinstance(reverted, OpenAICompatibleAdvisor)
    assert reverted.react_model == "main-model"
    assert reverted.react_reasoning_effort == ""
