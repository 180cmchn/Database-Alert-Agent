from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.adapters.tool_result_analysis import OpenAICompatibleToolResultAnalyzer
from app.agent_runtime.contracts import ArtifactRef
from app.domain.errors import AdvisorError


def _artifact() -> ArtifactRef:
    artifact_id = uuid4()
    return ArtifactRef(
        artifact_id=artifact_id,
        kind="raw_tool_result",
        uri=f"agent-artifact://{artifact_id}",
        sha256="a" * 64,
        size_bytes=100,
    )


@pytest.mark.asyncio
async def test_openai_tool_result_analyzer_uses_isolated_strict_schema() -> None:
    calls: list[dict[str, object]] = []

    class Completions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            content = json.dumps(
                {
                    "summary": "发现连接数升高。",
                    "observations": [
                        {
                            "statement": "连接数为100。",
                            "source_paths": ["/structured_data/value"],
                        }
                    ],
                    "anomalies": [
                        {
                            "statement": "连接数相对基线异常升高。",
                            "source_paths": ["/structured_data/value"],
                        }
                    ],
                    "limitations": [],
                    "analysis_usable": True,
                }
            )
            return SimpleNamespace(
                id="tool-result-request-1",
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    analyzer = object.__new__(OpenAICompatibleToolResultAnalyzer)
    analyzer._api_key = "test"
    analyzer._model = "shared-model"
    analyzer._max_tokens = 16_384
    analyzer._json_mode = True
    analyzer._input_chunk_chars = 24_000
    analyzer._client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    artifact = _artifact()

    result = await analyzer.analyze(
        tool_name="metrics",
        source_system="prometheus_mcp",
        request={"read_only": True},
        raw_result={"status": "SUCCESS", "structured_data": {"value": 100}},
        artifact=artifact,
    )

    assert result.source_artifact_id == artifact.artifact_id
    assert result.source_sha256 == artifact.sha256
    assert result.request_id == "tool-result-request-1"
    assert result.observations[0].source_paths == ["/structured_data/value"]
    assert result.anomalies[0].source_paths == ["/structured_data/value"]
    assert result.source_coverage_complete is True
    assert len(calls) == 1
    assert calls[0]["temperature"] == 0
    response_format = calls[0]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True


@pytest.mark.asyncio
async def test_tool_result_analyzer_rejects_untraceable_observation_after_repair() -> None:
    class Completions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            content = json.dumps(
                {
                    "summary": "无法核验。",
                    "observations": [
                        {"statement": "虚构事实", "source_paths": ["/missing"]}
                    ],
                    "anomalies": [],
                    "limitations": [],
                    "analysis_usable": True,
                }
            )
            return SimpleNamespace(
                id="bad-request",
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    analyzer = object.__new__(OpenAICompatibleToolResultAnalyzer)
    analyzer._api_key = "test"
    analyzer._model = "shared-model"
    analyzer._max_tokens = 16_384
    analyzer._json_mode = True
    analyzer._input_chunk_chars = 24_000
    analyzer._client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))

    with pytest.raises(AdvisorError, match="invalid after repair"):
        await analyzer.analyze(
            tool_name="metrics",
            source_system="prometheus_mcp",
            request={},
            raw_result={"status": "SUCCESS", "structured_data": {"value": 100}},
            artifact=_artifact(),
        )


@pytest.mark.asyncio
async def test_large_result_is_losslessly_partitioned_without_child_causality() -> None:
    calls: list[dict[str, object]] = []
    source_fragments: list[dict[str, object]] = []

    class Completions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            messages = kwargs["messages"]
            payload = json.loads(messages[1]["content"])
            entries = payload.get("entries")
            if isinstance(entries, list):
                source_fragments.extend(entries)
                available_paths = [str(entry["path"]) for entry in entries]
                source_path = (
                    "/structured_data/payload"
                    if "/structured_data/payload" in available_paths
                    else available_paths[0]
                )
                source_entry = next(
                    entry for entry in entries if str(entry["path"]) == source_path
                )
                source_spans = (
                    [
                        {
                            "path": source_path,
                            "character_start": source_entry["character_start"],
                            "character_end": source_entry["character_end"],
                            "character_total": source_entry["character_total"],
                        }
                    ]
                    if "character_start" in source_entry
                    else []
                )
                observations = [
                    {
                        "statement": "工具返回包含日志文本。",
                        "source_paths": [source_path],
                        "source_spans": source_spans,
                    }
                ]
                analysis_usable = True
            else:
                observations = []
                analysis_usable = False
            content = json.dumps(
                {
                    "summary": "已转换为可追溯事实。",
                    "observations": observations,
                    "anomalies": [],
                    "limitations": [],
                    "analysis_usable": analysis_usable,
                }
            )
            return SimpleNamespace(
                id=f"fact-projection-{len(calls)}",
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    analyzer = object.__new__(OpenAICompatibleToolResultAnalyzer)
    analyzer._api_key = "test"
    analyzer._model = "shared-model"
    analyzer._max_tokens = 16_384
    analyzer._json_mode = True
    analyzer._input_chunk_chars = 4_096
    analyzer._client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    original_text = "slow-log-line\n" * 2_000

    result = await analyzer.analyze(
        tool_name="query_mcp_archery",
        source_system="archery_mcp",
        request={"read_only": True},
        raw_result={"status": "SUCCESS", "structured_data": {"payload": original_text}},
        artifact=_artifact(),
    )

    text_entries = [
        entry
        for entry in source_fragments
        if entry.get("path") == "/structured_data/payload"
        and isinstance(entry.get("text_fragment"), str)
    ]
    assert len(text_entries) > 1
    assert "".join(str(entry["text_fragment"]) for entry in text_entries) == original_text
    assert [entry["character_start"] for entry in text_entries] == [
        0,
        *[entry["character_end"] for entry in text_entries[:-1]],
    ]
    assert text_entries[-1]["character_end"] == len(original_text)
    assert result.source_coverage_complete is True
    payload_observations = [
        item
        for item in result.observations
        if item.source_paths == ["/structured_data/payload"]
    ]
    assert payload_observations
    assert all(item.source_spans for item in payload_observations)
    assert all(
        item.source_spans[0].character_total == len(original_text)
        for item in payload_observations
    )
    for call in calls:
        schema = call["response_format"]["json_schema"]["schema"]
        assert "root_cause_eligible" not in schema["properties"]
        assert "result_complete" not in schema["properties"]


@pytest.mark.asyncio
async def test_large_result_host_preserves_more_than_two_hundred_chunk_facts() -> None:
    class Completions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            payload = json.loads(kwargs["messages"][1]["content"])
            entries = payload.get("entries")
            if isinstance(entries, list):
                observations = [
                    {
                        "statement": f"事实 {entry['path']}",
                        "source_paths": [entry["path"]],
                        "source_spans": [],
                    }
                    for entry in entries
                ]
                limitations = [f"限制 {entry['path']}" for entry in entries]
                usable = bool(observations)
            else:
                observations = []
                limitations = []
                usable = False
            content = json.dumps(
                {
                    "summary": "分片事实摘要。",
                    "observations": observations,
                    "anomalies": observations,
                    "limitations": limitations,
                    "analysis_usable": usable,
                }
            )
            return SimpleNamespace(
                id="many-facts",
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    analyzer = object.__new__(OpenAICompatibleToolResultAnalyzer)
    analyzer._api_key = "test"
    analyzer._model = "shared-model"
    analyzer._max_tokens = 16_384
    analyzer._json_mode = True
    analyzer._input_chunk_chars = 4_096
    analyzer._client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    values = {f"field_{index:03d}": "x" * 80 for index in range(205)}

    result = await analyzer.analyze(
        tool_name="query_mcp",
        source_system="generic_mcp",
        request={"read_only": True},
        raw_result={"status": "SUCCESS", "structured_data": values},
        artifact=_artifact(),
    )

    field_observations = [
        item for item in result.observations if item.source_paths[0].startswith("/structured_data/")
    ]
    field_anomalies = [
        item for item in result.anomalies if item.source_paths[0].startswith("/structured_data/")
    ]
    field_limitations = [
        item for item in result.limitations if item.startswith("限制 /structured_data/")
    ]
    assert len(field_observations) == 205
    assert len(field_anomalies) == 205
    assert len(field_limitations) == 205
    assert field_observations[0].source_paths == ["/structured_data/field_000"]
    assert field_observations[-1].source_paths == ["/structured_data/field_204"]


@pytest.mark.parametrize(
    "causal_statement",
    [
        "根因是连接池泄漏。",
        "连接池泄漏是本次故障的主要因素。",
        "数据库崩溃源于磁盘写满。",
        "连接耗尽解释了告警。",
        "连接数异常说明连接池泄漏。",
        "磁盘空间不足与告警一致。",
        "The outage was caused by connection pool exhaustion.",
        "Disk saturation explains the database failure.",
        "These samples suggest a memory leak.",
        "Lock contention is the contributing factor.",
    ],
)
@pytest.mark.asyncio
async def test_child_projection_rejects_causal_judgment_after_repair(
    causal_statement: str,
) -> None:
    class Completions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            del kwargs
            content = json.dumps(
                {
                    "summary": causal_statement,
                    "observations": [
                        {
                            "statement": causal_statement,
                            "source_paths": ["/structured_data/value"],
                        }
                    ],
                    "anomalies": [],
                    "limitations": [],
                    "analysis_usable": True,
                }
            )
            return SimpleNamespace(
                id="causal-child-output",
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                usage=None,
            )

    analyzer = object.__new__(OpenAICompatibleToolResultAnalyzer)
    analyzer._api_key = "test"
    analyzer._model = "shared-model"
    analyzer._max_tokens = 16_384
    analyzer._json_mode = True
    analyzer._input_chunk_chars = 24_000
    analyzer._client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))

    with pytest.raises(AdvisorError, match="invalid after repair"):
        await analyzer.analyze(
            tool_name="metrics",
            source_system="prometheus_mcp",
            request={},
            raw_result={"status": "SUCCESS", "structured_data": {"value": 100}},
            artifact=_artifact(),
        )
