import asyncio
from pathlib import Path

import httpx
import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.external_knowledge import (
    ExternalKnowledgeAPIError,
    ExternalKnowledgeClient,
    ExternalKnowledgeSource,
    KnowledgeSearchResponse,
    KnowledgeSearchResult,
    _distance_to_relevance,
    format_items_for_advisor,
)
from app.adapters.knowledge import KnowledgeSourceRegistry
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import INCONCLUSIVE_ROOT_CAUSE_SUMMARY, AnalysisBasisSource


async def no_sleep(_seconds: float) -> None:
    return None


def knowledge_result(
    content: str,
    source: str,
    distance: float,
) -> KnowledgeSearchResult:
    return KnowledgeSearchResult(
        content=content,
        source=source,
        raw_score=distance,
        relevance=_distance_to_relevance(distance),
        metadata={"source": source},
    )


def test_cosine_distance_conversion_is_bounded() -> None:
    assert _distance_to_relevance(0) == 1
    assert _distance_to_relevance(0.25) == 0.75
    assert _distance_to_relevance(1) == 0
    assert _distance_to_relevance(2) == 0
    assert _distance_to_relevance(-1) == 0
    assert _distance_to_relevance(float("nan")) == 0
    assert _distance_to_relevance(float("inf")) == 0


def test_invalid_scores_and_empty_content_are_not_accepted() -> None:
    response = ExternalKnowledgeClient._parse_search_response(
        {
            "results": [
                {"content": "nan", "score": float("nan")},
                {"content": "infinite", "score": float("inf")},
                {"content": "", "score": 0.1},
                {"content": "valid", "score": 0.2},
            ]
        },
        "replica lag",
    )

    assert [item.content for item in response.items] == ["valid"]


@pytest.mark.asyncio
async def test_search_uses_knowledge_pack_contract_and_bearer_key() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["authorization"] = request.headers.get("Authorization")
        captured["body"] = request.content
        return httpx.Response(
            200,
            json={
                "query": "replica lag",
                "results": [
                    {
                        "content": "Check replica apply latency.",
                        "metadata": {"source": "replication.md"},
                        "score": 0.2,
                    }
                ],
                "total": 1,
            },
        )

    client = ExternalKnowledgeClient(
        "http://knowledge.test",
        api_key="secret",
        transport=httpx.MockTransport(handler),
    )
    response = await client.search("replica lag", top_k=3)

    assert captured["path"] == "/search"
    assert captured["authorization"] == "Bearer secret"
    assert b'"top_k":3' in captured["body"]
    assert response.items[0].relevance == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_search_stops_after_bounded_recoverable_error_retries() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, json={"detail": "temporarily unavailable"})

    client = ExternalKnowledgeClient(
        "http://knowledge.test",
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    with pytest.raises(ExternalKnowledgeAPIError, match="HTTP503"):
        await client.search("replica lag")

    assert attempts == 3


@pytest.mark.asyncio
async def test_registry_times_out_one_source_without_blocking_other_sources() -> None:
    class HangingSource:
        name = "hanging"

        async def search(self, alert):  # type: ignore[no-untyped-def]
            del alert
            await asyncio.sleep(60)
            return []

    class EmptySource:
        name = "empty"

        async def search(self, alert):  # type: ignore[no-untyped-def]
            del alert
            return []

    settings = Settings(_env_file=None, ai_provider="fake")
    runtime = build_runtime(settings)
    alert = runtime.service.source_registry.normalize(
        "canonical",
        {
            "external_id": "knowledge-timeout",
            "severity": "INFO",
            "title": "Connection pressure",
            "reason": "connections_high",
        },
    )
    registry = KnowledgeSourceRegistry(
        [HangingSource(), EmptySource()],
        source_timeout_seconds=0.01,
    )

    results = await registry.search(["hanging", "empty", "missing"], alert)

    assert [(item.source, item.status) for item in results] == [
        ("hanging", "unavailable"),
        ("empty", "no_match"),
        ("missing", "unavailable"),
    ]
    assert results[0].error == "TimeoutError"
    assert results[2].error == "SourceNotRegistered"


@pytest.mark.asyncio
async def test_registry_preserves_safe_provider_error_code() -> None:
    class FailingSource:
        name = "external_knowledge"

        async def search(self, alert):  # type: ignore[no-untyped-def]
            del alert
            raise ExternalKnowledgeAPIError(
                "temporarily unavailable",
                code="HTTP503",
                status_code=503,
            )

    settings = Settings(_env_file=None, ai_provider="fake")
    runtime = build_runtime(settings)
    alert = runtime.service.source_registry.normalize(
        "canonical",
        {
            "external_id": "knowledge-http-error",
            "severity": "INFO",
            "title": "Connection pressure",
            "reason": "connections_high",
        },
    )

    result = (await KnowledgeSourceRegistry([FailingSource()]).search(
        ["external_knowledge"], alert
    ))[0]

    assert result.status == "unavailable"
    assert result.error == "HTTP503"


def test_persisted_excerpt_has_stable_traceable_identity() -> None:
    item = knowledge_result(
        "Check read-only replica diagnostics.",
        "replication.md",
        0.15,
    )

    first = format_items_for_advisor([item])[0]
    second = format_items_for_advisor([item])[0]

    assert first.knowledge_id == second.knowledge_id
    assert first.source_uri == "file://replication.md"
    assert first.score == pytest.approx(0.85)


def test_duplicate_chunks_share_one_stable_reference() -> None:
    item = knowledge_result("Same chunk.", "same.md", 0.2)

    formatted = format_items_for_advisor([item, item])

    assert len(formatted) == 1
    assert formatted[0].knowledge_id.startswith("external-")


class StubExternalKnowledgeClient:
    def __init__(self, items: list[KnowledgeSearchResult]) -> None:
        self.items = items

    async def search_alert(self, alert, *, top_k=5):  # type: ignore[no-untyped-def]
        return KnowledgeSearchResponse(
            query=alert.title,
            items=self.items[:top_k],
            total=len(self.items),
        )


class CapturingAdvisor(FakeAIAdvisor):
    def __init__(self) -> None:
        self.knowledge = []
        self.knowledge_match_summary = ""

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        knowledge,
        evidence=None,
        knowledge_match_summary="",
    ):
        self.knowledge = list(knowledge)
        self.knowledge_match_summary = knowledge_match_summary
        return await super().advise(
            alert,
            knowledge,
            evidence=evidence,
            knowledge_match_summary=knowledge_match_summary,
        )


def external_only_settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        external_knowledge_base_url="http://knowledge.test",
        external_knowledge_min_relevance=0.60,
        knowledge_sources=["external_knowledge"],
    )


@pytest.mark.asyncio
async def test_threshold_rejects_low_relevance_before_advisor(
    tmp_path: Path,
) -> None:
    advisor = CapturingAdvisor()
    source = ExternalKnowledgeSource(
        StubExternalKnowledgeClient(
            [
                knowledge_result("Relevant replica diagnostic.", "replica.md", 0.2),
                knowledge_result("Unrelated backup article.", "backup.md", 0.9),
            ]
        ),
        limit=5,
        min_relevance=0.60,
    )
    runtime = build_runtime(
        external_only_settings(tmp_path),
        advisor=advisor,
        knowledge_registry=KnowledgeSourceRegistry([source]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "external-threshold-1",
            "severity": "WARNING",
            "title": "Replica lag is high",
            "reason": "replica_lag",
            "database": {"engine": "mysql"},
        },
    )

    assert len(advisor.knowledge) == 1
    assert result.recommendation is not None
    assert len(result.recommendation.knowledge_matches) == 1
    assert AnalysisBasisSource.KNOWLEDGE in {
        basis.source for basis in result.recommendation.analysis_bases
    }
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_all_low_relevance_results_produce_explicit_no_match(
    tmp_path: Path,
) -> None:
    source = ExternalKnowledgeSource(
        StubExternalKnowledgeClient(
            [knowledge_result("Unrelated document.", "unrelated.md", 0.95)]
        ),
        limit=5,
        min_relevance=0.60,
    )
    runtime = build_runtime(
        external_only_settings(tmp_path),
        knowledge_registry=KnowledgeSourceRegistry([source]),
    )
    await runtime.repository.initialize()

    result = await runtime.service.analyze(
        "canonical",
        {
            "external_id": "external-threshold-2",
            "severity": "INFO",
            "title": "Connection pressure",
            "reason": "connections_high",
        },
    )

    assert result.recommendation is not None
    assert result.recommendation.knowledge_matches == []
    assert "所选知识来源均未命中" in result.recommendation.knowledge_match_summary
    assert result.recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.recommendation.root_causes == []
    completion = next(
        item for item in result.progress if item.message == "知识匹配完成。"
    )
    assert completion.details["knowledge_match_count"] == 0
    assert completion.details["knowledge_match_summary"] == (
        result.recommendation.knowledge_match_summary
    )
    source_details = completion.details["sources"]
    assert len(source_details) == 1
    assert source_details[0]["source"] == "external_knowledge"
    assert source_details[0]["status"] == "no_match"
    assert source_details[0]["match_count"] == 0
    assert source_details[0]["error"] is None
    assert source_details[0]["duration_ms"] >= 0
    await runtime.repository.close()  # type: ignore[attr-defined]
