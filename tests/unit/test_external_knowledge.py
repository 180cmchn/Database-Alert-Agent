from pathlib import Path

import httpx
import pytest

from app.adapters.ai import FakeAIAdvisor
from app.adapters.external_knowledge import (
    ExternalKnowledgeClient,
    KnowledgeSearchResponse,
    KnowledgeSearchResult,
    _distance_to_relevance,
    format_items_for_advisor,
)
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
async def test_search_retries_recoverable_errors_without_count_limit() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts <= 4:
            return httpx.Response(503, json={"detail": "temporarily unavailable"})
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
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )

    response = await client.search("replica lag")

    assert attempts == 5
    assert response.items[0].content == "Check replica apply latency."


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
        self.external_knowledge = []
        self.knowledge_match_summary = ""

    async def advise(  # type: ignore[no-untyped-def]
        self,
        alert,
        runbooks,
        evidence=None,
        external_knowledge=None,
        knowledge_match_summary="",
    ):
        self.external_knowledge = list(external_knowledge or [])
        self.knowledge_match_summary = knowledge_match_summary
        return await super().advise(
            alert,
            runbooks,
            evidence=evidence,
            external_knowledge=external_knowledge,
            knowledge_match_summary=knowledge_match_summary,
        )


def external_only_settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=tmp_path / "unused-runbooks",
        external_knowledge_enabled=True,
        external_knowledge_base_url="http://knowledge.test",
        external_knowledge_min_relevance=0.60,
        knowledge_sources=["external_knowledge"],
    )


@pytest.mark.asyncio
async def test_threshold_rejects_low_relevance_before_advisor(
    tmp_path: Path,
) -> None:
    advisor = CapturingAdvisor()
    runtime = build_runtime(external_only_settings(tmp_path), advisor=advisor)
    runtime.service.agent.ctx.external_knowledge_client = StubExternalKnowledgeClient(
        [
            knowledge_result("Relevant replica diagnostic.", "replica.md", 0.2),
            knowledge_result("Unrelated backup article.", "backup.md", 0.9),
        ]
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

    assert len(advisor.external_knowledge) == 1
    assert "低于相关度阈值" in advisor.knowledge_match_summary
    assert result.recommendation is not None
    assert len(result.recommendation.external_knowledge_matches) == 1
    assert AnalysisBasisSource.EXTERNAL_KNOWLEDGE in {
        basis.source for basis in result.recommendation.analysis_bases
    }
    await runtime.repository.close()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_all_low_relevance_results_produce_explicit_no_match(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(external_only_settings(tmp_path))
    runtime.service.agent.ctx.external_knowledge_client = StubExternalKnowledgeClient(
        [knowledge_result("Unrelated document.", "unrelated.md", 0.95)]
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
    assert result.recommendation.external_knowledge_matches == []
    assert "已拒绝匹配" in result.recommendation.knowledge_match_summary
    assert "所选知识来源均未命中" in result.recommendation.knowledge_match_summary
    assert result.recommendation.summary == INCONCLUSIVE_ROOT_CAUSE_SUMMARY
    assert result.recommendation.root_causes == []
    assert result.recommendation.confidence <= 0.45
    await runtime.repository.close()  # type: ignore[attr-defined]
