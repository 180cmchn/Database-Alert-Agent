"""External knowledge API client for the KnowledgePack (LangChain + Chroma) service.

This adapter bridges the project's analyze-database-alerts skill contract with the
actual KnowledgePack HTTP API. It follows the same defensive patterns as the
FlashDuty adapter: typed errors, bounded retries, and graceful degradation.

Per the skill rules (SKILL.md §4):
- Results are advisory data, never live evidence.
- KnowledgePack does not return an explicit ``quality_status``; every result is
  treated as ``draft``.
- API failure or an empty response degrades gracefully to local knowledge.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

import httpx

from app.application.sanitization import sanitize_text
from app.domain.models import NormalizedAlert

logger = logging.getLogger(__name__)


class ExternalKnowledgeError(RuntimeError):
    """Base error for the external knowledge integration."""


class ExternalKnowledgeConfigurationError(ExternalKnowledgeError):
    """The client is not configured or missing required parameters."""


class ExternalKnowledgeAPIError(ExternalKnowledgeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "ExternalKnowledgeError",
        status_code: int | None = None,
    ) -> None:
        safe_message = sanitize_text(message)[:1000]
        details = [code]
        if status_code is not None:
            details.append(f"http_status={status_code}")
        super().__init__(f"ExternalKnowledge {' '.join(details)}: {safe_message}")
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class KnowledgeSearchResult:
    """A single knowledge item returned by the external service."""

    content: str
    source: str
    raw_score: float
    relevance: float
    metadata: dict[str, Any]


@dataclass(frozen=True)
class KnowledgeSearchResponse:
    """Parsed response from ``POST /search``."""

    query: str
    items: list[KnowledgeSearchResult]
    total: int


# Chroma returns an L2 distance where *lower* means *more similar*.
# We invert and squash it into a 0-1 relevance score where higher is better.
# The transformation ``1 / (1 + distance)`` maps 0 → 1.0 and decays toward 0.


def _distance_to_relevance(distance: float) -> float:
    """Convert a Chroma L2 distance into a 0-1 relevance score.

    The transformation is ``1 / (1 + distance)`` which maps 0 → 1.0 and
    decays smoothly toward 0 as distance grows. This is intentionally simple
    and does not claim to be a calibrated probability.
    """

    try:
        d = float(distance)
    except (TypeError, ValueError):
        return 0.0
    if d < 0:
        return 0.0
    return 1.0 / (1.0 + d)


def build_search_query(alert: NormalizedAlert) -> str:
    """Build a natural-language search query from a normalized alert.

    The query prioritizes database engine, alert type, metric/error pattern, and
    service context so that the vector store returns the most relevant runbooks,
    incident cases, or references.
    """

    parts: list[str] = []
    if alert.database and alert.database.engine:
        parts.append(alert.database.engine)
    if alert.alert_type and alert.alert_type != "unknown":
        parts.append(alert.alert_type)
    if alert.metric_name:
        parts.append(alert.metric_name)
    if alert.error_pattern:
        parts.append(alert.error_pattern)
    if alert.title:
        parts.append(alert.title)
    if alert.service_name and alert.service_name != "unknown":
        parts.append(alert.service_name)
    if alert.resource_type:
        parts.append(alert.resource_type)
    query = " ".join(dict.fromkeys(parts))  # deduplicate while preserving order
    # Fallback so the query is never empty (KnowledgePack requires minLength=1)
    return query.strip() or alert.alert_type or "database alert"


class ExternalKnowledgeClient:
    """HTTP client for the KnowledgePack search API.

    The client is safe to construct even when the feature is disabled; callers
    check ``is_enabled`` or simply avoid construction via the factory in
    ``app.application.factory``.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8001",
        *,
        api_key: str = "",
        timeout_seconds: float = 30,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key.strip()
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._transport = transport
        self._sleep = sleep

    @property
    def is_enabled(self) -> bool:
        return bool(self.base_url)

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        with_score: bool = True,
    ) -> KnowledgeSearchResponse:
        """Call ``POST /search`` on the KnowledgePack service.

        Raises:
            ExternalKnowledgeAPIError: On network or HTTP errors after retries.
        """

        if not query.strip():
            raise ExternalKnowledgeConfigurationError("query must not be empty")
        payload: dict[str, Any] = {
            "query": query.strip()[:2000],
            "top_k": min(max(top_k, 1), 20),
            "with_score": with_score,
        }

        response = await self._request("POST", "/search", json=payload)
        return self._parse_search_response(response, query)

    async def health(self) -> dict[str, Any]:
        """Call ``GET /stats`` as a lightweight health / readiness probe.

        Returns the raw stats dictionary. Returns an empty dict on failure so
        callers can treat health checks as non-fatal.
        """

        try:
            response = await self._request("GET", "/stats")
            return response if isinstance(response, dict) else {}
        except ExternalKnowledgeAPIError:
            logger.debug("external_knowledge_health_check_failed", exc_info=True)
            return {}

    async def search_alert(
        self, alert: NormalizedAlert, *, top_k: int = 5
    ) -> KnowledgeSearchResponse:
        """Convenience wrapper that builds a query from the alert context."""

        query = build_search_query(alert)
        return await self.search(query, top_k=top_k, with_score=True)

    async def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            transport=self._transport,
            follow_redirects=False,
            headers=self._headers(),
        ) as client:
            response: httpx.Response | None = None
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.request(method, url, json=json)
                except httpx.TransportError as exc:
                    if attempt >= self.max_retries:
                        raise ExternalKnowledgeAPIError(
                            type(exc).__name__, code="NetworkError"
                        ) from exc
                    await self._sleep(min(2**attempt, 10))
                    continue

                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < self.max_retries:
                        await self._sleep(self._retry_delay(response, attempt))
                        continue
                break

        if response is None:  # pragma: no cover - loop contract guard
            raise ExternalKnowledgeAPIError("No response received", code="NetworkError")
        return self._decode_response(response)

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After", "")
        try:
            return min(max(float(retry_after), 0), 10)
        except ValueError:
            return min(2**attempt, 10)

    def _decode_response(self, response: httpx.Response) -> Any:
        if response.is_error:
            detail = ""
            try:
                body = response.json()
                if isinstance(body, dict):
                    detail = str(body.get("detail") or body.get("message") or "")
            except ValueError:
                pass
            raise ExternalKnowledgeAPIError(
                detail or response.reason_phrase or "Request failed",
                code=f"HTTP{response.status_code}",
                status_code=response.status_code,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ExternalKnowledgeAPIError(
                "Response was not valid JSON",
                code="InvalidResponse",
                status_code=response.status_code,
            ) from exc

    @staticmethod
    def _parse_search_response(
        body: Any, original_query: str
    ) -> KnowledgeSearchResponse:
        if not isinstance(body, dict):
            raise ExternalKnowledgeAPIError(
                "Search response was not an object", code="InvalidResponse"
            )
        results = body.get("results")
        if not isinstance(results, list):
            results = []
        items: list[KnowledgeSearchResult] = []
        for entry in results:
            if not isinstance(entry, dict):
                continue
            content = str(entry.get("content") or "")
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            source = str(metadata.get("source") or "")
            raw_score = float(entry.get("score") or 0.0)
            relevance = _distance_to_relevance(raw_score)
            items.append(
                KnowledgeSearchResult(
                    content=content,
                    source=source,
                    raw_score=raw_score,
                    relevance=relevance,
                    metadata=metadata,
                )
            )
        total = int(body.get("total") or len(items))
        query = str(body.get("query") or original_query)
        return KnowledgeSearchResponse(query=query, items=items, total=total)


def format_items_for_advisor(items: list[KnowledgeSearchResult]) -> list[dict[str, Any]]:
    """Convert search results into the dict shape expected by the AI advisor.

    The advisor receives a list of plain dicts to keep the domain model decoupled
    from the external API. Every item is tagged with ``quality_status: draft``
    and ``knowledge_type: reference`` because KnowledgePack does not provide
    these fields.
    """

    formatted: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        formatted.append(
            {
                "id": f"ext-knowledge-{index}",
                "title": item.source or f"External knowledge chunk {index + 1}",
                "section": "main",
                "content": item.content,
                "source_uri": _safe_source_uri(item.source),
                "knowledge_type": "reference",
                "quality_status": "draft",
                "score": round(item.relevance, 4),
                "metadata": item.metadata,
            }
        )
    return formatted


def _safe_source_uri(source: str) -> str:
    """Return a best-effort URI for the source field.

    If the source looks like a URL it is returned as-is. Otherwise the source
    is treated as a local filename and wrapped in a ``file://`` URI.
    """

    stripped = source.strip()
    if not stripped:
        return "file://unknown"
    if stripped.startswith(("http://", "https://", "file://")):
        return stripped
    return f"file://{quote(stripped)}"