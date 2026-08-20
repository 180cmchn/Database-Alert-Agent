"""External knowledge API client for the KnowledgePack (LangChain + Chroma) service.

This adapter bridges the project's analyze-database-alerts skill contract with the
actual KnowledgePack HTTP API. It follows the same defensive patterns as the
FlashDuty adapter: typed errors, cancellation-aware retries, and graceful degradation.

Results are advisory data, never live evidence. API failure or an empty response
degrades gracefully and cannot prevent the investigation from continuing.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

import httpx

from app.application.sanitization import sanitize, sanitize_text
from app.domain.models import KnowledgeExcerpt, NormalizedAlert


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


# KnowledgePack uses Chroma cosine distance, where lower is more similar.
# Convert it to a bounded relevance score where higher is better.


def _distance_to_relevance(distance: float) -> float:
    """Convert Chroma cosine distance into a bounded 0-1 relevance score."""

    try:
        d = float(distance)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(d) or d < 0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - d))


def build_search_query(alert: NormalizedAlert) -> str:
    """Build a natural-language search query from a normalized alert.

    The query prioritizes database engine, alert type, metric/error pattern, and
    service context so that the vector store returns the most relevant operational
    guides, incident cases, or references.
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
        base_url: str = "http://knowledge:8000",
        *,
        api_key: str = "",
        timeout_seconds: float = 30,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if max_retries < 0:
            raise ValueError("max_retries must not be negative")
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

        Recoverable failures use a bounded retry budget and total wall-clock
        deadline. Permanent HTTP and response errors still fail fast.
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

    async def search_alert(
        self, alert: NormalizedAlert, *, top_k: int = 5
    ) -> KnowledgeSearchResponse:
        """Convenience wrapper that builds a query from the alert context."""

        query = build_search_query(alert)
        return await self.search(query, top_k=top_k, with_score=True)

    async def _request(
        self,
        method: Literal["POST"],
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            async with asyncio.timeout(self.timeout_seconds):
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
                                    "Knowledge service request failed",
                                    code="NetworkError",
                                ) from exc
                            await self._sleep(min(2 ** min(attempt, 4), 10))
                            continue

                        retryable = response.status_code == 429 or response.status_code >= 500
                        if not retryable or attempt >= self.max_retries:
                            break
                        await self._sleep(self._retry_delay(response, attempt))
        except TimeoutError as exc:
            raise ExternalKnowledgeAPIError(
                "Knowledge service request exceeded its time budget",
                code="Timeout",
            ) from exc

        if response is None:  # pragma: no cover - loop contract guard
            raise ExternalKnowledgeAPIError("No response received", code="NetworkError")
        return self._decode_response(response)

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After", "")
        try:
            retry_after_seconds = float(retry_after)
        except ValueError:
            return min(2 ** min(attempt, 4), 10)
        if not math.isfinite(retry_after_seconds):
            return min(2 ** min(attempt, 4), 10)
        return min(max(retry_after_seconds, 0), 10)

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
            content = sanitize_text(str(entry.get("content") or "")).strip()
            if not content:
                continue
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            source = sanitize_text(str(metadata.get("source") or "")).strip()
            try:
                raw_score = float(entry.get("score") or 0.0)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(raw_score) or raw_score < 0:
                continue
            relevance = _distance_to_relevance(raw_score)
            items.append(
                KnowledgeSearchResult(
                    content=content[:20_000],
                    source=source,
                    raw_score=raw_score,
                    relevance=relevance,
                    metadata=sanitize(metadata),
                )
            )
        try:
            total = max(0, int(body.get("total") or len(items)))
        except (TypeError, ValueError):
            total = len(items)
        query = str(body.get("query") or original_query)
        return KnowledgeSearchResponse(query=query, items=items, total=total)


def format_items_for_advisor(
    items: list[KnowledgeSearchResult],
) -> list[KnowledgeExcerpt]:
    """Create stable, bounded excerpts suitable for persisted citations."""

    formatted: list[KnowledgeExcerpt] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(items):
        content = sanitize_text(item.content).strip()[:20_000]
        if not content:
            continue
        source = sanitize_text(item.source).strip()
        digest = hashlib.sha256(f"{source}\0{content}".encode()).hexdigest()[:24]
        knowledge_id = f"external-{digest}"
        if knowledge_id in seen_ids:
            continue
        seen_ids.add(knowledge_id)
        formatted.append(
            KnowledgeExcerpt(
                source="external_knowledge",
                knowledge_id=knowledge_id,
                title=source or f"External knowledge chunk {index + 1}",
                content=content,
                source_uri=_safe_source_uri(source),
                score=round(item.relevance, 4),
                raw_score=item.raw_score,
                metadata=sanitize(item.metadata),
            )
        )
    return formatted


class ExternalKnowledgeSource:
    """Registered KnowledgePack source with deployment-specific result limits."""

    name = "external_knowledge"

    def __init__(
        self,
        client: ExternalKnowledgeClient,
        *,
        limit: int,
        min_relevance: float,
    ) -> None:
        self._client = client
        self._limit = limit
        self._min_relevance = min_relevance

    async def search(self, alert: NormalizedAlert) -> list[KnowledgeExcerpt]:
        response = await self._client.search_alert(alert, top_k=self._limit)
        accepted = [
            item for item in response.items if item.relevance >= self._min_relevance
        ]
        return format_items_for_advisor(accepted)


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
