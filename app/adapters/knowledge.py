"""Extensible advisory knowledge-source registry.

Knowledge is optional context, never live evidence. Each registered provider is
isolated so an unavailable, unknown, or empty source cannot block investigation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Literal

from app.domain.models import KnowledgeExcerpt, NormalizedAlert
from app.domain.ports import KnowledgeSource


def _error_code(exc: Exception) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        normalized = code.strip()
        if normalized and len(normalized) <= 100 and all(
            character.isalnum() or character in "._-" for character in normalized
        ):
            return normalized
    return type(exc).__name__


@dataclass(frozen=True, slots=True)
class KnowledgeSourceResult:
    source: str
    matches: list[KnowledgeExcerpt]
    status: Literal["matched", "no_match", "unavailable"]
    error: str | None = None
    duration_ms: int = 0


class KnowledgeSourceRegistry:
    """Resolve configured source names without coupling the workflow to providers."""

    def __init__(
        self,
        sources: list[KnowledgeSource] | None = None,
        *,
        source_timeout_seconds: float = 30,
    ) -> None:
        if source_timeout_seconds <= 0:
            raise ValueError("knowledge source timeout must be greater than zero")
        self._sources: dict[str, KnowledgeSource] = {}
        self._source_timeout_seconds = source_timeout_seconds
        for source in sources or []:
            self.register(source)

    def register(self, source: KnowledgeSource) -> None:
        name = source.name.strip()
        if not name:
            raise ValueError("knowledge source name must not be empty")
        if name in self._sources:
            raise ValueError(f"knowledge source already registered: {name}")
        self._sources[name] = source

    def names(self) -> list[str]:
        return list(self._sources)

    async def search(
        self,
        selected_sources: list[str],
        alert: NormalizedAlert,
    ) -> list[KnowledgeSourceResult]:
        async def search_one(name: str) -> KnowledgeSourceResult:
            started_at = time.monotonic()

            def duration_ms() -> int:
                return max(0, int((time.monotonic() - started_at) * 1000))

            source = self._sources.get(name)
            if source is None:
                return KnowledgeSourceResult(
                    source=name,
                    matches=[],
                    status="unavailable",
                    error="SourceNotRegistered",
                    duration_ms=duration_ms(),
                )
            try:
                matches = await asyncio.wait_for(
                    source.search(alert),
                    timeout=self._source_timeout_seconds,
                )
            except TimeoutError:
                return KnowledgeSourceResult(
                    source=name,
                    matches=[],
                    status="unavailable",
                    error="TimeoutError",
                    duration_ms=duration_ms(),
                )
            except Exception as exc:
                return KnowledgeSourceResult(
                    source=name,
                    matches=[],
                    status="unavailable",
                    error=_error_code(exc),
                    duration_ms=duration_ms(),
                )
            return KnowledgeSourceResult(
                source=name,
                matches=matches,
                status="matched" if matches else "no_match",
                duration_ms=duration_ms(),
            )

        return await asyncio.gather(*(search_one(name) for name in selected_sources))
