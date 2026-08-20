"""Extensible advisory knowledge-source registry.

Knowledge is optional context, never live evidence. Each registered provider is
isolated so an unavailable, unknown, or empty source cannot block investigation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.domain.models import KnowledgeExcerpt, NormalizedAlert
from app.domain.ports import KnowledgeSource


@dataclass(frozen=True, slots=True)
class KnowledgeSourceResult:
    source: str
    matches: list[KnowledgeExcerpt]
    error: str | None = None


class KnowledgeSourceRegistry:
    """Resolve configured source names without coupling the workflow to providers."""

    def __init__(self, sources: list[KnowledgeSource] | None = None) -> None:
        self._sources: dict[str, KnowledgeSource] = {}
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
            source = self._sources.get(name)
            if source is None:
                return KnowledgeSourceResult(source=name, matches=[], error="NotConfigured")
            try:
                matches = await source.search(alert)
            except Exception as exc:
                return KnowledgeSourceResult(
                    source=name,
                    matches=[],
                    error=type(exc).__name__,
                )
            return KnowledgeSourceResult(source=name, matches=matches)

        return await asyncio.gather(*(search_one(name) for name in selected_sources))