from pathlib import Path

import pytest

from app.adapters.runbook_store import LocalMarkdownRunbookStore
from app.adapters.web_runbooks import AuthenticatedWebRunbookProvider
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import NormalizedAlert, RunbookDocument, RunbookExcerpt


def settings_for(tmp_path: Path) -> Settings:
    return Settings(
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_dir=tmp_path / "runbooks",
    )


class ExternalRunbookProvider:
    async def search(
        self, alert: NormalizedAlert, limit: int = 5
    ) -> list[RunbookExcerpt]:
        return []


class ExternalRunbookStore:
    async def list(self) -> list[RunbookDocument]:
        return []

    async def get(self, runbook_id: str) -> RunbookDocument:
        raise LookupError(runbook_id)

    async def create(self, document: RunbookDocument) -> RunbookDocument:
        return document

    async def update(
        self,
        runbook_id: str,
        document: RunbookDocument,
        *,
        expected_version: int | None = None,
    ) -> RunbookDocument:
        return document

    async def delete(self, runbook_id: str) -> None:
        return None


@pytest.mark.asyncio
async def test_default_provider_uses_web_content_and_never_local_body(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))

    assert isinstance(runtime.runbook_provider, AuthenticatedWebRunbookProvider)
    assert isinstance(runtime.runbook_store, LocalMarkdownRunbookStore)
    assert runtime.service.runbook_provider is runtime.runbook_provider

    await runtime.runbook_store.create(
        RunbookDocument(
            id="connection-limit",
            title="Connection limit",
            reasons=["connection_exhausted"],
            content="This local catalog note must never be matched.",
        )
    )
    alert = runtime.service.source_registry.normalize(
        "canonical",
        {
            "severity": "WARNING",
            "title": "Connections exhausted",
            "reason": "connection_exhausted",
        }
    )

    matches = await runtime.runbook_provider.search(alert)

    assert matches == []
    await runtime.repository.close()  # type: ignore[attr-defined]


def test_custom_runbook_provider_requires_explicit_store(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be provided together"):
        build_runtime(
            settings_for(tmp_path),
            runbook_provider=ExternalRunbookProvider(),
        )


def test_custom_runbook_store_requires_explicit_provider(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be provided together"):
        build_runtime(
            settings_for(tmp_path),
            runbook_store=ExternalRunbookStore(),
        )


def test_custom_runbook_pair_is_preserved(tmp_path: Path) -> None:
    provider = ExternalRunbookProvider()
    store = ExternalRunbookStore()

    runtime = build_runtime(
        settings_for(tmp_path),
        runbook_provider=provider,
        runbook_store=store,
    )

    assert runtime.runbook_provider is provider
    assert runtime.runbook_store is store
    assert runtime.service.runbook_provider is provider
