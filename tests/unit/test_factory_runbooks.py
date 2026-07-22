from pathlib import Path

import pytest

from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.application.factory import build_runtime
from app.config import Settings
from app.domain.models import NormalizedAlert, RunbookDocument, RunbookExcerpt


def settings_for(tmp_path: Path) -> Settings:
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    return Settings(
        _env_file=None,
        ai_provider="fake",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}",
        runbook_pdf_dir=runbooks,
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


@pytest.mark.asyncio
async def test_default_provider_and_inventory_share_local_pdf_library(
    tmp_path: Path,
) -> None:
    runtime = build_runtime(settings_for(tmp_path))

    assert isinstance(runtime.runbook_provider, LocalPDFRunbookLibrary)
    assert runtime.runbook_store is runtime.runbook_provider
    assert runtime.service.runbook_provider is runtime.runbook_provider

    alert = runtime.service.source_registry.normalize(
        "canonical",
        {
            "severity": "WARNING",
            "title": "Connections exhausted",
            "reason": "connection_exhausted",
        },
    )
    assert await runtime.runbook_provider.search(alert) == []
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
