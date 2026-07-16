import os
from pathlib import Path

import pytest

from app.adapters import runbooks as runbook_module
from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.runbook_store import LocalMarkdownRunbookStore
from app.adapters.runbooks import LocalMarkdownRunbookProvider
from app.config import DEFAULT_SEVERITY_MAPPING
from app.domain.models import RunbookDocument


@pytest.mark.asyncio
async def test_runbook_metadata_controls_priority(tmp_path: Path) -> None:
    (tmp_path / "exact.md").write_text(
        """---
id: exact
title: Exact
reasons: [connection_exhausted]
keywords: [connection]
severities: [CRITICAL]
---
Approved exact procedure.
""",
        encoding="utf-8",
    )
    (tmp_path / "weak.md").write_text(
        """---
id: weak
title: Weak
keywords: [connection]
---
Generic procedure.
""",
        encoding="utf-8",
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {
            "severity": "CRITICAL",
            "title": "Connection use is high",
            "reason": "connection_exhausted",
        }
    )
    matches = await LocalMarkdownRunbookProvider(tmp_path).search(alert)
    assert [item.runbook_id for item in matches] == ["exact", "weak"]
    assert matches[0].score > matches[1].score


@pytest.mark.asyncio
async def test_unmatched_runbook_returns_empty_list(tmp_path: Path) -> None:
    (tmp_path / "cpu.md").write_text(
        "---\nid: cpu\nkeywords: [cpu]\n---\nCPU procedure.\n", encoding="utf-8"
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "LOW", "title": "Disk usage", "reason": "disk"}
    )
    assert await LocalMarkdownRunbookProvider(tmp_path).search(alert) == []


@pytest.mark.asyncio
async def test_severity_and_labels_only_boost_semantic_matches(tmp_path: Path) -> None:
    (tmp_path / "slow-query.md").write_text(
        """---
id: slow-query
title: Slow query
reasons: [slow_query_spike]
keywords: [slow query]
severities: [CRITICAL]
labels:
  trial_channel: qq
---
Read-only slow query procedure.
""",
        encoding="utf-8",
    )
    adapter = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING)

    unrelated = adapter.normalize(
        {
            "severity": "CRITICAL",
            "title": "Replication lag is high",
            "reason": "replication_lag_high",
            "labels": {"trial_channel": "qq"},
        }
    )
    assert await LocalMarkdownRunbookProvider(tmp_path).search(unrelated) == []

    related = adapter.normalize(
        {
            "severity": "CRITICAL",
            "title": "Slow query count increased",
            "reason": "slow_query_spike",
            "labels": {"trial_channel": "qq"},
        }
    )
    matches = await LocalMarkdownRunbookProvider(tmp_path).search(related)
    assert [item.runbook_id for item in matches] == ["slow-query"]
    assert matches[0].score == 17


@pytest.mark.asyncio
async def test_search_works_with_read_only_runbook_mount(tmp_path: Path) -> None:
    await LocalMarkdownRunbookStore(tmp_path).create(
        RunbookDocument(
            id="read-only",
            title="Read-only runbook",
            reasons=["latency"],
            content="Read-only latency procedure.",
        )
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Latency", "reason": "latency"}
    )

    (tmp_path / ".runbooks.lock").unlink()
    os.chmod(tmp_path, 0o555)
    try:
        matches = await LocalMarkdownRunbookProvider(tmp_path).search(alert)
    finally:
        os.chmod(tmp_path, 0o755)

    assert [item.runbook_id for item in matches] == ["read-only"]


@pytest.mark.asyncio
async def test_search_skips_file_removed_by_external_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "vanished.md"
    path.write_text(
        "---\nid: vanished\nreasons: [latency]\n---\nProcedure.\n",
        encoding="utf-8",
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Latency", "reason": "latency"}
    )

    def remove_before_open(candidate: Path):  # type: ignore[no-untyped-def]
        candidate.unlink()
        raise FileNotFoundError(candidate)

    monkeypatch.setattr(runbook_module, "_parse_markdown", remove_before_open)
    assert await LocalMarkdownRunbookProvider(tmp_path).search(alert) == []
