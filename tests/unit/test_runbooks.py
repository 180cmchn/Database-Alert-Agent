from pathlib import Path

import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.runbooks import LocalMarkdownRunbookProvider
from app.config import DEFAULT_SEVERITY_MAPPING


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
