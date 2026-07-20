from pathlib import Path

import httpx
import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.web_runbooks import AuthenticatedWebRunbookProvider
from app.config import DEFAULT_SEVERITY_MAPPING
from app.domain.errors import RunbookError


@pytest.mark.asyncio
async def test_web_runbook_uses_authenticated_page_body_and_cache(tmp_path: Path) -> None:
    (tmp_path / "latency.md").write_text(
        """---
id: latency
title: Database latency
section: initial-triage
reasons: [latency_high]
source_url: https://wiki.corp.example/runbooks/latency
content_selector: '#article-content'
---
The authoritative content is stored at source_url.
""",
        encoding="utf-8",
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["cookie"] == "company_session=authenticated"
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="""
            <html><nav>Unrelated navigation</nav><main id="article-content">
              <h1>Latency runbook</h1><p>Collect slow-query evidence read-only.</p>
            </main></html>
            """,
        )

    provider = AuthenticatedWebRunbookProvider(
        tmp_path,
        allowed_hosts=["wiki.corp.example"],
        auth_mode="cookie",
        auth_secret="company_session=authenticated",
        cache_ttl_seconds=300,
        transport=httpx.MockTransport(handler),
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Latency", "reason": "latency_high"}
    )

    first = await provider.search(alert)
    second = await provider.search(alert)

    assert len(requests) == 1
    assert [item.runbook_id for item in first] == ["latency"]
    assert first == second
    assert first[0].section == "initial-triage"
    assert "Collect slow-query evidence read-only." in first[0].content
    assert "Unrelated navigation" not in first[0].content


@pytest.mark.asyncio
async def test_web_runbook_does_not_fetch_unrelated_catalog_entry(tmp_path: Path) -> None:
    (tmp_path / "cpu.md").write_text(
        """---
id: cpu
reasons: [cpu_high]
source_url: https://wiki.corp.example/runbooks/cpu
---
Web catalog record.
""",
        encoding="utf-8",
    )

    def unexpected_request(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.url}")

    provider = AuthenticatedWebRunbookProvider(
        tmp_path,
        allowed_hosts=["wiki.corp.example"],
        auth_mode="cookie",
        auth_secret="company_session=authenticated",
        transport=httpx.MockTransport(unexpected_request),
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Disk usage", "reason": "disk_high"}
    )

    assert await provider.search(alert) == []


@pytest.mark.asyncio
async def test_web_runbook_never_matches_local_markdown_body(
    tmp_path: Path,
) -> None:
    (tmp_path / "local-only.md").write_text(
        "---\nid: local-only\nreasons: [latency_high]\n---\nAdministrative note.\n",
        encoding="utf-8",
    )
    provider = AuthenticatedWebRunbookProvider(
        tmp_path,
        allowed_hosts=["wiki.corp.example"],
        auth_mode="cookie",
        auth_secret="company_session=authenticated",
        transport=httpx.MockTransport(
            lambda request: pytest.fail(f"unexpected request: {request.url}")
        ),
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Latency", "reason": "latency_high"}
    )

    assert await provider.search(alert) == []


@pytest.mark.asyncio
async def test_web_runbook_rejects_cross_origin_login_redirect(tmp_path: Path) -> None:
    (tmp_path / "latency.md").write_text(
        """---
id: latency
reasons: [latency_high]
source_url: https://wiki.corp.example/runbooks/latency
---
Web catalog record.
""",
        encoding="utf-8",
    )
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://sso.corp.example/login"})

    provider = AuthenticatedWebRunbookProvider(
        tmp_path,
        allowed_hosts=["wiki.corp.example", "sso.corp.example"],
        auth_mode="cookie",
        auth_secret="company_session=expired",
        transport=httpx.MockTransport(handler),
    )
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "HIGH", "title": "Latency", "reason": "latency_high"}
    )

    with pytest.raises(RunbookError, match="login session may be missing or expired"):
        await provider.search(alert)
    assert requested_hosts == ["wiki.corp.example"]
