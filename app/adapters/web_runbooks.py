from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.adapters.runbooks import _as_lower_strings, _parse_markdown, _score_runbook
from app.domain.errors import RunbookError
from app.domain.models import NormalizedAlert, RunbookExcerpt

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_LOGIN_PATH_PARTS = {"auth", "login", "signin", "sso"}
_TEXT_CONTENT_TYPES = {
    "application/xhtml+xml",
    "text/html",
    "text/markdown",
    "text/plain",
}
_IGNORED_HTML_TAGS = {"footer", "head", "nav", "noscript", "script", "style", "svg"}
_BLOCK_HTML_TAGS = {
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}


@dataclass(frozen=True)
class _WebRunbookCandidate:
    metadata: dict[str, Any]
    source_url: str
    preliminary_score: float
    path: Path


class _HTMLTextExtractor(HTMLParser):
    """Extract readable text, optionally below one simple tag/#id/.class selector."""

    def __init__(self, selector: str | None) -> None:
        super().__init__(convert_charrefs=True)
        self._selector = selector.strip() if selector else None
        self._stack: list[tuple[bool, bool, str]] = []
        self._parts: list[str] = []
        self.selector_found = self._selector is None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        normalized_tag = tag.casefold()
        parent_capture = self._stack[-1][0] if self._stack else self._selector is None
        parent_ignored = self._stack[-1][1] if self._stack else False
        matched = self._matches(normalized_tag, attrs)
        if matched:
            self.selector_found = True
        capture = parent_capture or matched
        ignored = parent_ignored or normalized_tag in _IGNORED_HTML_TAGS
        self._stack.append((capture, ignored, normalized_tag))
        if capture and not ignored and normalized_tag in _BLOCK_HTML_TAGS:
            self._parts.append("\n")
        if capture and not ignored and normalized_tag == "li":
            self._parts.append("- ")

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self._stack:
            return
        capture, ignored, opened_tag = self._stack.pop()
        if capture and not ignored and opened_tag in _BLOCK_HTML_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._stack:
            return
        capture, ignored, _ = self._stack[-1]
        if capture and not ignored:
            self._parts.append(data)

    def text(self) -> str:
        lines = []
        for line in "".join(self._parts).splitlines():
            normalized = re.sub(r"[\t\r\f\v ]+", " ", line).strip()
            if normalized:
                lines.append(normalized)
        return "\n".join(lines)

    def _matches(self, tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        if self._selector is None:
            return False
        attributes = {key.casefold(): value or "" for key, value in attrs}
        if self._selector.startswith("#"):
            return attributes.get("id") == self._selector[1:]
        if self._selector.startswith("."):
            classes = attributes.get("class", "").split()
            return self._selector[1:] in classes
        return tag == self._selector.casefold()


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    port = parsed.port if parsed.port is not None else default_port
    return scheme, (parsed.hostname or "").casefold(), port


def _host_allowlist_key(url: str) -> str:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").casefold()
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    if parsed.port in {None, default_port}:
        return hostname
    return f"{hostname}:{parsed.port}"


def _safe_url_label(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _page_text(body: str, content_type: str, selector: str | None) -> str:
    if content_type != "text/html" and content_type != "application/xhtml+xml":
        return body.strip()
    extractor = _HTMLTextExtractor(selector)
    extractor.feed(body)
    extractor.close()
    if not extractor.selector_found:
        raise RunbookError(f"Runbook content selector was not found: {selector}")
    return extractor.text()


class AuthenticatedWebRunbookProvider:
    """Match local catalog metadata, then read the authoritative authenticated page.

    Each Markdown document remains a small administrable catalog record. Its custom
    metadata must contain ``source_url`` and may contain ``content_selector``. The
    Markdown body is only a note for administrators; matched excerpts always use
    freshly fetched (or briefly cached) web page text.
    """

    def __init__(
        self,
        directory: Path,
        *,
        allowed_hosts: list[str],
        auth_mode: str,
        auth_secret: str,
        timeout_seconds: float = 15,
        cache_ttl_seconds: int = 300,
        max_response_bytes: int = 1_000_000,
        verify_tls: bool = True,
        require_https: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._directory = directory
        self._allowed_hosts = {
            item.strip().casefold() for item in allowed_hosts if item.strip()
        }
        self._auth_mode = auth_mode.strip().casefold()
        self._auth_secret = auth_secret
        self._timeout_seconds = timeout_seconds
        self._cache_ttl_seconds = cache_ttl_seconds
        self._max_response_bytes = max_response_bytes
        self._verify_tls = verify_tls
        self._require_https = require_https
        self._transport = transport
        self._cache: dict[tuple[str, str | None], tuple[float, str]] = {}
        self._cache_lock = asyncio.Lock()

        if self._auth_mode not in {"bearer", "cookie", "none"}:
            raise ValueError("auth_mode must be bearer, cookie, or none")

    async def search(self, alert: NormalizedAlert, limit: int = 5) -> list[RunbookExcerpt]:
        candidates = await asyncio.to_thread(self._load_candidates_sync, alert)
        resolved = await asyncio.gather(
            *(self._resolve_candidate(candidate, alert) for candidate in candidates)
        )
        matches = [item for item in resolved if item is not None]
        matches.sort(key=lambda item: (-item.score, item.runbook_id))
        return matches[:limit]

    def _load_candidates_sync(self, alert: NormalizedAlert) -> list[_WebRunbookCandidate]:
        if not self._directory.exists():
            raise RunbookError(f"Runbook catalog directory does not exist: {self._directory}")

        candidates: list[_WebRunbookCandidate] = []
        for path in sorted(self._directory.glob("*.md")):
            if path.name.casefold() == "readme.md":
                continue
            try:
                metadata, _catalog_note = _parse_markdown(path)
            except FileNotFoundError:
                continue
            source_url = str(metadata.get("source_url") or "").strip()
            if not source_url:
                # Local-only entries may coexist in the managed directory during
                # migration. Web mode deliberately ignores them instead of using
                # their Markdown body as an authoritative handbook.
                continue
            self._validate_source_url(source_url, path)
            # The local Markdown body is an administrative note only. Candidate
            # scoring may use catalog metadata, never the local body.
            score = _score_runbook(metadata, "", alert)
            has_match_metadata = bool(
                _as_lower_strings(metadata.get("reasons"))
                or _as_lower_strings(metadata.get("keywords"))
            )
            if score <= 0 and has_match_metadata:
                continue
            candidates.append(
                _WebRunbookCandidate(
                    metadata=metadata,
                    source_url=source_url,
                    preliminary_score=score,
                    path=path,
                )
            )
        candidates.sort(
            key=lambda item: (
                -item.preliminary_score,
                str(item.metadata.get("id") or item.path.stem),
            )
        )
        return candidates

    async def _resolve_candidate(
        self, candidate: _WebRunbookCandidate, alert: NormalizedAlert
    ) -> RunbookExcerpt | None:
        selector_value = candidate.metadata.get("content_selector")
        selector = str(selector_value).strip() if selector_value else None
        content = await self._get_page_text(candidate.source_url, selector)
        score = _score_runbook(candidate.metadata, content, alert)
        if score <= 0:
            return None
        return RunbookExcerpt(
            runbook_id=str(candidate.metadata.get("id") or candidate.path.stem),
            title=str(candidate.metadata.get("title") or candidate.path.stem),
            section=str(candidate.metadata.get("section") or "main"),
            content=content,
            score=score,
            metadata=candidate.metadata,
        )

    async def _get_page_text(self, source_url: str, selector: str | None) -> str:
        cache_key = (source_url, selector)
        async with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                return cached[1]

        content = await self._fetch_page_text(source_url, selector)
        async with self._cache_lock:
            self._cache[cache_key] = (
                time.monotonic() + self._cache_ttl_seconds,
                content,
            )
        return content

    async def _fetch_page_text(self, source_url: str, selector: str | None) -> str:
        if self._auth_mode != "none" and not self._auth_secret:
            raise RunbookError(
                "RUNBOOK_WEB_AUTH_SECRET is required before fetching a runbook page"
            )
        headers = {
            "Accept": "text/html, text/plain;q=0.9",
            "User-Agent": "database-alert-agent/0.1",
        }
        if self._auth_mode == "cookie":
            headers["Cookie"] = self._auth_secret
        elif self._auth_mode == "bearer":
            headers["Authorization"] = f"Bearer {self._auth_secret}"

        original_origin = _origin(source_url)
        current_url = source_url
        async with httpx.AsyncClient(
            timeout=self._timeout_seconds,
            verify=self._verify_tls,
            transport=self._transport,
            follow_redirects=False,
            headers=headers,
        ) as client:
            for _ in range(6):
                try:
                    async with client.stream("GET", current_url) as response:
                        if response.status_code in _REDIRECT_STATUSES:
                            location = response.headers.get("location")
                            if not location:
                                raise RunbookError(
                                    "Runbook server returned a redirect without Location"
                                )
                            redirected_url = urljoin(current_url, location)
                            self._validate_source_url(redirected_url)
                            if _origin(redirected_url) != original_origin:
                                raise RunbookError(
                                    "Runbook request was redirected to another origin; "
                                    "the login session may be missing or expired"
                                )
                            current_url = redirected_url
                            continue
                        if response.status_code in {401, 403}:
                            raise RunbookError(
                                "Runbook authentication was rejected by "
                                f"{_safe_url_label(current_url)}"
                            )
                        if response.status_code >= 400:
                            raise RunbookError(
                                f"Runbook request returned HTTP {response.status_code} for "
                                f"{_safe_url_label(current_url)}"
                            )
                        content_type = (
                            response.headers.get("content-type", "")
                            .split(";", 1)[0]
                            .strip()
                            .casefold()
                        )
                        if content_type and content_type not in _TEXT_CONTENT_TYPES:
                            raise RunbookError(f"Unsupported runbook content type: {content_type}")
                        declared_length = response.headers.get("content-length")
                        try:
                            response_size = int(declared_length) if declared_length else 0
                        except ValueError:
                            response_size = 0
                        if response_size > self._max_response_bytes:
                            raise RunbookError(
                                "Runbook page exceeds RUNBOOK_WEB_MAX_RESPONSE_BYTES"
                            )
                        chunks: list[bytes] = []
                        received = 0
                        async for chunk in response.aiter_bytes():
                            received += len(chunk)
                            if received > self._max_response_bytes:
                                raise RunbookError(
                                    "Runbook page exceeds RUNBOOK_WEB_MAX_RESPONSE_BYTES"
                                )
                            chunks.append(chunk)
                        encoding = response.encoding or "utf-8"
                        body = b"".join(chunks).decode(encoding, errors="replace")
                except httpx.HTTPError as exc:
                    raise RunbookError(
                        f"Cannot access runbook page {_safe_url_label(current_url)}: "
                        f"{exc.__class__.__name__}"
                    ) from exc

                parsed_path = {part.casefold() for part in urlsplit(current_url).path.split("/")}
                if parsed_path.intersection(_LOGIN_PATH_PARTS) or re.search(
                    r"<input\b[^>]*\btype=[\"']?password\b", body, flags=re.IGNORECASE
                ):
                    raise RunbookError(
                        "Runbook server returned a login page; refresh RUNBOOK_WEB_AUTH_SECRET"
                    )
                effective_content_type = content_type or (
                    "text/html" if re.search(r"<\w+[\s>]", body) else "text/plain"
                )
                extracted = _page_text(body, effective_content_type, selector)
                if not extracted:
                    raise RunbookError(
                        "Runbook page contained no readable text; configure content_selector "
                        "or use the handbook system's export/API URL"
                    )
                return extracted
        raise RunbookError("Runbook request exceeded the redirect limit")

    def _validate_source_url(self, source_url: str, path: Path | None = None) -> None:
        parsed = urlsplit(source_url)
        location = f" in {path.name}" if path else ""
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RunbookError(f"source_url must be an absolute HTTP(S) URL{location}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise RunbookError(f"source_url contains an invalid port{location}") from exc
        if port == 0:
            raise RunbookError(f"source_url contains an invalid port{location}")
        if self._require_https and parsed.scheme != "https":
            raise RunbookError(f"source_url must use HTTPS in production{location}")
        if parsed.username is not None or parsed.password is not None:
            raise RunbookError(f"source_url must not contain credentials{location}")
        if not self._allowed_hosts:
            raise RunbookError("RUNBOOK_WEB_ALLOWED_HOSTS is required")
        if _host_allowlist_key(source_url) not in self._allowed_hosts:
            raise RunbookError(
                f"Runbook host is not in RUNBOOK_WEB_ALLOWED_HOSTS{location}: {parsed.hostname}"
            )
