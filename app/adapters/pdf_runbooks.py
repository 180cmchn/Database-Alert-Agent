from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.domain.errors import InvalidRunbookIdError, RunbookError, RunbookNotFoundError
from app.domain.models import NormalizedAlert, RunbookDocument, RunbookExcerpt

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_SEVERITY_PATTERN = re.compile(r"(?i)\[(critical|warning|info)\]")
_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}")
_IGNORED_VALUES = {"", "unknown", "none", "null", "n/a"}
_STOP_TERMS = {
    "alert",
    "alarm",
    "database",
    "error",
    "failure",
    "info",
    "critical",
    "warning",
    "告警",
    "异常",
    "故障",
    "数据库",
    "生产",
}


@dataclass(frozen=True)
class _CachedPDF:
    signature: tuple[int, int]
    document: RunbookDocument


def _normalize_pdf_text(value: str) -> str:
    lines: list[str] = []
    for line in value.replace("\x00", "").splitlines():
        normalized = re.sub(r"[\t\r\f\v ]+", " ", line).strip()
        if normalized:
            lines.append(normalized)
    return "\n".join(lines)


def _normalized_match_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _title_from_text(text: str, fallback: str) -> str:
    lines = text.splitlines()
    for line in lines[:12]:
        labelled = re.search(r"案件标题\s*[：:]\s*[“\"]?(.+?)[”\"]?$", line)
        if labelled:
            return labelled.group(1).strip(" “\"”")[:300]
    for line in lines[:8]:
        candidate = line.strip(" \t-—_:：")
        if "告警处理" in candidate and len(candidate) >= 6:
            return candidate[:300]
    for line in lines:
        candidate = line.strip(" \t-—_:：")
        if len(candidate) >= 3 and not candidate.isdigit():
            return candidate[:300]
    return fallback[:300]


def _severity_values(text: str) -> list[str]:
    found = {match.group(1).upper() for match in _SEVERITY_PATTERN.finditer(text)}
    return [value for value in ("CRITICAL", "WARNING", "INFO") if value in found]


def _match_terms(value: str) -> set[str]:
    terms: set[str] = set()
    for match in _TOKEN_PATTERN.finditer(value.casefold()):
        token = match.group(0).strip("_- ")
        if token and token not in _STOP_TERMS and token not in _IGNORED_VALUES:
            terms.add(token)
    return terms


def _score_pdf(document: RunbookDocument, alert: NormalizedAlert) -> float:
    """Rank a PDF by exact alert fields first, then by specific token overlap.

    Severity, database type and other broad context only boost a semantic match;
    they can never make an otherwise unrelated PDF match an alert.
    """

    content = _normalized_match_text(f"{document.title}\n{document.content}")
    title = _normalized_match_text(document.title)
    weighted_values: list[tuple[str | None, float]] = [
        (alert.reason, 18),
        (alert.alert_name, 18),
        (alert.metric_name, 16),
        (alert.alert_type, 14),
        (alert.alarm_type, 12),
        (alert.error_pattern, 10),
        (alert.error_summary, 8),
        (alert.title, 10),
        (alert.description, 6),
    ]

    score = 0.0
    direct_match = False
    seen: set[str] = set()
    token_source: list[str] = []
    for raw_value, weight in weighted_values:
        if not raw_value:
            continue
        value = _normalized_match_text(raw_value)
        if value in _IGNORED_VALUES or value in seen:
            continue
        seen.add(value)
        token_source.append(value)
        if len(value) >= 4 and value in content:
            score += weight
            if value in title:
                score += 4
            direct_match = True

    if not direct_match:
        # PDF titles often insert Chinese words between identifier fragments
        # (for example "MySQL出现Crash..."). Treat complete multi-token title
        # coverage as a strong match without requiring a contiguous phrase.
        for value in token_source[:5]:
            terms = _match_terms(value)
            if len(terms) >= 2 and all(term in title for term in terms):
                score += 8
                direct_match = True
                break

    if not direct_match:
        terms = set().union(*(_match_terms(value) for value in token_source))
        hits = {term for term in terms if term in content}
        # A single broad word such as "mysql" or "tidb" is not enough to select
        # a handbook. Two independent alert terms are required as a fallback.
        if len(hits) < 2:
            return 0.0
        fallback_score = float(sum(2 if len(term) >= 8 else 1 for term in hits))
        if fallback_score < 4:
            return 0.0
        score += min(12.0, fallback_score)

    if alert.severity.value in document.severities:
        score += 2
    if alert.database and alert.database.engine:
        engine = _normalized_match_text(alert.database.engine)
        if engine and engine in content:
            score += 1
    return score


class LocalPDFRunbookLibrary:
    """Read-only local PDF corpus used by both analysis and administration APIs."""

    def __init__(
        self,
        directory: Path,
        *,
        max_file_bytes: int = 20_000_000,
        max_text_chars: int = 200_000,
    ) -> None:
        self._directory = directory
        self._max_file_bytes = max_file_bytes
        self._max_text_chars = max_text_chars
        self._cache: dict[Path, _CachedPDF] = {}
        self._lock = asyncio.Lock()

    async def search(
        self, alert: NormalizedAlert, limit: int = 5
    ) -> list[RunbookExcerpt]:
        documents = await self.list()
        matches: list[RunbookExcerpt] = []
        for document in documents:
            score = _score_pdf(document, alert)
            if score <= 0:
                continue
            matches.append(
                RunbookExcerpt(
                    runbook_id=document.id,
                    title=document.title,
                    section=document.section,
                    content=document.content,
                    score=score,
                    metadata=document.metadata,
                )
            )
        matches.sort(key=lambda item: (-item.score, item.runbook_id))
        return matches[:limit]

    async def list(self) -> list[RunbookDocument]:
        async with self._lock:
            return await asyncio.to_thread(self._list_sync)

    async def get(self, runbook_id: str) -> RunbookDocument:
        path = self._path_for(runbook_id)
        async with self._lock:
            return await asyncio.to_thread(self._read_sync, path, runbook_id)

    def _list_sync(self) -> list[RunbookDocument]:
        if not self._directory.exists():
            raise RunbookError(f"PDF runbook directory does not exist: {self._directory}")
        if not self._directory.is_dir():
            raise RunbookError(f"PDF runbook path is not a directory: {self._directory}")

        documents: list[RunbookDocument] = []
        active_paths: set[Path] = set()
        for path in sorted(self._directory.glob("*.pdf")):
            self._assert_regular_pdf(path)
            active_paths.add(path)
            documents.append(self._read_sync(path, path.stem))
        self._cache = {
            path: cached for path, cached in self._cache.items() if path in active_paths
        }
        return documents

    def _read_sync(self, path: Path, requested_id: str) -> RunbookDocument:
        if not path.exists():
            raise RunbookNotFoundError(f"PDF runbook not found: {requested_id}")
        self._assert_regular_pdf(path)
        file_stat = path.stat()
        if file_stat.st_size > self._max_file_bytes:
            raise RunbookError(
                f"PDF runbook exceeds RUNBOOK_PDF_MAX_FILE_BYTES: {path.name}"
            )
        signature = (file_stat.st_mtime_ns, file_stat.st_size)
        cached = self._cache.get(path)
        if cached and cached.signature == signature:
            return cached.document

        try:
            reader = PdfReader(str(path), strict=False)
            if reader.is_encrypted:
                raise RunbookError(f"Encrypted PDF runbook is not supported: {path.name}")
            page_texts: list[str] = []
            for page_number, page in enumerate(reader.pages, start=1):
                try:
                    page_texts.append(_normalize_pdf_text(page.extract_text() or ""))
                except Exception as exc:
                    raise RunbookError(
                        f"Cannot extract text from {path.name} page {page_number}"
                    ) from exc
        except RunbookError:
            raise
        except (OSError, PdfReadError, ValueError) as exc:
            raise RunbookError(f"Cannot read PDF runbook: {path.name}") from exc

        full_text = "\n\n".join(text for text in page_texts if text).strip()
        if len(full_text) < 20:
            raise RunbookError(
                f"PDF runbook has no usable text layer; OCR is required: {path.name}"
            )
        truncated = len(full_text) > self._max_text_chars
        content = full_text[: self._max_text_chars]
        document = RunbookDocument(
            id=path.stem,
            title=_title_from_text(content, path.stem),
            section="PDF",
            severities=_severity_values(content),
            content=content,
            metadata={
                "source_type": "local_pdf",
                "file_name": path.name,
                "page_count": len(reader.pages),
                "file_size_bytes": file_stat.st_size,
                "text_truncated": truncated,
            },
            version=1,
            updated_at=datetime.fromtimestamp(file_stat.st_mtime, UTC),
        )
        self._cache[path] = _CachedPDF(signature=signature, document=document)
        return document

    def _path_for(self, runbook_id: str) -> Path:
        if not _SAFE_RUNBOOK_ID.fullmatch(runbook_id):
            raise InvalidRunbookIdError(
                "PDF runbook ID must use 1-128 letters, digits, underscores or hyphens"
            )
        root = self._directory.resolve()
        path = self._directory / f"{runbook_id}.pdf"
        if path.resolve(strict=False).parent != root:
            raise InvalidRunbookIdError("PDF runbook path escapes the configured directory")
        return path

    def _assert_regular_pdf(self, path: Path) -> None:
        root = self._directory.resolve()
        if (
            path.suffix.casefold() != ".pdf"
            or path.is_symlink()
            or path.resolve().parent != root
            or not path.is_file()
        ):
            raise RunbookError(f"PDF runbook is not a regular managed file: {path.name}")
