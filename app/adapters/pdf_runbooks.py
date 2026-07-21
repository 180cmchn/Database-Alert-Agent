from __future__ import annotations

import asyncio
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.domain.errors import InvalidRunbookIdError, RunbookError, RunbookNotFoundError
from app.domain.models import (
    NormalizedAlert,
    RunbookAction,
    RunbookCause,
    RunbookDocument,
    RunbookExcerpt,
    RunbookKnowledgeType,
    RunbookQualityStatus,
    RunbookSection,
)

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_SEVERITY_PATTERN = re.compile(r"(?i)\[(critical|warning|info)\]")
_LATIN_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_-]{2,}")
_CHINESE_RUN_PATTERN = re.compile(r"[\u4e00-\u9fff]{2,}")
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
    signature: tuple[int, int, int, int]
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


def _lexical_terms(value: str) -> list[str]:
    """Tokenize identifiers and Chinese text without requiring a segmenter.

    Chinese bi/tri-grams give deterministic fuzzy recall while exact alert and
    metric identifiers remain the dominant matching signals.
    """

    normalized = _normalized_match_text(value)
    terms = [
        token.strip("_- ")
        for token in _LATIN_TOKEN_PATTERN.findall(normalized)
        if token.strip("_- ") not in _STOP_TERMS
        and token.strip("_- ") not in _IGNORED_VALUES
    ]
    for run in _CHINESE_RUN_PATTERN.findall(normalized):
        if run in _STOP_TERMS:
            continue
        if len(run) <= 4:
            terms.append(run)
        for size in (2, 3):
            terms.extend(run[index : index + size] for index in range(len(run) - size + 1))
    return terms


def _match_terms(value: str) -> set[str]:
    return set(_lexical_terms(value))


def _alert_weighted_values(alert: NormalizedAlert) -> list[tuple[str, float, str]]:
    values: list[tuple[str | None, float, str]] = [
        (alert.reason, 18, "告警原因"),
        (alert.alert_name, 18, "告警名称"),
        (alert.metric_name, 16, "指标名称"),
        (alert.alert_type, 14, "告警类型"),
        (alert.alarm_type, 12, "报警类型"),
        (alert.error_pattern, 10, "错误模式"),
        (alert.error_summary, 8, "错误摘要"),
        (alert.title, 10, "标题"),
        (alert.description, 6, "描述"),
    ]
    result: list[tuple[str, float, str]] = []
    seen: set[str] = set()
    for raw, weight, label in values:
        normalized = _normalized_match_text(raw or "")
        if normalized in _IGNORED_VALUES or normalized in seen:
            continue
        seen.add(normalized)
        result.append((normalized, weight, label))
    return result


def _scope_matches(document: RunbookDocument, alert: NormalizedAlert) -> bool:
    scope = document.metadata.get("scope") or {}
    engines = {
        _normalized_match_text(str(item)) for item in scope.get("database_engines", [])
    }
    alert_engine = _normalized_match_text(alert.database.engine if alert.database else "")
    return not engines or not alert_engine or alert_engine in engines


def _bm25_score(
    query_terms: Counter[str],
    document_terms: Counter[str],
    idf: dict[str, float],
    average_length: float,
) -> float:
    if not query_terms or not document_terms:
        return 0
    length = sum(document_terms.values())
    k1 = 1.5
    b = 0.75
    score = 0.0
    for term, query_frequency in query_terms.items():
        frequency = document_terms.get(term, 0)
        if not frequency:
            continue
        denominator = frequency + k1 * (
            1 - b + b * length / max(average_length, 1)
        )
        term_score = idf.get(term, 0) * frequency * (k1 + 1) / denominator
        score += term_score * (1 + min(query_frequency - 1, 2) * 0.05)
    return score


def _score_section(
    document: RunbookDocument,
    section: RunbookSection,
    alert: NormalizedAlert,
    *,
    idf: dict[str, float],
    average_length: float,
) -> tuple[float, list[str]]:
    if document.knowledge_type == RunbookKnowledgeType.INCOMPLETE:
        return 0, []
    if document.quality_status == RunbookQualityStatus.DEPRECATED:
        return 0, []
    if not _scope_matches(document, alert):
        return 0, []

    match_metadata = document.metadata.get("match") or {}
    annotations = [
        *match_metadata.get("alert_names", []),
        *match_metadata.get("metric_names", []),
        *match_metadata.get("aliases", []),
        *match_metadata.get("keywords", []),
    ]
    searchable = _normalized_match_text(
        "\n".join([document.title, section.title, section.content, *annotations])
    )
    title = _normalized_match_text(f"{document.title} {section.title}")
    weighted_values = _alert_weighted_values(alert)
    query_blob = " ".join(value for value, _, _ in weighted_values)

    score = 0.0
    reasons: list[str] = []
    direct_match = False
    for value, weight, label in weighted_values:
        if len(value) >= 4 and value in searchable:
            score += weight
            if value in title:
                score += 4
            reasons.append(f"{label}精确命中")
            direct_match = True

    if not direct_match:
        for value, _, label in weighted_values[:5]:
            value_terms = _match_terms(value)
            if len(value_terms) >= 2 and all(term in title for term in value_terms):
                score += 20
                reasons.append(f"{label}完整分词命中标题")
                direct_match = True
                break

    identity_values = {
        _normalized_match_text(value)
        for value in (
            alert.alert_name,
            alert.metric_name or "",
            alert.reason,
            alert.title,
        )
        if _normalized_match_text(value) not in _IGNORED_VALUES
    }
    for metadata_key, bonus, reason in (
        ("alert_names", 28, "结构化告警名命中"),
        ("metric_names", 25, "结构化指标名命中"),
    ):
        expected = {
            _normalized_match_text(str(item))
            for item in match_metadata.get(metadata_key, [])
        }
        if expected & identity_values:
            score += bonus
            reasons.append(reason)
            direct_match = True

    for alias in match_metadata.get("aliases", []):
        normalized_alias = _normalized_match_text(str(alias))
        alias_terms = _match_terms(normalized_alias)
        query_terms = _match_terms(query_blob)
        if normalized_alias and (
            normalized_alias in query_blob
            or (len(alias_terms) >= 2 and alias_terms.issubset(query_terms))
        ):
            score += 16
            reasons.append("手册别名命中")
            direct_match = True
            break

    query_counter = Counter(_lexical_terms(query_blob))
    document_counter = Counter(_lexical_terms(searchable))
    lexical_score = _bm25_score(query_counter, document_counter, idf, average_length)
    overlapping = set(query_counter) & set(document_counter)
    specific_overlap = {
        term for term in overlapping if len(term) >= 5 or "_" in term
    }

    if direct_match:
        score += min(12.0, lexical_score * 1.8)
    else:
        # Fuzzy retrieval must have multiple independent overlaps or one specific
        # identifier. This is the explicit no-match guard for broad database words.
        if len(overlapping) < 3 and not specific_overlap:
            return 0, []
        score += min(14.0, lexical_score * 2.2)
        if score < 8:
            return 0, []
        reasons.append("BM25/字符片段组合命中")

    if alert.severity.value in document.severities:
        score += 2
    if document.quality_status == RunbookQualityStatus.REVIEW_REQUIRED:
        score *= 0.9
        reasons.append("手册待专家审核")
    elif document.quality_status == RunbookQualityStatus.DRAFT:
        score *= 0.75
        reasons.append("手册仍为草稿")
    return score, list(dict.fromkeys(reasons))


def _score_pdf(document: RunbookDocument, alert: NormalizedAlert) -> float:
    """Backward-compatible document score used by focused unit tests."""

    section = RunbookSection(
        id=document.section,
        title=document.section,
        pages=list(range(1, int(document.metadata.get("page_count", 1)) + 1)),
        content=document.content,
    )
    terms = Counter(_lexical_terms(section.content))
    idf = {term: 1.0 for term in terms}
    score, _ = _score_section(
        document,
        section,
        alert,
        idf=idf,
        average_length=max(1, sum(terms.values())),
    )
    return score


class LocalPDFRunbookLibrary:
    """PDF-backed, annotation-aware, read-only runbook corpus."""

    def __init__(
        self,
        directory: Path,
        *,
        max_file_bytes: int = 20_000_000,
        max_text_chars: int = 200_000,
        annotation_path: Path | None = None,
        min_score: float = 12.0,
        min_confidence: float = 0.35,
    ) -> None:
        self._directory = directory
        self._max_file_bytes = max_file_bytes
        self._max_text_chars = max_text_chars
        self._annotation_path = annotation_path or directory.parent / "index.json"
        self._min_score = min_score
        self._min_confidence = min_confidence
        self._cache: dict[Path, _CachedPDF] = {}
        self._annotations_signature: tuple[int, int] | None = None
        self._annotations: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def search(
        self, alert: NormalizedAlert, limit: int = 5
    ) -> list[RunbookExcerpt]:
        documents = await self.list()
        candidates = [
            (document, section)
            for document in documents
            for section in (
                document.sections
                or [
                    RunbookSection(
                        id=document.section,
                        title=document.section,
                        pages=list(
                            range(1, int(document.metadata.get("page_count", 1)) + 1)
                        ),
                        content=document.content,
                    )
                ]
            )
            if document.knowledge_type != RunbookKnowledgeType.INCOMPLETE
            and document.quality_status != RunbookQualityStatus.DEPRECATED
        ]
        term_counters = [
            Counter(_lexical_terms(f"{document.title} {section.title} {section.content}"))
            for document, section in candidates
        ]
        document_frequency: Counter[str] = Counter()
        for terms in term_counters:
            document_frequency.update(terms.keys())
        corpus_size = max(len(term_counters), 1)
        idf = {
            term: math.log(1 + (corpus_size - frequency + 0.5) / (frequency + 0.5))
            for term, frequency in document_frequency.items()
        }
        average_length = (
            sum(sum(terms.values()) for terms in term_counters) / corpus_size
        )

        best_by_runbook: dict[str, RunbookExcerpt] = {}
        for document, section in candidates:
            score, reasons = _score_section(
                document,
                section,
                alert,
                idf=idf,
                average_length=average_length,
            )
            confidence = score / (score + 20) if score > 0 else 0
            if score < self._min_score or confidence < self._min_confidence:
                continue
            excerpt = RunbookExcerpt(
                runbook_id=document.id,
                title=document.title,
                section=section.id,
                content=section.content,
                score=round(score, 4),
                match_confidence=round(confidence, 4),
                match_reasons=reasons,
                page_refs=section.pages,
                knowledge_type=document.knowledge_type,
                quality_status=document.quality_status,
                causes=document.causes,
                actions=document.actions,
                metadata={
                    **document.metadata,
                    "section_title": section.title,
                    "retrieval": "structured_exact+bm25_char_ngram+quality_rerank",
                },
            )
            current = best_by_runbook.get(document.id)
            if current is None or excerpt.score > current.score:
                best_by_runbook[document.id] = excerpt

        matches = sorted(
            best_by_runbook.values(), key=lambda item: (-item.score, item.runbook_id)
        )
        return matches[:limit]

    async def list(self) -> list[RunbookDocument]:
        async with self._lock:
            return await asyncio.to_thread(self._list_sync)

    async def get(self, runbook_id: str) -> RunbookDocument:
        path = self._path_for(runbook_id)
        async with self._lock:
            annotations = self._read_annotations_sync()
            return await asyncio.to_thread(
                self._read_sync, path, runbook_id, annotations.get(runbook_id)
            )

    def _read_annotations_sync(self) -> dict[str, dict[str, Any]]:
        if not self._annotation_path.exists():
            self._annotations_signature = None
            self._annotations = {}
            return {}
        if not self._annotation_path.is_file() or self._annotation_path.is_symlink():
            raise RunbookError(
                f"Runbook annotation index must be a regular file: {self._annotation_path}"
            )
        stat = self._annotation_path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        if signature == self._annotations_signature:
            return self._annotations
        try:
            payload = json.loads(self._annotation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RunbookError(
                f"Cannot read runbook annotation index: {self._annotation_path}"
            ) from exc
        if payload.get("schema_version") != 1 or not isinstance(payload.get("runbooks"), list):
            raise RunbookError("Runbook annotation index must use schema_version=1")
        annotations: dict[str, dict[str, Any]] = {}
        for item in payload["runbooks"]:
            if not isinstance(item, dict) or not _SAFE_RUNBOOK_ID.fullmatch(
                str(item.get("runbook_id", ""))
            ):
                raise RunbookError("Runbook annotation contains an invalid runbook_id")
            runbook_id = str(item["runbook_id"])
            if runbook_id in annotations:
                raise RunbookError(f"Duplicate runbook annotation: {runbook_id}")
            annotations[runbook_id] = item
        self._annotations_signature = signature
        self._annotations = annotations
        self._cache.clear()
        return annotations

    def _list_sync(self) -> list[RunbookDocument]:
        if not self._directory.exists():
            raise RunbookError(f"PDF runbook directory does not exist: {self._directory}")
        if not self._directory.is_dir():
            raise RunbookError(f"PDF runbook path is not a directory: {self._directory}")

        annotations = self._read_annotations_sync()
        documents: list[RunbookDocument] = []
        active_paths: set[Path] = set()
        pdf_ids: set[str] = set()
        for path in sorted(self._directory.glob("*.pdf")):
            self._assert_regular_pdf(path)
            active_paths.add(path)
            pdf_ids.add(path.stem)
            documents.append(self._read_sync(path, path.stem, annotations.get(path.stem)))
        unknown_annotations = set(annotations) - pdf_ids
        if unknown_annotations:
            raise RunbookError(
                "Runbook annotations reference missing PDFs: "
                + ", ".join(sorted(unknown_annotations))
            )
        self._cache = {
            path: cached for path, cached in self._cache.items() if path in active_paths
        }
        return documents

    def _read_sync(
        self,
        path: Path,
        requested_id: str,
        annotation: dict[str, Any] | None = None,
    ) -> RunbookDocument:
        if not path.exists():
            raise RunbookNotFoundError(f"PDF runbook not found: {requested_id}")
        self._assert_regular_pdf(path)
        file_stat = path.stat()
        if file_stat.st_size > self._max_file_bytes:
            raise RunbookError(
                f"PDF runbook exceeds RUNBOOK_PDF_MAX_FILE_BYTES: {path.name}"
            )
        annotation_signature = self._annotations_signature or (0, 0)
        signature = (
            file_stat.st_mtime_ns,
            file_stat.st_size,
            annotation_signature[0],
            annotation_signature[1],
        )
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

        annotation = annotation or {}
        try:
            knowledge_type = RunbookKnowledgeType(
                annotation.get("knowledge_type", RunbookKnowledgeType.RUNBOOK)
            )
            quality_status = RunbookQualityStatus(
                annotation.get("quality_status", RunbookQualityStatus.DRAFT)
            )
            causes = [RunbookCause.model_validate(item) for item in annotation.get("causes", [])]
            actions = [
                RunbookAction.model_validate(item) for item in annotation.get("actions", [])
            ]
            sections: list[RunbookSection] = []
            for raw_section in annotation.get("sections", []):
                pages = list(dict.fromkeys(int(page) for page in raw_section.get("pages", [])))
                if not pages or min(pages) < 1 or max(pages) > len(page_texts):
                    raise RunbookError(
                        f"Runbook annotation has invalid pages for {path.name}: {pages}"
                    )
                section_content = "\n\n".join(
                    page_texts[page - 1] for page in pages if page_texts[page - 1]
                )
                sections.append(
                    RunbookSection(
                        id=str(raw_section["id"]),
                        title=str(raw_section["title"]),
                        pages=pages,
                        content=section_content[: self._max_text_chars],
                    )
                )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise RunbookError(f"Invalid runbook annotation for {path.name}: {exc}") from exc

        if not sections:
            sections = [
                RunbookSection(
                    id="PDF",
                    title="PDF",
                    pages=list(range(1, len(page_texts) + 1)),
                    content=content,
                )
            ]
        match_metadata = annotation.get("match") or {}
        document = RunbookDocument(
            id=path.stem,
            title=_title_from_text(content, path.stem),
            section=sections[0].id if len(sections) == 1 else "structured",
            reasons=[cause.hypothesis for cause in causes],
            keywords=[str(item) for item in match_metadata.get("keywords", [])],
            severities=_severity_values(content),
            labels={
                "database_engines": ",".join(
                    str(item) for item in (annotation.get("scope") or {}).get(
                        "database_engines", []
                    )
                ),
                "components": ",".join(
                    str(item)
                    for item in (annotation.get("scope") or {}).get("components", [])
                ),
            },
            knowledge_type=knowledge_type,
            quality_status=quality_status,
            sections=sections,
            causes=causes,
            actions=actions,
            content=content,
            metadata={
                "source_type": "local_pdf",
                "file_name": path.name,
                "page_count": len(reader.pages),
                "file_size_bytes": file_stat.st_size,
                "text_truncated": truncated,
                "annotation_source": (
                    str(self._annotation_path) if annotation else None
                ),
                "scope": annotation.get("scope") or {},
                "match": match_metadata,
                "review_notes": annotation.get("review_notes") or [],
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
