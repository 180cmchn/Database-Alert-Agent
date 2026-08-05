from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.domain.errors import (
    InvalidRunbookIdError,
    RunbookAlertTypeNotFoundError,
    RunbookError,
    RunbookNotFoundError,
)
from app.domain.models import (
    NormalizedAlert,
    RunbookAction,
    RunbookCause,
    RunbookDocument,
    RunbookExcerpt,
    RunbookKnowledgeType,
    RunbookSection,
    RunbookVisualEvidence,
)

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_MAX_ALERT_TYPE_DIRECTORY_LENGTH = 128
_SEVERITY_PATTERN = re.compile(r"(?i)\[(critical|warning|info)\]")
_LATIN_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_-]{2,}")
_CHINESE_RUN_PATTERN = re.compile(r"[\u4e00-\u9fff]{2,}")
_FILTER_OPERATOR_SPACING = re.compile(r"\s*(>=|<=|!=|==|=|>|<)\s*")
_ASCII_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_IDENTIFIER_WORD_CHAR = r"a-z0-9\u4e00-\u9fff"
_IGNORED_VALUES = {"", "unknown", "none", "null", "n/a"}
_ALERT_TYPE_LABEL_PATTERNS = (
    re.compile(
        r"(?im)^(?:告警类型|告警名称|告警项|alert[ _-]*(?:type|name))\s*[：:]\s*"
        r"([^\n]{2,200})$"
    ),
    re.compile(r"(?i)([a-z][a-z0-9_.:-]{3,})\s*告警"),
)
_ALERT_TYPE_VALUE_SEPARATOR = re.compile(r"[,，;；、|]+")
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


@dataclass(frozen=True)
class _CachedAnnotations:
    signature: tuple[int, int]
    annotations: dict[str, dict[str, Any]]


def alert_type_directory_name(value: str) -> str:
    """Return the shared, path-safe key used by processing and retrieval.

    Alert types are case-insensitive identifiers. Punctuation and whitespace are
    normalized to underscores so an incoming alert and its processed PDF always
    resolve to the same directory without using fuzzy matching.
    """

    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    characters = [
        character if character.isalnum() or character == "_" else "_"
        for character in normalized
    ]
    key = re.sub(r"_+", "_", "".join(characters)).strip("_")
    if not key or key in _IGNORED_VALUES:
        raise ValueError("alert_type must contain a usable identifier")
    if len(key) > _MAX_ALERT_TYPE_DIRECTORY_LENGTH:
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
        prefix_length = _MAX_ALERT_TYPE_DIRECTORY_LENGTH - len(digest) - 1
        key = f"{key[:prefix_length].rstrip('_')}_{digest}"
    return key


def derive_runbook_alert_types(
    pdf_text: str,
    annotation: dict[str, Any] | None = None,
) -> list[str]:
    """Derive all canonical alert types discoverable for a PDF.

    An explicit ``alert_types`` annotation wins, followed by the singular
    ``alert_type``. Existing structured alert/metric identities are the next safest
    processing result. Otherwise all labelled alert types in the PDF text are
    collected, and legacy indexes may use their primary alias. Results are
    normalized and deduplicated; inferred candidates are sorted, while an explicit
    plural annotation preserves first-seen order.
    """

    annotation = annotation or {}
    if "alert_types" in annotation:
        raw_alert_types = annotation["alert_types"]
        if not isinstance(raw_alert_types, list) or not raw_alert_types:
            raise RunbookError("PDF annotation alert_types must be a non-empty list")
        explicit_alert_types: list[str] = []
        seen_alert_types: set[str] = set()
        for value in raw_alert_types:
            if not isinstance(value, str) or not value.strip():
                raise RunbookError(
                    "PDF annotation alert_types entries must be non-empty strings"
                )
            try:
                normalized = alert_type_directory_name(value)
            except ValueError as exc:
                raise RunbookError(
                    "PDF annotation alert_types entries must contain usable identifiers"
                ) from exc
            if normalized not in seen_alert_types:
                explicit_alert_types.append(normalized)
                seen_alert_types.add(normalized)

        if "alert_type" in annotation:
            singular = annotation["alert_type"]
            if not isinstance(singular, str) or not singular.strip():
                raise RunbookError(
                    "PDF annotation alert_type must be a non-empty string when "
                    "alert_types is present"
                )
            try:
                normalized_singular = alert_type_directory_name(singular)
            except ValueError as exc:
                raise RunbookError(
                    "PDF annotation alert_type must contain a usable identifier "
                    "when alert_types is present"
                ) from exc
            if normalized_singular not in seen_alert_types:
                raise RunbookError(
                    "PDF annotation alert_type must also be included in alert_types"
                )
        return explicit_alert_types

    explicit = annotation.get("alert_type")
    if isinstance(explicit, str) and explicit.strip():
        return [alert_type_directory_name(explicit)]

    match_metadata = annotation.get("match") or {}
    structured_candidates: set[str] = set()
    for field in ("alert_names", "metric_names"):
        for value in _metadata_strings(match_metadata, field):
            structured_candidates.add(alert_type_directory_name(value))
    if structured_candidates:
        return sorted(structured_candidates)

    for pattern in _ALERT_TYPE_LABEL_PATTERNS:
        labelled_candidates: set[str] = set()
        for match in pattern.finditer(pdf_text[:20_000]):
            for raw_candidate in _ALERT_TYPE_VALUE_SEPARATOR.split(match.group(1)):
                candidate = raw_candidate.strip(" \t-—_:：,，。.;；[]【】()（）")
                ascii_named_alert = re.fullmatch(
                    r"(?i)([a-z][a-z0-9_.:-]{3,})\s*告警",
                    candidate,
                )
                if ascii_named_alert:
                    candidate = ascii_named_alert.group(1)
                if candidate:
                    labelled_candidates.add(alert_type_directory_name(candidate))
        if labelled_candidates:
            return sorted(labelled_candidates)

    aliases = _metadata_strings(match_metadata, "aliases")
    if aliases:
        return [alert_type_directory_name(aliases[0])]
    raise RunbookError(
        "Cannot derive alert type from PDF; add an alert_type annotation"
    )


def derive_runbook_alert_type(
    pdf_text: str,
    annotation: dict[str, Any] | None = None,
) -> str:
    """Backward-compatible singular wrapper around ``derive_runbook_alert_types``."""

    alert_types = derive_runbook_alert_types(pdf_text, annotation)
    if len(alert_types) > 1:
        raise RunbookError(
            "PDF processing found multiple alert types; add one alert_type to its "
            "annotation"
        )
    return alert_types[0]


def _normalize_pdf_text(value: str) -> str:
    lines: list[str] = []
    for line in value.replace("\x00", "").splitlines():
        normalized = re.sub(r"[\t\r\f\v ]+", " ", line).strip()
        if normalized:
            lines.append(normalized)
    return "\n".join(lines)


def _normalized_match_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _normalized_log_signature(value: str) -> str:
    normalized = _normalized_match_text(value)
    return re.sub(r"[^a-z0-9_\u4e00-\u9fff]+", " ", normalized).strip()


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


def _metadata_strings(metadata: dict[str, Any], key: str) -> list[str]:
    """Read schema string arrays while tolerating legacy singleton strings."""

    value = metadata.get(key, [])
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value if item is not None]
    else:
        return []
    return [item.strip() for item in values if item.strip()]


def _scalar_filter_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _flatten_alert_filter_text(
    value: Any,
    *,
    path: tuple[str, ...] = (),
) -> tuple[list[str], list[str]]:
    """Return alert values and key/value expressions for runbook gates."""

    values: list[str] = []
    assignments: list[str] = []
    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = str(raw_key).strip()
            nested_path = (*path, key) if key else path
            scalar = _scalar_filter_text(nested)
            if scalar is not None:
                values.append(scalar)
                if key:
                    assignments.append(f"{key}={scalar}")
                if nested_path:
                    assignments.append(f"{'.'.join(nested_path)}={scalar}")
                continue
            nested_values, nested_assignments = _flatten_alert_filter_text(
                nested,
                path=nested_path,
            )
            values.extend(nested_values)
            assignments.extend(nested_assignments)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            scalar = _scalar_filter_text(nested)
            if scalar is not None:
                values.append(scalar)
            else:
                nested_values, nested_assignments = _flatten_alert_filter_text(
                    nested,
                    path=path,
                )
                values.extend(nested_values)
                assignments.extend(nested_assignments)
    else:
        scalar = _scalar_filter_text(value)
        if scalar is not None:
            values.append(scalar)
    return values, assignments


def _normalized_filter_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = _FILTER_OPERATOR_SPACING.sub(r"\1", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def _identifier_filter_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    value = re.sub(r"[_./:=-]+", " ", value)
    return _normalized_filter_text(value)


def _alert_filter_blobs(alert: NormalizedAlert) -> tuple[str, str, str]:
    values, assignments = _flatten_alert_filter_text(
        alert.model_dump(mode="json")
    )
    value_blob = _normalized_filter_text("\n".join(values))
    condition_blob = _normalized_filter_text("\n".join([*values, *assignments]))
    identifier_blob = _identifier_filter_text("\n".join(values))
    return value_blob, condition_blob, identifier_blob


def _filter_phrase_present(
    phrase: str,
    *blobs: str,
    identifier_boundary: bool = False,
) -> bool:
    normalized = _normalized_filter_text(phrase)
    if not normalized:
        return False
    candidates = [normalized]
    signature = _normalized_log_signature(normalized)
    if signature and signature != normalized:
        candidates.append(signature)
    for candidate in candidates:
        if identifier_boundary or _ASCII_IDENTIFIER.fullmatch(candidate):
            pattern = re.compile(
                rf"(?<![{_IDENTIFIER_WORD_CHAR}])"
                rf"{re.escape(candidate)}"
                rf"(?![{_IDENTIFIER_WORD_CHAR}])"
            )
            if any(pattern.search(blob) for blob in blobs):
                return True
        elif any(candidate in blob for blob in blobs):
            return True
    return False


def _scope_matches(
    document: RunbookDocument,
    alert: NormalizedAlert,
    *,
    value_blob: str,
    identifier_blob: str,
) -> bool:
    scope = document.metadata.get("scope") or {}
    engines = {
        _normalized_match_text(item)
        for item in _metadata_strings(scope, "database_engines")
    }
    alert_engine = _normalized_match_text(
        (alert.database.engine or "") if alert.database else ""
    )
    if engines and alert_engine and alert_engine not in engines:
        return False

    components = _metadata_strings(scope, "components")
    if not components:
        return True
    return any(
        _filter_phrase_present(
            component,
            value_blob,
            identifier_blob,
            identifier_boundary=True,
        )
        for component in components
    )


def _match_conditions(
    match_metadata: dict[str, Any],
    *,
    condition_blob: str,
) -> bool:
    required = _metadata_strings(match_metadata, "required_conditions")
    excluded = _metadata_strings(match_metadata, "exclusion_conditions")
    return all(
        _filter_phrase_present(condition, condition_blob)
        for condition in required
    ) and not any(
        _filter_phrase_present(condition, condition_blob)
        for condition in excluded
    )


def _section_visual_evidence(
    document: RunbookDocument, section: RunbookSection
) -> list[RunbookVisualEvidence]:
    pages = set(section.pages)
    return [
        item
        for item in document.visual_evidence
        if item.page in pages and (not item.section_ids or section.id in item.section_ids)
    ]


def _section_causes(
    document: RunbookDocument, section: RunbookSection
) -> list[RunbookCause]:
    return [
        item
        for item in document.causes
        if not item.section_ids or section.id in item.section_ids
    ]


def _section_actions(
    document: RunbookDocument, section: RunbookSection
) -> list[RunbookAction]:
    return [
        item
        for item in document.actions
        if not item.section_ids or section.id in item.section_ids
    ]


def _visual_search_text(items: list[RunbookVisualEvidence]) -> str:
    return "\n".join(
        [part for item in items for part in (item.text, *item.keywords) if part]
    )


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
    if document.deprecated:
        return 0, []
    value_blob, condition_blob, identifier_blob = _alert_filter_blobs(alert)
    if not _scope_matches(
        document,
        alert,
        value_blob=value_blob,
        identifier_blob=identifier_blob,
    ):
        return 0, []

    match_metadata = document.metadata.get("match") or {}
    if not _match_conditions(match_metadata, condition_blob=condition_blob):
        return 0, []
    visual_evidence = _section_visual_evidence(document, section)
    visual_searchable = _normalized_match_text(_visual_search_text(visual_evidence))
    annotations = [
        *match_metadata.get("alert_names", []),
        *match_metadata.get("metric_names", []),
        *match_metadata.get("aliases", []),
        *match_metadata.get("keywords", []),
        *section.match_terms,
    ]
    searchable = _normalized_match_text(
        "\n".join(
            [
                document.title,
                section.title,
                section.content,
                *annotations,
                visual_searchable,
            ]
        )
    )
    title = _normalized_match_text(f"{document.title} {section.title}")
    weighted_values = _alert_weighted_values(alert)
    query_blob = " ".join(value for value, _, _ in weighted_values)

    score = 0.0
    reasons: list[str] = []
    direct_match = False
    for value, weight, label in weighted_values:
        visual_hit = value in visual_searchable or (
            len(_normalized_log_signature(value)) >= 4
            and _normalized_log_signature(value)
            in _normalized_log_signature(visual_searchable)
        )
        if len(value) >= 4 and (value in searchable or visual_hit):
            score += weight
            if value in title:
                score += 4
            if visual_hit:
                score += 6
                reasons.append(f"{label}命中图片关键报错")
            else:
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

    for match_term in section.match_terms:
        normalized_term = _normalized_match_text(match_term)
        if normalized_term and normalized_term in query_blob:
            score += 24
            reasons.append("章节结构化特征命中")
            direct_match = True
            break

    for item in visual_evidence:
        for keyword in item.keywords:
            normalized_keyword = _normalized_match_text(keyword)
            if normalized_keyword and normalized_keyword in query_blob:
                score += 14
                reasons.append("图片关键词命中")
                direct_match = True
                break
        if "图片关键词命中" in reasons:
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
        min_score: float = 12.0,
        min_confidence: float = 0.35,
    ) -> None:
        self._directory = directory
        self._max_file_bytes = max_file_bytes
        self._max_text_chars = max_text_chars
        self._min_score = min_score
        self._min_confidence = min_confidence
        self._cache: dict[Path, _CachedPDF] = {}
        self._annotation_cache: dict[Path, _CachedAnnotations] = {}
        self._lock = asyncio.Lock()

    async def search(
        self, alert: NormalizedAlert, limit: int = 5
    ) -> list[RunbookExcerpt]:
        try:
            alert_type = alert_type_directory_name(alert.alert_type)
        except ValueError as exc:
            raise RunbookAlertTypeNotFoundError(alert.alert_type) from exc
        async with self._lock:
            documents = await asyncio.to_thread(
                self._list_alert_type_sync, alert_type
            )
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
            and not document.deprecated
        ]
        term_counters = [
            Counter(
                _lexical_terms(
                    " ".join(
                        [
                            document.title,
                            section.title,
                            section.content,
                            _visual_search_text(
                                _section_visual_evidence(document, section)
                            ),
                        ]
                    )
                )
            )
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
                causes=_section_causes(document, section),
                actions=_section_actions(document, section),
                visual_evidence=_section_visual_evidence(document, section),
                metadata={
                    **document.metadata,
                    "section_title": section.title,
                    "retrieval": "structured_exact+visual_evidence+bm25_char_ngram",
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
        async with self._lock:
            paths = await asyncio.to_thread(self._paths_for, runbook_id)
            path = paths[0]
            alert_type_directory = path.parent
            annotations, signature, annotation_path = self._read_annotations_sync(
                alert_type_directory
            )
            document = await asyncio.to_thread(
                self._read_sync,
                path,
                runbook_id,
                annotations.get(runbook_id),
                signature,
                annotation_path,
                alert_type_directory.name,
            )
            return self._with_alert_types(
                document, [candidate.parent.name for candidate in paths]
            )

    def _read_annotations_sync(
        self,
        alert_type_directory: Path,
    ) -> tuple[dict[str, dict[str, Any]], tuple[int, int], Path]:
        annotation_path = alert_type_directory / "index.json"
        if not annotation_path.exists():
            self._annotation_cache.pop(annotation_path, None)
            return {}, (0, 0), annotation_path
        if not annotation_path.is_file() or annotation_path.is_symlink():
            raise RunbookError(
                f"Runbook annotation index must be a regular file: {annotation_path}"
            )
        stat = annotation_path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        cached = self._annotation_cache.get(annotation_path)
        if cached and signature == cached.signature:
            return cached.annotations, signature, annotation_path
        try:
            payload = json.loads(annotation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RunbookError(
                f"Cannot read runbook annotation index: {annotation_path}"
            ) from exc
        schema_version = payload.get("schema_version")
        if schema_version not in {1, 2, 3} or not isinstance(
            payload.get("runbooks"), list
        ):
            raise RunbookError(
                "Runbook annotation index must use schema_version=1, 2 or 3"
            )
        if schema_version == 3:
            declared_alert_type = payload.get("alert_type")
            if not isinstance(declared_alert_type, str):
                raise RunbookError(
                    f"Runbook annotation index has no alert_type: {annotation_path}"
                )
            try:
                declared_directory = alert_type_directory_name(declared_alert_type)
            except ValueError as exc:
                raise RunbookError(
                    f"Runbook annotation index has invalid alert_type: {annotation_path}"
                ) from exc
            if declared_directory != alert_type_directory.name:
                raise RunbookError(
                    "Runbook annotation alert_type does not match its directory: "
                    f"{annotation_path}"
                )
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
        self._annotation_cache[annotation_path] = _CachedAnnotations(
            signature=signature,
            annotations=annotations,
        )
        return annotations, signature, annotation_path

    def _list_sync(self) -> list[RunbookDocument]:
        alert_type_directories = self._alert_type_directories_sync()
        documents_by_id: dict[str, list[tuple[RunbookDocument, Path]]] = {}
        active_paths: set[Path] = set()
        for alert_type_directory in alert_type_directories:
            type_documents, type_paths = self._list_directory_sync(
                alert_type_directory
            )
            for document in type_documents:
                documents_by_id.setdefault(document.id, []).append(
                    (
                        document,
                        alert_type_directory / f"{document.id}.pdf",
                    )
                )
            active_paths.update(type_paths)

        documents: list[RunbookDocument] = []
        for runbook_id, records in documents_by_id.items():
            paths = [path for _, path in records]
            self._assert_equivalent_runbook_copies(runbook_id, paths)
            documents.append(
                self._with_alert_types(
                    records[0][0],
                    [path.parent.name for path in paths],
                )
            )
        self._cache = {
            path: cached for path, cached in self._cache.items() if path in active_paths
        }
        return documents

    def _list_alert_type_sync(self, alert_type: str) -> list[RunbookDocument]:
        self._assert_root_directory()
        alert_type_directory = self._directory / alert_type
        if not alert_type_directory.exists():
            raise RunbookAlertTypeNotFoundError(alert_type)
        self._assert_alert_type_directory(alert_type_directory)
        documents, _ = self._list_directory_sync(alert_type_directory)
        for document in documents:
            self._paths_for(document.id)
        return documents

    def _list_directory_sync(
        self,
        alert_type_directory: Path,
    ) -> tuple[list[RunbookDocument], set[Path]]:
        annotations, annotation_signature, annotation_path = (
            self._read_annotations_sync(alert_type_directory)
        )
        documents: list[RunbookDocument] = []
        active_paths: set[Path] = set()
        pdf_ids: set[str] = set()
        for path in sorted(alert_type_directory.glob("*.pdf")):
            self._assert_regular_pdf(path, alert_type_directory)
            active_paths.add(path)
            pdf_ids.add(path.stem)
            documents.append(
                self._read_sync(
                    path,
                    path.stem,
                    annotations.get(path.stem),
                    annotation_signature,
                    annotation_path,
                    alert_type_directory.name,
                )
            )
        unknown_annotations = set(annotations) - pdf_ids
        if unknown_annotations:
            raise RunbookError(
                "Runbook annotations reference missing PDFs: "
                + ", ".join(sorted(unknown_annotations))
            )
        return documents, active_paths

    def _alert_type_directories_sync(self) -> list[Path]:
        self._assert_root_directory()
        flat_pdfs = sorted(self._directory.glob("*.pdf"))
        if flat_pdfs:
            raise RunbookError(
                "PDF runbooks must be organized under alert type directories: "
                + ", ".join(path.name for path in flat_pdfs)
            )
        directories: list[Path] = []
        for path in sorted(self._directory.iterdir()):
            if path.name.startswith(".") or not path.is_dir():
                continue
            self._assert_alert_type_directory(path)
            directories.append(path)
        return directories

    def _assert_root_directory(self) -> None:
        if not self._directory.exists():
            raise RunbookError(f"PDF runbook directory does not exist: {self._directory}")
        if not self._directory.is_dir():
            raise RunbookError(f"PDF runbook path is not a directory: {self._directory}")

    def _assert_alert_type_directory(self, path: Path) -> None:
        root = self._directory.resolve()
        try:
            canonical_name = alert_type_directory_name(path.name)
        except ValueError as exc:
            raise RunbookError(f"Invalid alert type directory: {path.name}") from exc
        if (
            path.is_symlink()
            or not path.is_dir()
            or path.resolve().parent != root
            or canonical_name != path.name
        ):
            raise RunbookError(f"Invalid alert type directory: {path.name}")

    def _read_sync(
        self,
        path: Path,
        requested_id: str,
        annotation: dict[str, Any] | None = None,
        annotation_signature: tuple[int, int] = (0, 0),
        annotation_path: Path | None = None,
        alert_type: str = "",
    ) -> RunbookDocument:
        if not path.exists():
            raise RunbookNotFoundError(f"PDF runbook not found: {requested_id}")
        self._assert_regular_pdf(path, path.parent)
        file_stat = path.stat()
        if file_stat.st_size > self._max_file_bytes:
            raise RunbookError(
                f"PDF runbook exceeds RUNBOOK_PDF_MAX_FILE_BYTES: {path.name}"
            )
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
            image_pages: list[int] = []
            for page_number, page in enumerate(reader.pages, start=1):
                try:
                    page_texts.append(_normalize_pdf_text(page.extract_text() or ""))
                    if len(page.images) > 0:
                        image_pages.append(page_number)
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
            deprecated = annotation.get("deprecated", False)
            if not isinstance(deprecated, bool):
                raise ValueError("deprecated must be a boolean")
            causes = [RunbookCause.model_validate(item) for item in annotation.get("causes", [])]
            actions = [
                RunbookAction.model_validate(item) for item in annotation.get("actions", [])
            ]
            visual_evidence = [
                RunbookVisualEvidence.model_validate(item)
                for item in annotation.get("visual_evidence", [])
            ]
            if any(item.page > len(page_texts) for item in visual_evidence):
                raise RunbookError(
                    f"Runbook annotation has invalid visual evidence pages for {path.name}"
                )
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
                        match_terms=[
                            str(item) for item in raw_section.get("match_terms", [])
                        ],
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
        section_ids = {section.id for section in sections}
        referenced_section_ids = {
            section_id
            for item in [*causes, *actions, *visual_evidence]
            for section_id in item.section_ids
        }
        unknown_section_ids = referenced_section_ids - section_ids
        if unknown_section_ids:
            raise RunbookError(
                f"Runbook annotation references unknown sections for {path.name}: "
                f"{sorted(unknown_section_ids)}"
            )
        cause_ids = {cause.cause_id for cause in causes}
        unknown_action_causes = {
            action.cause_id
            for action in actions
            if action.cause_id and action.cause_id not in cause_ids
        }
        if unknown_action_causes:
            raise RunbookError(
                f"Runbook annotation actions reference unknown causes for {path.name}: "
                f"{sorted(unknown_action_causes)}"
            )
        match_metadata = annotation.get("match") or {}
        visual_annotated_pages = sorted({item.page for item in visual_evidence})
        unannotated_image_pages = sorted(set(image_pages) - set(visual_annotated_pages))
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
            deprecated=deprecated,
            sections=sections,
            causes=causes,
            actions=actions,
            visual_evidence=visual_evidence,
            content=content,
            metadata={
                "source_type": "local_pdf",
                "file_name": path.name,
                "alert_type": alert_type,
                "alert_types": [alert_type],
                "alert_type_directory": alert_type,
                "page_count": len(reader.pages),
                "file_size_bytes": file_stat.st_size,
                "text_truncated": truncated,
                "image_pages": image_pages,
                "visual_annotated_pages": visual_annotated_pages,
                "unannotated_image_pages": unannotated_image_pages,
                "visual_coverage_complete": not unannotated_image_pages,
                "annotation_source": (
                    str(annotation_path) if annotation and annotation_path else None
                ),
                "scope": annotation.get("scope") or {},
                "match": match_metadata,
            },
            version=1,
            updated_at=datetime.fromtimestamp(file_stat.st_mtime, UTC),
        )
        self._cache[path] = _CachedPDF(signature=signature, document=document)
        return document

    def _paths_for(self, runbook_id: str) -> list[Path]:
        if not _SAFE_RUNBOOK_ID.fullmatch(runbook_id):
            raise InvalidRunbookIdError(
                "PDF runbook ID must use 1-128 letters, digits, underscores or hyphens"
            )
        self._assert_root_directory()
        candidates = sorted(self._directory.glob(f"*/{runbook_id}.pdf"))
        if not candidates:
            raise RunbookNotFoundError(f"PDF runbook not found: {runbook_id}")
        for path in candidates:
            self._assert_alert_type_directory(path.parent)
            self._assert_regular_pdf(path, path.parent)
        self._assert_equivalent_runbook_copies(runbook_id, candidates)
        return candidates

    def _path_for(self, runbook_id: str) -> Path:
        """Resolve the deterministic canonical copy of a runbook."""

        return self._paths_for(runbook_id)[0]

    @staticmethod
    def _with_alert_types(
        document: RunbookDocument,
        alert_types: list[str],
    ) -> RunbookDocument:
        metadata = dict(document.metadata)
        merged_alert_types = sorted(
            {
                *_metadata_strings(metadata, "alert_types"),
                *alert_types,
            }
        )
        if metadata.get("alert_types") == merged_alert_types:
            return document
        metadata["alert_types"] = merged_alert_types
        return document.model_copy(update={"metadata": metadata})

    def _assert_equivalent_runbook_copies(
        self,
        runbook_id: str,
        paths: list[Path],
    ) -> None:
        if len(paths) < 2:
            return

        digests: set[str] = set()
        try:
            for path in paths:
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
                digests.add(digest.hexdigest())
        except OSError as exc:
            raise RunbookError(
                f"Cannot read PDF runbook copy for comparison: {runbook_id}"
            ) from exc
        if len(digests) > 1:
            directories = ", ".join(path.parent.name for path in paths)
            raise RunbookError(
                f"Conflicting PDF runbook copies for ID {runbook_id} across alert "
                f"type directories have different PDF content: {directories}"
            )

        semantic_annotations: list[dict[str, Any]] = []
        for path in paths:
            annotations, _, _ = self._read_annotations_sync(path.parent)
            annotation = annotations.get(runbook_id) or {}
            semantic_annotations.append(
                {key: value for key, value in annotation.items() if key != "alert_type"}
            )
        if any(
            annotation != semantic_annotations[0]
            for annotation in semantic_annotations[1:]
        ):
            directories = ", ".join(path.parent.name for path in paths)
            raise RunbookError(
                f"Conflicting PDF runbook copies for ID {runbook_id} across alert "
                f"type directories have different structured annotations: "
                f"{directories}"
            )

    def _assert_regular_pdf(self, path: Path, managed_directory: Path) -> None:
        root = managed_directory.resolve()
        if (
            path.suffix.casefold() != ".pdf"
            or path.is_symlink()
            or path.resolve().parent != root
            or not path.is_file()
        ):
            raise RunbookError(f"PDF runbook is not a regular managed file: {path.name}")
