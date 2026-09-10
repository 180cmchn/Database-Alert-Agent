from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from app.domain.models import (
    EVIDENCE_RECORD_V2,
    EvidenceRecord,
    EvidenceUnit,
    EvidenceUnitKind,
)

_MODEL_EVIDENCE_FIELDS = (
    "id",
    "tool_name",
    "source_system",
    "status",
    "request",
    "summary",
    "error",
    "started_at",
    "collected_at",
    "duration_ms",
    "truncated",
)
_MODEL_EVIDENCE_UNIT_FIELDS = (
    "id",
    "parent_evidence_id",
    "kind",
    "stage",
    "result_index",
    "status",
    "summary",
    "data",
    "root_cause_eligible",
    "root_cause_ineligible_reason",
    "source_paths",
)
_MODEL_STATUS_FIELDS = (
    "partial",
    "query_completed",
    "range_query_completed",
    "range_query_attempt_count",
    "range_query_success_count",
    "range_query_empty_count",
    "processing_status",
    "processing_error_type",
    "root_cause_eligible",
    "root_cause_ineligible_reason",
    "termination_reason",
    "termination_error_type",
    "reason_code",
    "monitoring_scope_status",
    "monitoring_scope_reason",
    "model_declared_scope_status",
    "scope_declaration_verified",
    "unverified_scope_declaration",
    "target_binding_count",
)
_MODEL_TOOL_ANALYSIS_FIELDS = (
    "summary",
    "observations",
    "anomalies",
    "limitations",
    "analysis_usable",
    "source_coverage_complete",
    "provider",
    "model",
    "prompt_version",
    "passthrough_payload",
    "slow_query_analysis",
)
_MODEL_OBSERVATION_FIELDS = ("statement", "source_paths", "source_spans")
_MODEL_SOURCE_SPAN_FIELDS = (
    "path",
    "character_start",
    "character_end",
    "character_total",
)
_NON_PROJECTION_EVIDENCE_SOURCES = frozenset({"alert_platform", "flashduty_alert_detail"})
_ARCHERY_SOURCES = frozenset({"archery", "archery_mcp"})
_OMIT_MODEL_VALUE = object()
_INTERNAL_ARTIFACT_URI = re.compile(r"(?i)agent-artifact://[^\s\"'<>\]}),]+")
_BOUNDED_SHA_SUFFIX = re.compile(r"(?i)\[sha256:[0-9a-f]+,total_chars:(?P<chars>\d+)\]")
_SHA_LABEL = re.compile(r"(?i)\bsha-?256\b(?:\s*前\s*\d+\s*位)?")
_EMBEDDED_PROVENANCE_KEY = re.compile(
    r"""(?ix)
    ["']?
    (?:
        raw[_-][a-z0-9_-]*
        | [a-z0-9_-]*artifact[a-z0-9_-]*
        | source[_-]?sha256
        | sha256
        | [a-z0-9_-]*_hash
        | hash
        | request[_-]?id
        | usage
    )
    ["']?\s*[:=]
    """
)


def _model_key_name(value: str) -> str:
    snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    return re.sub(r"[^a-z0-9]+", "_", snake_case.casefold()).strip("_")


def _is_internal_provenance_key(value: str) -> bool:
    key = _model_key_name(value)
    return (
        key == "raw"
        or key.startswith("raw_")
        or "artifact" in key
        or key in {"hash", "request_id", "sha256", "source_sha256", "usage"}
        or key.endswith("_hash")
        or key.endswith("_sha256")
    )


def _clean_model_string(value: str) -> str | object:
    if value.casefold().startswith("agent-artifact://"):
        return _OMIT_MODEL_VALUE

    cleaned = _BOUNDED_SHA_SUFFIX.sub(
        lambda match: f"[total_chars:{match.group('chars')}]",
        value,
    )

    object_start = cleaned.find("{")
    if object_start >= 0 and cleaned.rstrip().endswith("}"):
        try:
            embedded = json.loads(cleaned[object_start:])
        except (TypeError, ValueError):
            pass
        else:
            projected = _clean_model_value(embedded)
            if projected is _OMIT_MODEL_VALUE:
                projected = {}
            cleaned = cleaned[:object_start] + json.dumps(
                projected,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )

    if _EMBEDDED_PROVENANCE_KEY.search(cleaned):
        return "[内部审计来源信息已移除]"
    cleaned = _INTERNAL_ARTIFACT_URI.sub("[内部审计工件已移除]", cleaned)
    return _SHA_LABEL.sub("匿名分组标识", cleaned)


def _clean_model_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _is_internal_provenance_key(key):
                continue
            projected = _clean_model_value(raw_value)
            if projected is not _OMIT_MODEL_VALUE:
                cleaned[key] = projected
        return cleaned
    if isinstance(value, (list, tuple)):
        cleaned_items = [_clean_model_value(item) for item in value]
        return [item for item in cleaned_items if item is not _OMIT_MODEL_VALUE]
    if isinstance(value, str):
        return _clean_model_string(value)
    return value


def _model_source_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    if any(
        _is_internal_provenance_key(part.replace("~1", "/").replace("~0", "~"))
        for part in value.split("/")[1:]
    ):
        return None
    cleaned = _clean_model_string(value)
    return cleaned if isinstance(cleaned, str) else None


def _model_observation_payload(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    for field_name in _MODEL_OBSERVATION_FIELDS:
        if field_name not in value:
            continue
        if field_name == "source_paths":
            paths = (
                [
                    path
                    for item in value[field_name]
                    if (path := _model_source_path(item)) is not None
                ]
                if isinstance(value[field_name], (list, tuple))
                else []
            )
            result[field_name] = paths
            continue
        if field_name == "source_spans":
            spans: list[dict[str, Any]] = []
            if isinstance(value[field_name], (list, tuple)):
                for raw_span in value[field_name]:
                    if not isinstance(raw_span, Mapping):
                        continue
                    span = {
                        key: _clean_model_value(raw_span[key])
                        for key in _MODEL_SOURCE_SPAN_FIELDS
                        if key in raw_span
                    }
                    path = _model_source_path(span.get("path"))
                    if path is not None:
                        span["path"] = path
                        spans.append(span)
            result[field_name] = spans
            continue
        projected = _clean_model_value(value[field_name])
        if projected is not _OMIT_MODEL_VALUE:
            result[field_name] = projected
    return result if isinstance(result.get("statement"), str) else None


def _model_tool_analysis_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for field_name in _MODEL_TOOL_ANALYSIS_FIELDS:
        if field_name not in value:
            continue
        if field_name in {"observations", "anomalies"}:
            items = value[field_name]
            result[field_name] = (
                [
                    projected
                    for item in items
                    if (projected := _model_observation_payload(item)) is not None
                ]
                if isinstance(items, (list, tuple))
                else []
            )
            continue
        projected = _clean_model_value(value[field_name])
        if projected is not _OMIT_MODEL_VALUE:
            result[field_name] = projected
    return result


def _model_structured_data_payload(evidence: EvidenceRecord) -> dict[str, Any]:
    data = evidence.structured_data
    is_program_projection = (
        evidence.source_system.casefold() not in _NON_PROJECTION_EVIDENCE_SOURCES
        or "processing_status" in data
        or "tool_result_analysis" in data
    )
    if not is_program_projection:
        projected = _clean_model_value(data)
        return projected if isinstance(projected, dict) else {}

    result = {
        field: projected
        for field in _MODEL_STATUS_FIELDS
        if field in data
        and (projected := _clean_model_value(data[field])) is not _OMIT_MODEL_VALUE
    }
    if "tool_result_analysis" in data:
        result["tool_result_analysis"] = _model_tool_analysis_payload(
            data["tool_result_analysis"]
        )
    return result


def _is_lossless_archery_history(source_system: str, unit: EvidenceUnit) -> bool:
    return (
        source_system.casefold() in _ARCHERY_SOURCES
        and unit.kind == EvidenceUnitKind.HISTORY
    )


def _model_evidence_unit_payload(
    unit: EvidenceUnit,
    *,
    source_system: str,
) -> dict[str, Any]:
    """Expose one unit without its internal artifact identity."""

    serialized = unit.model_dump(mode="json")
    lossless_history = _is_lossless_archery_history(source_system, unit)
    payload: dict[str, Any] = {}
    for field_name in _MODEL_EVIDENCE_UNIT_FIELDS:
        if lossless_history and field_name in {"data", "source_paths"}:
            payload[field_name] = deepcopy(serialized[field_name])
            continue
        if field_name == "source_paths":
            payload[field_name] = [
                path
                for item in serialized[field_name]
                if (path := _model_source_path(item)) is not None
            ]
            continue
        projected = _clean_model_value(serialized[field_name])
        if projected is not _OMIT_MODEL_VALUE:
            payload[field_name] = projected
    return payload


def model_evidence_payload(evidence: EvidenceRecord) -> dict[str, Any]:
    """Build the single model/trace DTO for one evidence record."""

    serialized = evidence.model_dump(mode="json")
    payload: dict[str, Any] = {}
    for field_name in _MODEL_EVIDENCE_FIELDS:
        projected = _clean_model_value(serialized[field_name])
        if projected is not _OMIT_MODEL_VALUE:
            payload[field_name] = projected
    structured_data = _model_structured_data_payload(evidence)
    if evidence.contract_version == EVIDENCE_RECORD_V2:
        payload["contract_version"] = evidence.contract_version
        tool_analysis = structured_data.get("tool_result_analysis")
        if isinstance(tool_analysis, dict):
            tool_analysis.pop("passthrough_payload", None)
            tool_analysis.pop("slow_query_analysis", None)
    payload["structured_data"] = structured_data
    if evidence.evidence_units:
        payload["evidence_units"] = [
            _model_evidence_unit_payload(
                item,
                source_system=evidence.source_system,
            )
            for item in evidence.evidence_units
        ]
    return payload
