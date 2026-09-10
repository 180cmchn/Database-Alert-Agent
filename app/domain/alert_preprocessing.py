from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from app.domain.models import NormalizedAlert

_MANAGEMENT_PLATFORM_SQL_FILTER_NOTE = re.compile(
    r"[（(]\s*已排除\s*\d[\d,，]*\s*(?:个|条)?\s*"
    r"数据库管理平台\s*(?:采集数据用|数据采集用|采集用|采集使用)"
    r"(?:的)?\s*SQL(?:语句)?\s*[）)]",
    re.IGNORECASE,
)


def preprocess_alert_text(value: str) -> str:
    """Remove slow-query SQL exclusion notes that are not diagnostic evidence."""

    cleaned = _MANAGEMENT_PLATFORM_SQL_FILTER_NOTE.sub("", value)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"[ \t]+(?=[，。！？；：,.!?;:])", "", cleaned)
    return cleaned.strip()


def _preprocess_alert_value(value: Any) -> Any:
    if isinstance(value, str):
        return preprocess_alert_text(value)
    if isinstance(value, Mapping):
        return {str(key): _preprocess_alert_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_preprocess_alert_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_preprocess_alert_value(item) for item in value)
    return value


def preprocess_alert_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Preprocess one alert payload without accepting arbitrary tool evidence."""

    return {str(key): _preprocess_alert_value(item) for key, item in value.items()}


def has_management_platform_sql_filter_note(value: Any) -> bool:
    """Return whether raw alert data says management collection SQL was filtered."""

    if isinstance(value, str):
        return _MANAGEMENT_PLATFORM_SQL_FILTER_NOTE.search(value) is not None
    if isinstance(value, dict):
        return any(has_management_platform_sql_filter_note(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(has_management_platform_sql_filter_note(item) for item in value)
    return False


def is_management_platform_collection_sql_cause(value: str) -> bool:
    """Identify the invalid cause implied by the already-applied filter note."""

    compact = re.sub(r"\s+", "", value).casefold()
    return "数据库管理平台" in compact and "采集" in compact and "sql" in compact


def preprocess_normalized_alert(alert: NormalizedAlert) -> NormalizedAlert:
    """Build the analysis view while retaining the original payload for audit."""

    analysis_data = preprocess_alert_payload(
        alert.model_dump(mode="python", exclude={"raw_payload"})
    )
    for field in ("title", "reason"):
        if not str(analysis_data.get(field) or "").strip():
            analysis_data[field] = "数据库慢查询告警"
    if not str(analysis_data.get("alert_type") or "").strip():
        analysis_data["alert_type"] = analysis_data["reason"]
    if not str(analysis_data.get("alert_name") or "").strip():
        analysis_data["alert_name"] = analysis_data["alert_type"]
    return NormalizedAlert.model_validate(
        {**analysis_data, "raw_payload": alert.raw_payload}
    )
