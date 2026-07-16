from __future__ import annotations

import re
from typing import Any

from app.domain.models import DatabaseTarget, NormalizedAlert

REDACTED = "***REDACTED***"

_SENSITIVE_KEY = re.compile(
    r"(^|[_-])(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|"
    r"credential|dsn|connection[_-]?string)([_-]|$)",
    re.IGNORECASE,
)
_URI_CREDENTIAL = re.compile(r"([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@]+)(@)", re.IGNORECASE)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)\b((?:proxy[-_ ]?)?authorization)\s*[:=]\s*[^\r\n]+"
)
_URL_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:key|token|access[_-]?token|refresh[_-]?token|api[_-]?key)=)"
    r"([^&#\s]+)"
)
_INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|api[_-]?key|client[_-]?secret|secret)\s*[=:]\s*([^\s,;]+)"
)


def sanitize_text(value: str) -> str:
    value = _AUTHORIZATION_HEADER.sub(
        lambda match: f"{match.group(1)}={REDACTED}", value
    )
    value = _URL_QUERY_SECRET.sub(rf"\1{REDACTED}", value)
    value = _URI_CREDENTIAL.sub(r"\1***REDACTED***\3", value)
    value = _BEARER.sub("Bearer ***REDACTED***", value)
    return _INLINE_SECRET.sub(lambda match: f"{match.group(1)}={REDACTED}", value)


def sanitize(value: Any, key: str | None = None) -> Any:
    if key and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(item_key): sanitize(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def sanitize_alert(alert: NormalizedAlert) -> NormalizedAlert:
    database = None
    if alert.database:
        database = DatabaseTarget.model_validate(sanitize(alert.database.model_dump()))
    return alert.model_copy(
        update={
            "title": sanitize_text(alert.title),
            "reason": sanitize_text(alert.reason),
            "description": sanitize_text(alert.description),
            "database": database,
            "features": sanitize(alert.features),
            "labels": sanitize(alert.labels),
            "attributes": sanitize(alert.attributes),
            "raw_payload": sanitize(alert.raw_payload),
        }
    )
