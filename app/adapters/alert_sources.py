from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.domain.errors import InvalidAlertPayloadError, UnknownAlertSourceError
from app.domain.models import DatabaseTarget, NormalizedAlert, Severity
from app.domain.ports import AlertSourceAdapter


class CanonicalAlertPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    external_id: str | None = None
    severity: str
    title: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    description: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    database: DatabaseTarget | None = None
    features: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def nonempty_severity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("severity cannot be empty")
        return value


def stable_alert_fingerprint(source: str, payload: CanonicalAlertPayload) -> str:
    identity = {
        "source": source,
        "severity": payload.severity.upper(),
        "title": payload.title,
        "reason": payload.reason,
        "occurred_at": payload.occurred_at.isoformat(),
        "database": payload.database.model_dump(mode="json") if payload.database else None,
    }
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()
    return f"generated-{hashlib.sha256(encoded).hexdigest()[:32]}"


class CanonicalAlertSourceAdapter:
    source = "canonical"

    def __init__(self, severity_mapping: dict[str, str]) -> None:
        self._mapping = {key.upper(): value.upper() for key, value in severity_mapping.items()}

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert:
        try:
            parsed = CanonicalAlertPayload.model_validate(payload)
        except ValidationError as exc:
            raise InvalidAlertPayloadError(str(exc)) from exc

        raw_severity = parsed.severity.upper()
        mapped = self._mapping.get(raw_severity, raw_severity)
        try:
            severity = Severity(mapped)
        except ValueError:
            severity = Severity.UNKNOWN

        known_fields = set(CanonicalAlertPayload.model_fields)
        extension_fields = {key: value for key, value in payload.items() if key not in known_fields}
        attributes = {**parsed.attributes, **extension_fields}
        external_id = parsed.external_id or stable_alert_fingerprint(self.source, parsed)
        return NormalizedAlert(
            external_id=external_id,
            source=self.source,
            raw_severity=parsed.severity,
            severity=severity,
            title=parsed.title,
            reason=parsed.reason,
            description=parsed.description,
            occurred_at=parsed.occurred_at,
            database=parsed.database,
            features=parsed.features,
            labels=parsed.labels,
            attributes=attributes,
            raw_payload=payload,
        )


class AlertSourceRegistry:
    def __init__(self, adapters: list[AlertSourceAdapter] | None = None) -> None:
        self._adapters: dict[str, AlertSourceAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: AlertSourceAdapter) -> None:
        self._adapters[adapter.source.lower()] = adapter

    def normalize(self, source: str, payload: dict[str, Any]) -> NormalizedAlert:
        adapter = self._adapters.get(source.lower())
        if not adapter:
            raise UnknownAlertSourceError(source)
        normalized = adapter.normalize(payload)
        if normalized.source.lower() != source.lower():
            normalized = normalized.model_copy(update={"source": source.lower()})
        return normalized


class ExamplePlatformAdapter:
    """Copy this class when the real alert platform payload is known."""

    source = "replace-with-platform-name"

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert:
        raise NotImplementedError("Map the real platform payload to NormalizedAlert here")
