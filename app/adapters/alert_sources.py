from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.domain.errors import InvalidAlertPayloadError, UnknownAlertSourceError
from app.domain.models import (
    DatabaseTarget,
    NormalizedAlert,
    Severity,
)
from app.domain.ports import AlertSourceAdapter


class CanonicalAlertPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    external_id: str | None = None
    environment: str | None = None
    service_name: str | None = None
    alert_type: str | None = None
    metric_name: str | None = None
    error_pattern: str | None = None
    error_summary: str | None = None
    severity: str
    alert_name: str | None = None
    resource_type: str | None = None
    cluster: str | None = None
    alarm_type: str | None = None
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

    @field_validator("title", "reason")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be empty or whitespace")
        return value

def _stable_hash(prefix: str, identity: dict[str, Any]) -> str:
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:32]}"


def stable_event_id(source: str, raw_payload: dict[str, Any]) -> str:
    identity = {"source": source, "payload": raw_payload}
    return _stable_hash("generated", identity)


def normalize_error_pattern(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "<uuid>",
        value,
    )
    value = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", value)
    value = re.sub(r"\d+(?:\.\d+)?", "<n>", value)
    return re.sub(r"\s+", " ", value)[:500]


def incident_fingerprint(
    source: str,
    payload: CanonicalAlertPayload,
    *,
    environment: str,
    service_name: str,
    alert_type: str,
) -> str:
    database_engine = (
        payload.database.engine.lower()
        if payload.database and payload.database.engine
        else None
    )
    pattern = payload.error_pattern or payload.error_summary or payload.description or payload.title
    identity = {
        "version": "v1",
        "source": source.lower(),
        "environment": environment,
        "service_name": service_name.lower(),
        "database_engine": database_engine,
        "alert_type": alert_type.lower(),
        "metric_name": (payload.metric_name or "").lower(),
        "error_pattern": normalize_error_pattern(pattern),
    }
    return _stable_hash("incident-v1", identity)


class EnvironmentResolver:
    def __init__(self, aliases: dict[str, list[str]]) -> None:
        self._aliases: dict[str, str] = {}
        for canonical, values in aliases.items():
            self._aliases[canonical.lower()] = canonical.lower()
            for value in values:
                self._aliases[str(value).strip().lower()] = canonical.lower()

    def resolve(self, value: str | None) -> str:
        if not value:
            return "unknown"
        normalized = value.strip().lower()
        return self._aliases.get(normalized, normalized)


class CanonicalAlertSourceAdapter:
    source = "canonical"

    def __init__(
        self,
        environment_aliases: dict[str, list[str]] | None = None,
    ) -> None:
        self._environment_resolver = EnvironmentResolver(environment_aliases or {})

    def normalize(self, payload: dict[str, Any]) -> NormalizedAlert:
        try:
            parsed = CanonicalAlertPayload.model_validate(payload)
        except ValidationError as exc:
            raise InvalidAlertPayloadError(str(exc)) from exc

        raw_severity = parsed.severity.upper()
        try:
            severity = Severity(raw_severity)
        except ValueError as exc:
            raise InvalidAlertPayloadError(
                "severity must be CRITICAL, WARNING, or INFO"
            ) from exc

        known_fields = set(CanonicalAlertPayload.model_fields)
        extension_fields = {key: value for key, value in payload.items() if key not in known_fields}
        attributes = {**parsed.attributes, **extension_fields}
        environment = self._environment_resolver.resolve(
            parsed.environment or parsed.labels.get("environment") or parsed.labels.get("env")
        )
        service_name = (
            parsed.service_name
            or parsed.labels.get("service")
            or parsed.labels.get("app")
            or (parsed.database.instance if parsed.database else None)
            or "unknown"
        )
        alert_type = parsed.alert_type or parsed.reason
        alert_name = (
            parsed.alert_name
            or parsed.labels.get("alertname")
            or parsed.labels.get("alert_name")
            or alert_type
        )
        resource_type = (
            parsed.resource_type
            or parsed.labels.get("resource_type")
            or parsed.attributes.get("resource_type")
        )
        cluster = (
            parsed.cluster
            or parsed.labels.get("cluster")
            or parsed.attributes.get("cluster")
        )
        alarm_type = (
            parsed.alarm_type
            or parsed.labels.get("alarm_type")
            or parsed.attributes.get("alarm_type")
        )
        external_id = parsed.external_id or stable_event_id(self.source, payload)
        fingerprint = incident_fingerprint(
            self.source,
            parsed,
            environment=environment,
            service_name=service_name,
            alert_type=alert_type,
        )
        return NormalizedAlert(
            external_id=external_id,
            source=self.source,
            raw_severity=parsed.severity,
            severity=severity,
            incident_fingerprint=fingerprint,
            fingerprint_version="v1",
            environment=environment,
            service_name=service_name,
            alert_type=alert_type,
            alert_name=alert_name,
            resource_type=resource_type,
            cluster=cluster,
            alarm_type=alarm_type,
            metric_name=parsed.metric_name,
            error_pattern=(
                parsed.error_pattern
                or normalize_error_pattern(parsed.description or parsed.title)
            ),
            error_summary=parsed.error_summary or parsed.description or parsed.title,
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
