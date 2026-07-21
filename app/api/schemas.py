from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.application.admin import runtime_configuration_issues
from app.config import Settings
from app.domain.models import AlertStatus, FeedbackVerdict, RunbookDocument, Severity


class AlertAccepted(BaseModel):
    alert_id: UUID
    event_id: str
    status: AlertStatus
    detail_url: str
    deduplicated: bool


class FeedbackRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=255)
    verdict: FeedbackVerdict
    # Kept as an optional compatibility field; the authenticated admin identity is
    # authoritative and the server never trusts this value.
    reviewer: str | None = Field(default=None, min_length=1, max_length=255)
    final_root_cause: str | None = None
    actual_resolution: str | None = None
    recovered: bool | None = None


class RunbookWriteBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    section: str = Field(default="main", min_length=1, max_length=200)
    reasons: list[str] = Field(default_factory=list, max_length=200)
    keywords: list[str] = Field(default_factory=list, max_length=200)
    severities: list[str] = Field(default_factory=list, max_length=10)
    labels: dict[str, str] = Field(default_factory=dict)
    content: str = Field(min_length=1, max_length=1_000_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severities")
    @classmethod
    def normalize_severities(cls, value: list[str]) -> list[str]:
        valid = {item.value for item in Severity}
        normalized = [item.strip().upper() for item in value]
        if any(item not in valid for item in normalized):
            raise ValueError(f"severities must be one of: {', '.join(sorted(valid))}")
        return normalized

    @model_validator(mode="after")
    def validate_custom_metadata(self) -> RunbookWriteBase:
        reserved = {
            "id",
            "title",
            "section",
            "reasons",
            "keywords",
            "severities",
            "labels",
            "version",
            "updated_at",
        }
        overlap = reserved.intersection(self.metadata)
        if overlap:
            raise ValueError(f"metadata contains reserved key: {sorted(overlap)[0]}")
        source_url = self.metadata.get("source_url")
        if not isinstance(source_url, str) or not source_url.strip():
            raise ValueError("metadata.source_url is required")
        parsed = urlsplit(source_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("metadata.source_url must be an absolute HTTP(S) URL")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("metadata.source_url contains an invalid port") from exc
        if port == 0:
            raise ValueError("metadata.source_url contains an invalid port")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("metadata.source_url must not contain credentials")
        selector = self.metadata.get("content_selector")
        if selector is not None and (
            not isinstance(selector, str) or not selector.strip()
        ):
            raise ValueError("metadata.content_selector must be a non-empty string")
        return self


class RunbookCreate(RunbookWriteBase):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

    def to_document(self) -> RunbookDocument:
        return RunbookDocument.model_validate(self.model_dump())


class RunbookUpdate(RunbookWriteBase):
    expected_version: int | None = Field(default=None, ge=1)

    def to_document(self, runbook_id: str) -> RunbookDocument:
        return RunbookDocument(
            id=runbook_id, **self.model_dump(exclude={"expected_version"})
        )


class RunbookListResponse(BaseModel):
    items: list[RunbookDocument]
    total: int = Field(ge=0)


class RuntimeSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: str = Field(pattern=r"^[0-9a-f]{16}$")
    ai_provider: Literal["openai_compatible", "fake"] | None = None
    ai_base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    ai_api_key: str | None = Field(default=None, max_length=8192, repr=False)
    ai_model: str | None = Field(default=None, max_length=300)
    ai_timeout_seconds: float | None = Field(default=None, gt=0, le=600)
    ai_max_retries: int | None = Field(default=None, ge=0, le=20)
    ai_json_mode: bool | None = None
    react_enabled: bool | None = None
    react_max_dynamic_turns: int | None = Field(default=None, ge=0, le=10)
    validation_enabled: bool | None = None
    runbook_limit: int | None = Field(default=None, ge=1, le=20)
    wecom_webhook_url: str | None = Field(default=None, max_length=2048, repr=False)

    def updates(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json", exclude_unset=True, exclude={"expected_revision"}
        )


class RuntimeSettingsResponse(BaseModel):
    app_env: str
    fake_provider_allowed: bool
    ready: bool
    issues: list[str]
    ai_provider: str
    ai_base_url: str
    ai_api_key_configured: bool
    ai_model: str
    ai_timeout_seconds: float
    ai_max_retries: int
    ai_json_mode: bool
    react_enabled: bool
    react_max_dynamic_turns: int
    validation_enabled: bool
    runbook_limit: int
    wecom_webhook_url_configured: bool
    revision: str
    apply_status: Literal["applied"] = "applied"
    worker_refresh_mode: Literal["before_each_job"] = "before_each_job"
    changed_fields: list[str] = Field(default_factory=list)

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        revision: str,
        changed_fields: list[str] | None = None,
    ) -> RuntimeSettingsResponse:
        issues = runtime_configuration_issues(settings)
        return cls(
            app_env=settings.app_env,
            fake_provider_allowed=settings.app_env.lower() not in {"production", "prod"},
            ready=not issues,
            issues=issues,
            ai_provider=settings.ai_provider,
            ai_base_url=settings.ai_base_url,
            ai_api_key_configured=bool(settings.ai_api_key),
            ai_model=settings.ai_model,
            ai_timeout_seconds=settings.ai_timeout_seconds,
            ai_max_retries=settings.ai_max_retries,
            ai_json_mode=settings.ai_json_mode,
            react_enabled=settings.react_enabled,
            react_max_dynamic_turns=settings.react_max_dynamic_turns,
            validation_enabled=settings.validation_enabled,
            runbook_limit=settings.runbook_limit,
            wecom_webhook_url_configured=bool(settings.wecom_webhook_url),
            revision=revision,
            changed_fields=changed_fields or [],
        )
