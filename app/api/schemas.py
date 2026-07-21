from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.application.admin import runtime_configuration_issues
from app.config import Settings
from app.domain.models import (
    AlertStatus,
    FeedbackVerdict,
    RunbookDocument,
    RunbookMatchVerdict,
)


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
    runbook_match_verdict: RunbookMatchVerdict = RunbookMatchVerdict.UNKNOWN
    correct_runbook_id: str | None = Field(default=None, min_length=1, max_length=128)
    correct_runbook_section: str | None = Field(
        default=None, min_length=1, max_length=200
    )
    missed_runbook_ids: list[str] = Field(default_factory=list, max_length=20)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    wrong_agent_claims: list[str] = Field(default_factory=list, max_length=20)
    accepted_step_orders: list[int] = Field(default_factory=list, max_length=50)


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
    shadow_enabled: bool | None = None
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
    shadow_enabled: bool
    production_gate_approved: bool
    runbook_limit: int
    wecom_webhook_url_configured: bool
    flashduty_enabled: bool
    flashduty_base_url: str
    flashduty_app_key_configured: bool
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
            shadow_enabled=settings.shadow_enabled,
            production_gate_approved=settings.production_gate_approved,
            runbook_limit=settings.runbook_limit,
            wecom_webhook_url_configured=bool(settings.wecom_webhook_url),
            flashduty_enabled=settings.flashduty_enabled,
            flashduty_base_url=settings.flashduty_base_url,
            flashduty_app_key_configured=bool(settings.flashduty_app_key),
            revision=revision,
            changed_fields=changed_fields or [],
        )
