from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.models import Severity

DEFAULT_SEVERITY_MAPPING = {
    "P0": "CRITICAL",
    "P1": "HIGH",
    "P2": "MEDIUM",
    "P3": "LOW",
    "FATAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = "sqlite+aiosqlite:///./data/alerts.db"

    ai_provider: str = "openai_compatible"
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = ""
    ai_timeout_seconds: float = Field(default=30, gt=0)
    ai_max_retries: int = Field(default=2, ge=0)
    ai_json_mode: bool = True

    runbook_dir: Path = Path("./runbooks")
    runbook_limit: int = Field(default=5, ge=1, le=20)
    severity_mapping: dict[str, str] = Field(
        default_factory=lambda: DEFAULT_SEVERITY_MAPPING.copy()
    )
    escalation_severities: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])

    notifier_mode: str = "log"
    management_webhook_url: str = ""
    management_webhook_bearer_token: str = ""
    notification_max_attempts: int = Field(default=3, ge=1, le=10)
    notification_retry_backoff_seconds: float = Field(default=0.5, ge=0, le=30)

    kafka_enabled: bool = False
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_alert_topic: str = "database-alerts"
    kafka_dlq_topic: str = "database-alerts.dlq"
    kafka_consumer_group: str = "database-alert-agent"
    kafka_max_retries: int = Field(default=3, ge=1, le=20)

    @field_validator("severity_mapping")
    @classmethod
    def normalize_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        return {str(key).upper(): str(mapped).upper() for key, mapped in value.items()}

    @field_validator("ai_provider", "notifier_mode")
    @classmethod
    def normalize_mode(cls, value: str) -> str:
        return value.strip().lower()

    def readiness_issues(self) -> list[str]:
        issues: list[str] = []
        if self.ai_provider == "openai_compatible":
            if not self.ai_api_key:
                issues.append("AI_API_KEY is required for openai_compatible provider")
            if not self.ai_model:
                issues.append("AI_MODEL is required for openai_compatible provider")
        elif self.ai_provider != "fake":
            issues.append(f"Unsupported AI_PROVIDER: {self.ai_provider}")

        if self.notifier_mode == "webhook" and not self.management_webhook_url:
            issues.append("MANAGEMENT_WEBHOOK_URL is required in webhook mode")
        elif self.notifier_mode not in {"log", "webhook"}:
            issues.append(f"Unsupported NOTIFIER_MODE: {self.notifier_mode}")

        if self.app_env.lower() in {"production", "prod"} and self.notifier_mode != "webhook":
            issues.append("Production requires NOTIFIER_MODE=webhook")
        if not self.runbook_dir.exists():
            issues.append(f"Runbook directory does not exist: {self.runbook_dir}")
        return issues


@lru_cache
def get_settings() -> Settings:
    return Settings()
