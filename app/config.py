from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs, urlsplit

from pydantic import AliasChoices, Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

DEFAULT_ENVIRONMENT_ALIASES = {
    "production": ["prod", "prd", "production", "生产", "生产环境"],
    "staging": ["staging", "stage", "pre", "预发", "预发布"],
    "test": ["test", "t1", "qa", "测试", "测试环境"],
    "development": ["dev", "development", "开发", "开发环境"],
}

# Only these settings may be changed through the administrative API. Bootstrap
# controls such as the database URL, scheduler backend and admin credential
# intentionally remain environment/file-deployment concerns.
RUNTIME_SETTINGS_KEYS = frozenset(
    {
        "ai_provider",
        "ai_base_url",
        "ai_api_key",
        "ai_model",
        "ai_timeout_seconds",
        "ai_max_retries",
        "ai_json_mode",
        "ai_fallback_enabled",
        "runbook_limit",
        "wecom_webhook_url",
        "wecom_page_base_url",
        "wecom_feedback_form_url",
        "wecom_enabled",
        "react_enabled",
        "react_max_dynamic_turns",
        "validation_enabled",
        "shadow_enabled",
        "knowledge_sources",
        "scheduler_workers",
        "flashduty_polling_enabled",
        "flashduty_poll_interval_seconds",
        "flashduty_poll_lookback_seconds",
        "archery_mcp_max_agent_steps",
        "external_knowledge_api_key",
        "external_knowledge_api_key_base_url",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = "sqlite+aiosqlite:///./data/alerts.db"
    admin_api_token: str = ""
    runtime_settings_path: Path = Path("./data/runtime-settings.json")
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    ai_provider: str = "openai_compatible"
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = ""
    # Reasoning models may consume several thousand completion tokens before
    # emitting final content. Set an explicit ceiling so provider defaults such
    # as 4096 do not end the response during the reasoning phase.
    ai_max_tokens: int = Field(default=16_384, ge=1024, le=131_072)
    ai_timeout_seconds: float = Field(default=300, gt=0)
    ai_max_retries: int = Field(default=2, ge=0)
    ai_json_mode: bool = True
    # Keep the investigation auditable when an OpenAI-compatible gateway is
    # temporarily unavailable or returns an invalid structure.  The fallback is
    # deliberately conservative and always forces REVIEW_REQUIRED.
    ai_fallback_enabled: bool = True

    runbook_pdf_dir: Path = Path("./runbooks/pdfs")
    runbook_limit: int = Field(default=5, ge=1, le=20)
    runbook_pdf_max_file_bytes: int = Field(
        default=20_000_000, ge=100_000, le=200_000_000
    )
    runbook_pdf_max_text_chars: int = Field(
        default=200_000, ge=10_000, le=1_000_000
    )
    runbook_match_min_score: float = Field(default=12, ge=0, le=200)
    runbook_match_min_confidence: float = Field(default=0.35, ge=0, le=1)
    environment_aliases: dict[str, list[str]] = Field(
        default_factory=lambda: DEFAULT_ENVIRONMENT_ALIASES.copy()
    )
    wecom_webhook_url: str = Field(default="", repr=False)
    # Public/intranet frontend origin used by WeCom's in-app browser. Root-cause
    # and recovery actions open dedicated lightweight pages under this origin.
    wecom_page_base_url: str = ""
    # Optional external questionnaire. When empty, the card opens the built-in
    # alert feedback form; correlation parameters are appended when configured.
    wecom_feedback_form_url: str = ""
    # Master switch for WeCom group robot notifications. When false, no messages
    # are sent even if a webhook URL is configured; when true, a valid URL is
    # required before notifications can be delivered.
    wecom_enabled: bool = False

    # FlashDuty credentials and data-source bindings are deployment settings.
    # They intentionally remain outside RUNTIME_SETTINGS_KEYS so an admin API
    # caller cannot replace the APP Key or redirect diagnostic traffic.
    flashduty_enabled: bool = False
    flashduty_base_url: str = "https://api.flashcat.cloud"
    flashduty_app_key: str = Field(default="", repr=False)
    flashduty_timeout_seconds: float = Field(default=40, ge=35, le=120)
    flashduty_max_retries: int = Field(default=2, ge=0, le=5)
    flashduty_context_item_limit: int = Field(default=20, ge=1, le=100)
    flashduty_polling_enabled: bool = False
    flashduty_poll_interval_seconds: int = Field(default=300, ge=300, le=86400)
    flashduty_poll_lookback_seconds: int = Field(default=900, ge=300, le=2678400)
    flashduty_poll_channel_ids: Annotated[list[int], NoDecode] = Field(
        default_factory=list
    )
    flashduty_poll_integration_ids: Annotated[list[int], NoDecode] = Field(
        default_factory=list
    )
    # These capability gates stay off until a read-only deployment audit shows
    # that the scoped collaboration spaces have corresponding upstream data.
    flashduty_monitors_enabled: bool = False
    flashduty_changes_enabled: bool = False
    flashduty_metrics_ds_name: str = ""
    flashduty_logs_ds_name: str = ""
    flashduty_logs_ds_type: str = "loki"

    # Archery MCP is a deployment-only live evidence source. Its endpoint,
    # X-Archery-Token, and query window stay outside RUNTIME_SETTINGS_KEYS so an
    # admin caller cannot redirect traffic. Each query target comes from its alert.
    mcp_settings_path: Path = Path("./config/mcp/settings.json")
    archery_mcp_url: str = ""
    archery_mcp_token: str = Field(
        default="",
        repr=False,
        validation_alias=AliasChoices(
            "archery_mcp_token",
            "ARCHERY_MCP_HTTP_API_KEY",
            "ARCHERY_TOKEN",
        ),
    )
    # Retained only so older deployment files remain loadable. Query targets are
    # resolved from each alert through MCP discovery and these values are ignored.
    archery_mcp_instance_ref: str = ""
    archery_mcp_db_name: str = ""
    archery_slow_log_window_seconds: int = Field(default=300, ge=60, le=86_400)
    archery_mcp_max_agent_steps: int = Field(default=10, ge=1, le=100)
    archery_mcp_timeout_seconds: float = Field(default=60, gt=0, le=120)

    # External knowledge deployment coordinates are intentionally not runtime
    # editable. Production content is approved before it enters the index, so it
    # is a peer of the approved local PDFs rather than a lower-priority source.
    external_knowledge_base_url: str = "http://knowledge:8000"
    external_knowledge_api_key: str = Field(default="", repr=False)
    external_knowledge_api_key_base_url: str = Field(default="", repr=False)
    external_knowledge_timeout_seconds: float = Field(default=30, gt=0)
    external_knowledge_max_retries: int = Field(default=2, ge=0, le=5)
    external_knowledge_limit: int = Field(default=5, ge=1, le=20)
    external_knowledge_min_relevance: float = Field(default=0.60, ge=0, le=1)

    # Selectable knowledge sources for alert matching. At least one source
    # should be enabled; historical cases (DB) are always used and not
    # controlled by this setting.  Values: "local_pdf", "external_knowledge".
    knowledge_sources: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["local_pdf"]
    )

    kafka_enabled: bool = False
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_alert_topic: str = "database-alerts"
    kafka_dlq_topic: str = "database-alerts.dlq"
    kafka_consumer_group: str = "database-alert-agent"
    kafka_max_retries: int = Field(default=3, ge=1, le=20)

    http_scheduler: str = "in_memory"
    # Per-process alert-analysis concurrency. Runtime edits are applied by both
    # the in-memory scheduler and the Kafka consumer before future work starts.
    scheduler_workers: int = Field(default=1, ge=1, le=16)
    investigation_lease_seconds: int = Field(default=600, ge=30, le=3600)
    tool_max_result_chars: int = Field(default=12000, ge=1000, le=100000)
    react_enabled: bool = False
    react_max_dynamic_turns: int = Field(default=2, ge=0, le=10)
    validation_enabled: bool = True
    shadow_enabled: bool = False
    production_gate_approved: bool = False

    @field_validator(
        "ai_provider",
        "http_scheduler",
        "flashduty_logs_ds_type",
    )
    @classmethod
    def normalize_mode(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator(
        "archery_mcp_instance_ref",
        "archery_mcp_db_name",
    )
    @classmethod
    def normalize_archery_scope(cls, value: str) -> str:
        value = value.strip()
        if len(value) > 255 or any(ord(character) < 32 for character in value):
            raise ValueError("Archery scope values must be printable and at most 255 chars")
        return value

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def normalize_cors_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                return json.loads(stripped)
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator(
        "flashduty_poll_channel_ids",
        "flashduty_poll_integration_ids",
        mode="before",
    )
    @classmethod
    def normalize_integer_lists(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            raw = json.loads(stripped) if stripped.startswith("[") else stripped.split(",")
            return [int(item) for item in raw if str(item).strip()]
        return value

    @field_validator("knowledge_sources", mode="before")
    @classmethod
    def normalize_knowledge_sources(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                raw = json.loads(stripped)
                if not isinstance(raw, list):
                    return raw
                return list(
                    dict.fromkeys(
                        str(item).strip() for item in raw if str(item).strip()
                    )
                )
            return list(
                dict.fromkeys(
                    item.strip() for item in stripped.split(",") if item.strip()
                )
            )
        if isinstance(value, (list, tuple)):
            return list(
                dict.fromkeys(
                    str(item).strip() for item in value if str(item).strip()
                )
            )
        return value

    @model_validator(mode="after")
    def validate_admin_editable_urls(self) -> Settings:
        for field_name, required in (
            ("ai_base_url", True),
            ("wecom_webhook_url", False),
            ("wecom_page_base_url", False),
            ("wecom_feedback_form_url", False),
            ("flashduty_base_url", True),
            ("external_knowledge_base_url", False),
            ("archery_mcp_url", False),
        ):
            value = getattr(self, field_name).strip()
            if not value and not required:
                continue
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"{field_name} must be an absolute HTTP(S) URL")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError(f"{field_name} must not contain embedded credentials")
            if field_name == "wecom_webhook_url":
                query = parse_qs(parsed.query, keep_blank_values=True)
                valid_key = len(query.get("key", [])) == 1 and bool(query["key"][0].strip())
                if (
                    parsed.scheme != "https"
                    or parsed.hostname != "qyapi.weixin.qq.com"
                    or parsed.port not in {None, 443}
                    or parsed.path != "/cgi-bin/webhook/send"
                    or parsed.fragment
                    or set(query) != {"key"}
                    or not valid_key
                ):
                    raise ValueError(
                        "wecom_webhook_url must be an official HTTPS WeCom group robot URL"
                    )
            if field_name == "wecom_page_base_url" and (
                parsed.query or parsed.fragment
            ):
                raise ValueError(
                    "wecom_page_base_url must not contain a query or fragment"
                )
            if field_name == "flashduty_base_url" and (
                parsed.scheme != "https"
                or parsed.hostname != "api.flashcat.cloud"
                or parsed.port not in {None, 443}
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "flashduty_base_url must be the official HTTPS FlashDuty API endpoint"
                )
            if field_name == "archery_mcp_url" and (
                parsed.query or parsed.fragment or parsed.path in {"", "/"}
            ):
                raise ValueError(
                    "archery_mcp_url must be the full MCP endpoint without query or fragment"
                )
            if (
                field_name != "external_knowledge_base_url"
                and self.app_env.lower() in {"production", "prod"}
                and parsed.scheme != "https"
            ):
                raise ValueError(f"{field_name} must use HTTPS in production")
        if (
            self.app_env.lower() in {"production", "prod"}
            and self.ai_provider == "fake"
        ):
            raise ValueError("AI_PROVIDER=fake is not allowed in production")
        if self.flashduty_logs_ds_type not in {"loki", "victorialogs"}:
            raise ValueError("FLASHDUTY_LOGS_DS_TYPE must be loki or victorialogs")
        if (
            self.flashduty_polling_enabled
            and self.flashduty_poll_lookback_seconds
            < self.flashduty_poll_interval_seconds
        ):
            raise ValueError(
                "FLASHDUTY_POLL_LOOKBACK_SECONDS must be greater than or equal to "
                "FLASHDUTY_POLL_INTERVAL_SECONDS when polling is enabled"
            )
        valid_sources = {"local_pdf", "external_knowledge"}
        invalid_sources = set(self.knowledge_sources) - valid_sources
        if invalid_sources:
            raise ValueError(
                f"KNOWLEDGE_SOURCES contains invalid values: {sorted(invalid_sources)}. "
                f"Allowed: {sorted(valid_sources)}"
            )
        if not self.knowledge_sources:
            raise ValueError("KNOWLEDGE_SOURCES must contain at least one source")
        return self

    @computed_field
    @property
    def external_knowledge_enabled(self) -> bool:
        """Expose the selected source as a compatibility/read-model flag."""

        return "external_knowledge" in self.knowledge_sources

    @computed_field
    @property
    def archery_mcp_enabled(self) -> bool:
        """Enable Archery evidence when the MCP connection itself is configured."""

        return all(
            (
                self.archery_mcp_url.strip(),
                self.archery_mcp_token.strip(),
            )
        )

    def external_knowledge_api_key_is_current(self) -> bool:
        """Return whether the secret is bound to the active deployment URL."""

        return bool(self.external_knowledge_api_key) and (
            not self.external_knowledge_api_key_base_url
            or self.external_knowledge_api_key_base_url
            == self.external_knowledge_base_url
        )

    def effective_external_knowledge_api_key(self) -> str:
        """Do not send a secret after its bound external URL changes."""

        if not self.external_knowledge_api_key_is_current():
            return ""
        return self.external_knowledge_api_key

    def readiness_issues(self) -> list[str]:
        issues: list[str] = []
        if self.ai_provider == "openai_compatible":
            if not self.ai_api_key:
                issues.append("AI_API_KEY is required for openai_compatible provider")
            if not self.ai_model:
                issues.append("AI_MODEL is required for openai_compatible provider")
        elif self.ai_provider != "fake":
            issues.append(f"Unsupported AI_PROVIDER: {self.ai_provider}")

        if self.wecom_enabled and not self.wecom_webhook_url:
            issues.append(
                "WECOM_WEBHOOK_URL is required when WeCom notifications are enabled"
            )
        if self.wecom_enabled and not self.wecom_page_base_url:
            issues.append(
                "WECOM_PAGE_BASE_URL is required when WeCom notifications are enabled"
            )
        if self.app_env.lower() in {"production", "prod"} and not self.admin_api_token:
            issues.append("ADMIN_API_TOKEN is required in production")
        if self.flashduty_enabled and not self.flashduty_app_key:
            issues.append("FLASHDUTY_APP_KEY is required when FlashDuty is enabled")
        if (
            self.flashduty_enabled
            and self.flashduty_polling_enabled
            and not self.flashduty_poll_channel_ids
        ):
            issues.append(
                "FLASHDUTY_POLL_CHANNEL_IDS must contain at least one collaboration space ID"
            )
        if (
            self.flashduty_enabled
            and self.flashduty_changes_enabled
            and not self.flashduty_poll_channel_ids
        ):
            issues.append(
                "FLASHDUTY_POLL_CHANNEL_IDS must contain at least one collaboration "
                "space ID when FlashDuty change queries are enabled"
            )
        if self.archery_mcp_url.strip() or self.archery_mcp_token.strip():
            required_archery_settings = {
                "ARCHERY_MCP_URL": self.archery_mcp_url,
                "ARCHERY_MCP_TOKEN": self.archery_mcp_token,
            }
            missing_archery_settings = [
                name
                for name, value in required_archery_settings.items()
                if not value.strip()
            ]
            if missing_archery_settings:
                issues.append(
                    "Archery MCP configuration is incomplete; missing: "
                    + ", ".join(missing_archery_settings)
                )
            elif not self.mcp_settings_path.is_file():
                issues.append(
                    f"MCP settings file does not exist: {self.mcp_settings_path}"
                )
            elif self.ai_provider != "openai_compatible":
                issues.append(
                    "Archery MCP requires an openai_compatible model with tool calling"
                )
        if self.http_scheduler not in {"in_memory", "kafka", "manual"}:
            issues.append(f"Unsupported HTTP_SCHEDULER: {self.http_scheduler}")
        if self.http_scheduler == "kafka" and not self.kafka_enabled:
            issues.append("KAFKA_ENABLED must be true when HTTP_SCHEDULER=kafka")
        if (
            self.app_env.lower() in {"production", "prod"}
            and not self.shadow_enabled
            and not self.production_gate_approved
        ):
            issues.append(
                "PRODUCTION_GATE_APPROVED must be true before disabling shadow mode "
                "in production"
            )
        if "local_pdf" in self.knowledge_sources:
            if not self.runbook_pdf_dir.exists():
                issues.append(
                    f"PDF runbook directory does not exist: {self.runbook_pdf_dir}"
                )
            elif not self.runbook_pdf_dir.is_dir():
                issues.append(
                    f"PDF runbook path is not a directory: {self.runbook_pdf_dir}"
                )
            elif not any(self.runbook_pdf_dir.glob("*.pdf")):
                issues.append(f"No PDF runbooks found in: {self.runbook_pdf_dir}")
        if (
            "external_knowledge" in self.knowledge_sources
            and not self.external_knowledge_base_url.strip()
        ):
            issues.append(
                "EXTERNAL_KNOWLEDGE_BASE_URL is required when external knowledge "
                "is selected"
            )
        if (
            self.external_knowledge_api_key
            and not self.external_knowledge_api_key_is_current()
        ):
            issues.append(
                "EXTERNAL_KNOWLEDGE_API_KEY must be re-entered after "
                "EXTERNAL_KNOWLEDGE_BASE_URL changes"
            )
        return issues


def load_runtime_overrides(path: Path) -> dict[str, Any]:
    """Load the persisted administrative overrides without accepting bootstrap keys."""

    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid runtime settings file: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Runtime settings file must contain an object: {path}")
    return {key: value for key, value in payload.items() if key in RUNTIME_SETTINGS_KEYS}


@lru_cache
def get_settings() -> Settings:
    # Deployment configuration (.env) is the bootstrap baseline. Runtime
    # overrides persisted in runtime-settings.json take precedence over the
    # deployment values for every key in RUNTIME_SETTINGS_KEYS, so changes made
    # through the admin settings page remain authoritative until they are
    # explicitly cleared from the runtime file.
    bootstrap = Settings()
    overrides = load_runtime_overrides(bootstrap.runtime_settings_path)
    if not overrides:
        return bootstrap
    return Settings.model_validate({**bootstrap.model_dump(), **overrides})
