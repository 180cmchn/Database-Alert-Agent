from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs, urlsplit

from pydantic import AliasChoices, Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.domain.models import Severity

DEFAULT_ENVIRONMENT_ALIASES = {
    "production": ["prod", "prd", "production", "生产", "生产环境"],
    "staging": ["staging", "stage", "pre", "预发", "预发布"],
    "test": ["test", "t1", "qa", "测试", "测试环境"],
    "development": ["dev", "development", "开发", "开发环境"],
}

REAL_AI_PROVIDERS = frozenset({"openai_compatible", "openai_responses"})
SUPPORTED_AI_PROVIDERS = REAL_AI_PROVIDERS | {"fake"}

# Reasoning-effort levels accepted by the model backends (OpenAI
# Chat Completions `reasoning_effort` / Responses `reasoning.effort` and
# compatible gateways). An empty string means "do not send the parameter" so
# the provider default applies.
SUPPORTED_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})

_FILTER_SEVERITY_ORDER = tuple(Severity)
_FILTER_SEVERITIES_KEY = "alert_analysis_filter_severities"
_LEGACY_FILTER_MAX_SEVERITY_KEY = "alert_analysis_filter_max_severity"


def _parse_filter_severities(value: Any) -> list[Severity]:
    raw: Any = value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        raw = json.loads(stripped) if stripped.startswith("[") else stripped.split(",")
    if not isinstance(raw, (list, tuple, set, frozenset)):
        raise ValueError("alert analysis filter severities must be a list")

    selected = {
        item if isinstance(item, Severity) else Severity(str(item).strip().upper())
        for item in raw
    }
    return [severity for severity in _FILTER_SEVERITY_ORDER if severity in selected]


def _legacy_filter_severities(value: Any) -> list[Severity]:
    max_severity = (
        value if isinstance(value, Severity) else Severity(str(value).strip().upper())
    )
    start = _FILTER_SEVERITY_ORDER.index(max_severity)
    return list(_FILTER_SEVERITY_ORDER[start:])

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
        "ai_json_mode",
        "ai_fallback_enabled",
        "ai_react_model",
        "ai_react_reasoning_effort",
        "ai_reasoning_effort",
        "ai_mcp_model",
        "ai_mcp_reasoning_effort",
        "stream_main_agent_reasoning",
        "alert_analysis_filter_enabled",
        "alert_analysis_filter_severities",
        "wecom_webhook_url",
        "wecom_page_base_url",
        "wecom_enabled",
        "react_max_rounds",
        "analysis_timeout_seconds",
        "knowledge_sources",
        "scheduler_workers",
        "flashduty_polling_enabled",
        "flashduty_poll_interval_seconds",
        "flashduty_poll_lookback_seconds",
        "external_knowledge_api_key",
        "external_knowledge_api_key_base_url",
    }
)


def _normalize_runtime_overrides(payload: dict[str, Any]) -> dict[str, Any]:
    overrides = {key: value for key, value in payload.items() if key in RUNTIME_SETTINGS_KEYS}
    if _FILTER_SEVERITIES_KEY in overrides:
        overrides[_FILTER_SEVERITIES_KEY] = [
            severity.value
            for severity in _parse_filter_severities(overrides[_FILTER_SEVERITIES_KEY])
        ]
    elif _LEGACY_FILTER_MAX_SEVERITY_KEY in payload:
        overrides[_FILTER_SEVERITIES_KEY] = [
            severity.value
            for severity in _legacy_filter_severities(
                payload[_LEGACY_FILTER_MAX_SEVERITY_KEY]
            )
        ]
    return overrides


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_env: str = "development"
    # Deployment pipelines should replace this with an immutable image or Git revision.
    app_code_version: str = "0.1.0"
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
    # deliberately conservative and always produces an INCONCLUSIVE result.
    ai_fallback_enabled: bool = True
    # Role-specific model overrides. The three model usage points (main-Agent
    # ReAct round decisions, final root-cause analysis, and the MCP tool inner
    # loop) may each use a different model. An empty value falls back to
    # ``ai_model`` so a single-model deployment keeps working unchanged.
    ai_react_model: str = ""
    ai_mcp_model: str = ""
    # Reasoning effort per usage point. Empty means "do not send the parameter"
    # and lets the provider default apply. Configure a low effort for cheap
    # tool-selection decisions and keep a high effort for final analysis.
    ai_react_reasoning_effort: str = ""
    ai_reasoning_effort: str = ""
    ai_mcp_reasoning_effort: str = ""
    # Required deployment baseline loaded from STREAM_MAIN_AGENT_REASONING.
    # An admin runtime override may replace it until runtime overrides are reset.
    stream_main_agent_reasoning: bool = Field(
        validation_alias=AliasChoices(
            "STREAM_MAIN_AGENT_REASONING",
            "stream_main_agent_reasoning",
        )
    )

    @field_validator(
        "ai_react_reasoning_effort",
        "ai_reasoning_effort",
        "ai_mcp_reasoning_effort",
    )
    @classmethod
    def validate_reasoning_effort(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized and normalized not in SUPPORTED_REASONING_EFFORTS:
            allowed = ", ".join(sorted(SUPPORTED_REASONING_EFFORTS))
            raise ValueError(
                f"reasoning effort must be one of: {allowed} (empty disables the "
                "parameter and keeps the provider default)"
            )
        return normalized

    @field_validator("ai_react_model", "ai_mcp_model")
    @classmethod
    def strip_role_model(cls, value: str) -> str:
        return value.strip()

    environment_aliases: dict[str, list[str]] = Field(
        default_factory=lambda: DEFAULT_ENVIRONMENT_ALIASES.copy()
    )
    # When enabled, alerts with one of these normalized severities are persisted
    # without creating an automatic investigation run.
    alert_analysis_filter_enabled: bool = False
    alert_analysis_filter_severities: Annotated[list[Severity], NoDecode] = Field(
        default_factory=lambda: [Severity.INFO]
    )
    legacy_alert_analysis_filter_max_severity: Severity | None = Field(
        default=None,
        validation_alias="alert_analysis_filter_max_severity",
        exclude=True,
        repr=False,
    )
    wecom_webhook_url: str = Field(default="", repr=False)
    # Public/intranet frontend origin used by WeCom's in-app browser. Root-cause
    # and recovery actions open dedicated lightweight pages under this origin.
    wecom_page_base_url: str = ""
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
    flashduty_poll_channel_ids: Annotated[list[int], NoDecode] = Field(default_factory=list)
    flashduty_poll_integration_ids: Annotated[list[int], NoDecode] = Field(default_factory=list)
    # These capability gates stay off until a read-only deployment audit shows
    # that the scoped collaboration spaces have corresponding upstream data.
    flashduty_monitors_enabled: bool = False
    flashduty_changes_enabled: bool = False
    flashduty_metrics_ds_name: str = ""
    flashduty_logs_ds_name: str = ""
    flashduty_logs_ds_type: str = "loki"

    # Archery MCP is a deployment-only live evidence source. Its endpoint,
    # catalog-resolved credentials, and query window stay outside RUNTIME_SETTINGS_KEYS
    # so an admin caller cannot redirect traffic. Each query target comes from its alert.
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
    archery_slow_log_window_seconds: int = Field(default=300, ge=60, le=86_400)
    archery_mcp_timeout_seconds: float = Field(default=60, gt=0, le=120)
    # The Host stops the Archery investigation cleanly before the outer tool
    # deadline so compact history evidence survives an enrichment timeout.
    archery_investigation_budget_seconds: float = Field(default=150, gt=0, le=1200)
    archery_mcp_tool_timeout_seconds: float = Field(default=180, gt=0, le=1200)

    # Prometheus is a deployment-only MCP evidence source. Its endpoint and
    # authentication material must not be changed through the admin API.
    prometheus_mcp_url: str = ""
    prometheus_mcp_api_key: str = Field(default="", repr=False)
    prometheus_mcp_api_key_header: str = ""
    prometheus_mcp_timeout_seconds: float = Field(default=60, gt=0, le=120)
    # Keep the inner Agent's recovery loop independent from one transport call.
    prometheus_investigation_budget_seconds: float = Field(default=180, gt=0, le=1200)
    prometheus_mcp_tool_timeout_seconds: float = Field(default=780, gt=0, le=1200)

    # External knowledge deployment coordinates are intentionally not runtime editable.
    external_knowledge_base_url: str = "http://knowledge:8000"
    external_knowledge_api_key: str = Field(default="", repr=False)
    external_knowledge_api_key_base_url: str = Field(default="", repr=False)
    external_knowledge_timeout_seconds: float = Field(default=30, gt=0)
    external_knowledge_limit: int = Field(default=5, ge=1, le=20)
    external_knowledge_min_relevance: float = Field(default=0.60, ge=0, le=1)

    # Selectable knowledge-source names. Empty is valid: the Agent then uses the
    # alert, live evidence, and general reasoning without advisory knowledge.
    knowledge_sources: Annotated[list[str], NoDecode] = Field(default_factory=list)

    redis_enabled: bool = False
    redis_url: str = "redis://localhost:6379/0"
    redis_username: str = ""
    redis_password: str = Field(default="", repr=False)
    redis_stream_name: str = "{database-alert-agent}:jobs"
    redis_dlq_stream_name: str = "{database-alert-agent}:dlq"
    redis_consumer_group: str = "database-alert-agent"
    redis_max_retries: int = Field(default=3, ge=1, le=20)
    redis_claim_idle_seconds: int = Field(default=660, ge=30, le=86_400)
    redis_dlq_maxlen: int = Field(default=10_000, ge=1, le=1_000_000)

    http_scheduler: str = "in_memory"
    # Per-process alert-analysis concurrency. Runtime edits are applied by both
    # the in-memory scheduler and the Redis consumer before future work starts.
    scheduler_workers: int = Field(default=1, ge=1, le=16)
    investigation_lease_seconds: int = Field(default=600, ge=30, le=3600)
    # Retention runs only at the configured weekly calendar slot; startup never
    # triggers an immediate cleanup.
    alert_retention_enabled: bool = True
    alert_retention_days: int = Field(default=7, ge=7, le=3650)
    react_max_rounds: int = Field(default=8, ge=1, le=100)
    analysis_timeout_seconds: int = Field(default=1800, ge=30, le=86_400)
    # Historical compatibility only. New runs always apply deterministic contract
    # validation and never invoke a second model-based conclusion validator.
    validation_enabled: bool = True

    @field_validator(
        "ai_provider",
        "http_scheduler",
        "flashduty_logs_ds_type",
    )
    @classmethod
    def normalize_mode(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator(
        "redis_url",
        "redis_stream_name",
        "redis_dlq_stream_name",
        "redis_consumer_group",
    )
    @classmethod
    def normalize_required_redis_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Redis connection and stream names must not be empty")
        return normalized

    @field_validator("redis_username")
    @classmethod
    def normalize_redis_username(cls, value: str) -> str:
        return value.strip()

    @field_validator("alert_analysis_filter_severities", mode="before")
    @classmethod
    def normalize_alert_analysis_filter_severities(cls, value: Any) -> list[Severity]:
        return _parse_filter_severities(value)

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
                return list(dict.fromkeys(str(item).strip() for item in raw if str(item).strip()))
            return list(dict.fromkeys(item.strip() for item in stripped.split(",") if item.strip()))
        if isinstance(value, (list, tuple)):
            return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
        return value

    @model_validator(mode="after")
    def validate_admin_editable_urls(self) -> Settings:
        if (
            self.legacy_alert_analysis_filter_max_severity is not None
            and "alert_analysis_filter_severities" not in self.model_fields_set
        ):
            self.alert_analysis_filter_severities = _legacy_filter_severities(
                self.legacy_alert_analysis_filter_max_severity
            )
        if self.alert_analysis_filter_enabled and not self.alert_analysis_filter_severities:
            raise ValueError(
                "ALERT_ANALYSIS_FILTER_SEVERITIES must contain at least one severity "
                "when alert analysis filtering is enabled"
            )
        for field_name, required in (
            ("ai_base_url", True),
            ("wecom_webhook_url", False),
            ("wecom_page_base_url", False),
            ("flashduty_base_url", True),
            ("external_knowledge_base_url", False),
            ("archery_mcp_url", False),
            ("prometheus_mcp_url", False),
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
            if field_name == "wecom_page_base_url" and (parsed.query or parsed.fragment):
                raise ValueError("wecom_page_base_url must not contain a query or fragment")
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
            if field_name == "prometheus_mcp_url" and (
                parsed.query or parsed.fragment or parsed.path in {"", "/"}
            ):
                raise ValueError(
                    "prometheus_mcp_url must be the full MCP endpoint without query or fragment"
                )
            if (
                field_name != "external_knowledge_base_url"
                and self.app_env.lower() in {"production", "prod"}
                and parsed.scheme != "https"
            ):
                raise ValueError(f"{field_name} must use HTTPS in production")
        redis_url = urlsplit(self.redis_url)
        if redis_url.scheme not in {"redis", "rediss"} or not redis_url.netloc:
            raise ValueError("redis_url must be an absolute Redis URL")
        if redis_url.username is not None or redis_url.password is not None:
            raise ValueError("redis_url must not contain embedded credentials")
        if redis_url.query or redis_url.fragment:
            raise ValueError("redis_url must not contain a query or fragment")
        if self.redis_stream_name == self.redis_dlq_stream_name:
            raise ValueError("REDIS_STREAM_NAME and REDIS_DLQ_STREAM_NAME must differ")
        if self.redis_enabled and self.redis_claim_idle_seconds < self.investigation_lease_seconds:
            raise ValueError(
                "REDIS_CLAIM_IDLE_SECONDS must be greater than or equal to "
                "INVESTIGATION_LEASE_SECONDS"
            )
        if self.app_env.lower() in {"production", "prod"} and self.ai_provider == "fake":
            raise ValueError("AI_PROVIDER=fake is not allowed in production")
        if self.flashduty_logs_ds_type not in {"loki", "victorialogs"}:
            raise ValueError("FLASHDUTY_LOGS_DS_TYPE must be loki or victorialogs")
        if (
            self.flashduty_polling_enabled
            and self.flashduty_poll_lookback_seconds < self.flashduty_poll_interval_seconds
        ):
            raise ValueError(
                "FLASHDUTY_POLL_LOOKBACK_SECONDS must be greater than or equal to "
                "FLASHDUTY_POLL_INTERVAL_SECONDS when polling is enabled"
            )
        if self.archery_mcp_tool_timeout_seconds <= self.archery_investigation_budget_seconds:
            raise ValueError(
                "ARCHERY_MCP_TOOL_TIMEOUT_SECONDS must exceed ARCHERY_INVESTIGATION_BUDGET_SECONDS"
            )
        if (
            "prometheus_investigation_budget_seconds" not in self.model_fields_set
            and self.prometheus_mcp_tool_timeout_seconds
            <= self.prometheus_investigation_budget_seconds
        ):
            self.prometheus_investigation_budget_seconds = (
                self.prometheus_mcp_tool_timeout_seconds * 0.9
            )
        if self.prometheus_mcp_tool_timeout_seconds <= (
            self.prometheus_investigation_budget_seconds
        ):
            raise ValueError(
                "PROMETHEUS_MCP_TOOL_TIMEOUT_SECONDS must exceed "
                "PROMETHEUS_INVESTIGATION_BUDGET_SECONDS"
            )
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

    @computed_field
    @property
    def prometheus_mcp_enabled(self) -> bool:
        """Enable Prometheus evidence when its MCP endpoint is configured."""

        return bool(self.prometheus_mcp_url.strip())

    def external_knowledge_api_key_is_current(self) -> bool:
        """Return whether the secret is bound to the active deployment URL."""

        return bool(self.external_knowledge_api_key) and (
            not self.external_knowledge_api_key_base_url
            or self.external_knowledge_api_key_base_url == self.external_knowledge_base_url
        )

    def effective_external_knowledge_api_key(self) -> str:
        """Do not send a secret after its bound external URL changes."""

        if not self.external_knowledge_api_key_is_current():
            return ""
        return self.external_knowledge_api_key

    def readiness_issues(self) -> list[str]:
        issues: list[str] = []
        if self.ai_provider in REAL_AI_PROVIDERS:
            if not self.ai_api_key:
                issues.append(f"AI_API_KEY is required for {self.ai_provider} provider")
            if not self.ai_model:
                issues.append(f"AI_MODEL is required for {self.ai_provider} provider")
        elif self.ai_provider not in SUPPORTED_AI_PROVIDERS:
            issues.append(f"Unsupported AI_PROVIDER: {self.ai_provider}")

        if self.wecom_enabled and not self.wecom_webhook_url:
            issues.append("WECOM_WEBHOOK_URL is required when WeCom notifications are enabled")
        if self.wecom_enabled and not self.wecom_page_base_url:
            issues.append("WECOM_PAGE_BASE_URL is required when WeCom notifications are enabled")
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
                name for name, value in required_archery_settings.items() if not value.strip()
            ]
            if missing_archery_settings:
                issues.append(
                    "Archery MCP configuration is incomplete; missing: "
                    + ", ".join(missing_archery_settings)
                )
            elif not self.mcp_settings_path.is_file():
                issues.append(f"MCP settings file does not exist: {self.mcp_settings_path}")
            elif self.ai_provider not in REAL_AI_PROVIDERS:
                issues.append("Archery MCP requires a real AI provider model with tool calling")
        prometheus_url_configured = bool(self.prometheus_mcp_url.strip())
        prometheus_header_configured = bool(self.prometheus_mcp_api_key_header.strip())
        prometheus_key_configured = bool(self.prometheus_mcp_api_key.strip())
        if any(
            (
                prometheus_url_configured,
                prometheus_header_configured,
                prometheus_key_configured,
            )
        ):
            prometheus_auth_complete = prometheus_header_configured == prometheus_key_configured
            if not prometheus_auth_complete:
                issues.append(
                    "Prometheus MCP authentication is incomplete; "
                    "PROMETHEUS_MCP_API_KEY_HEADER and PROMETHEUS_MCP_API_KEY must "
                    "both be configured or both be empty"
                )
            if not prometheus_url_configured:
                issues.append(
                    "Prometheus MCP configuration is incomplete; missing: PROMETHEUS_MCP_URL"
                )
            elif prometheus_auth_complete:
                if not self.mcp_settings_path.is_file():
                    issues.append(f"MCP settings file does not exist: {self.mcp_settings_path}")
                elif self.ai_provider not in REAL_AI_PROVIDERS:
                    issues.append(
                        "Prometheus MCP requires a real AI provider model with tool calling"
                    )
        if self.http_scheduler not in {"in_memory", "redis", "manual"}:
            issues.append(f"Unsupported HTTP_SCHEDULER: {self.http_scheduler}")
        if self.http_scheduler == "redis" and not self.redis_enabled:
            issues.append("REDIS_ENABLED must be true when HTTP_SCHEDULER=redis")
        if (
            "external_knowledge" in self.knowledge_sources
            and not self.external_knowledge_base_url.strip()
        ):
            issues.append(
                "EXTERNAL_KNOWLEDGE_BASE_URL is required when external knowledge is selected"
            )
        if self.external_knowledge_api_key and not self.external_knowledge_api_key_is_current():
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
    return _normalize_runtime_overrides(payload)


def resolve_runtime_settings(
    deployment_baseline: Settings,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Layer persisted runtime overrides on an immutable deployment baseline."""

    effective_overrides = _normalize_runtime_overrides(
        load_runtime_overrides(deployment_baseline.runtime_settings_path)
        if overrides is None
        else overrides
    )
    if not effective_overrides:
        return deployment_baseline.model_copy(deep=True)
    return Settings.model_validate(
        {
            **deployment_baseline.model_dump(mode="python"),
            **effective_overrides,
        }
    )


def get_deployment_settings() -> Settings:
    """Load deployment configuration without consulting runtime overrides."""

    return Settings()


@lru_cache
def get_settings() -> Settings:
    # Deployment configuration (.env) is the bootstrap baseline. Runtime
    # overrides persisted in runtime-settings.json take precedence over the
    # deployment values for every key in RUNTIME_SETTINGS_KEYS, so changes made
    # through the admin settings page remain authoritative until they are
    # explicitly cleared from the runtime file.
    bootstrap = get_deployment_settings()
    return resolve_runtime_settings(bootstrap)
