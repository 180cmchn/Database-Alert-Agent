from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from app.adapters.ai import (
    AI_PROVIDER_MAX_ATTEMPTS,
    PROMPT_VERSION,
    ConservativeFallbackAdvisor,
    FakeAIAdvisor,
    OpenAICompatibleAdvisor,
    OpenAIResponsesAdvisor,
)
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
from app.adapters.archery_harness import ArcheryHarnessRuntimeDependencies
from app.adapters.archery_mcp import (
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcheryMCPClient,
    ArcherySlowLogEvidenceTool,
)
from app.adapters.external_knowledge import ExternalKnowledgeClient, ExternalKnowledgeSource
from app.adapters.flashduty import (
    FlashDutyAlertDetailEnricher,
    FlashDutyAlertSourceAdapter,
    FlashDutyClient,
    build_flashduty_tools,
)
from app.adapters.generic_mcp import GenericMCPEvidenceTool
from app.adapters.investigation import (
    InvestigationToolRegistry,
    ToolExecutor,
    build_default_tool_registry,
)
from app.adapters.knowledge import KnowledgeSourceRegistry
from app.adapters.notification import (
    LogManagementNotifier,
    WeComManagementNotifier,
)
from app.adapters.persistence import SQLAlchemyAlertRepository
from app.adapters.prometheus_harness import PrometheusHarnessRuntimeDependencies
from app.adapters.prometheus_mcp import (
    PROMETHEUS_METRICS_TOOL_NAME,
    PrometheusMCPClient,
    PrometheusMCPEvidenceTool,
)
from app.adapters.tool_result_analysis import DeterministicToolResultProcessor
from app.agents.graph import InvestigationAgent
from app.application.service import AlertAnalysisService
from app.application.validation import RuleConclusionValidator
from app.config import Settings
from app.domain.ports import (
    AIAdvisor,
    AlertRepository,
    ConclusionValidator,
    ManagementNotifier,
    ToolResultAnalyzer,
)
from app.domain.tool_calling import MCPToolCallingModel
from app.mcp_catalog import (
    MCPCatalog,
    MCPCatalogConfigurationError,
    MCPServerDescriptor,
    load_mcp_catalog,
)


@dataclass
class Runtime:
    settings: Settings
    repository: AlertRepository
    service: AlertAnalysisService
    flashduty_client: FlashDutyClient | None = None
    deployment_settings: Settings | None = None


def _flashduty_tool_timeout(settings: Settings) -> float:
    retry_backoff = sum(min(2**attempt, 10) for attempt in range(settings.flashduty_max_retries))
    return min(
        120,
        settings.flashduty_timeout_seconds * (settings.flashduty_max_retries + 1) + retry_backoff,
    )


def ai_settings_revision(settings: Settings) -> str:
    payload = {
        "provider": settings.ai_provider,
        "base_url": settings.ai_base_url.rstrip("/"),
        "model": settings.ai_model,
        "react_model": settings.ai_react_model,
        "mcp_model": settings.ai_mcp_model,
        "json_mode": settings.ai_json_mode,
        "reasoning_effort": settings.ai_reasoning_effort,
        "react_reasoning_effort": settings.ai_react_reasoning_effort,
        "mcp_reasoning_effort": settings.ai_mcp_reasoning_effort,
        "max_tokens": settings.ai_max_tokens,
        "api_key_hash": hashlib.sha256(settings.ai_api_key.encode("utf-8")).hexdigest(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _runtime_manifest_config(settings: Settings) -> dict[str, object]:
    """Return non-secret runtime values that must be frozen per investigation."""

    return {
        "code_version": settings.app_code_version,
        "prompt_version": PROMPT_VERSION,
        "ai_timeout_seconds": settings.ai_timeout_seconds,
        "ai_max_tokens": settings.ai_max_tokens,
        "ai_provider_max_attempts": AI_PROVIDER_MAX_ATTEMPTS,
        "analysis_timeout_seconds": settings.analysis_timeout_seconds,
        "prometheus_mcp_timeout_seconds": settings.prometheus_mcp_timeout_seconds,
        "prometheus_investigation_budget_seconds": (
            settings.prometheus_investigation_budget_seconds
        ),
        "prometheus_mcp_tool_timeout_seconds": settings.prometheus_mcp_tool_timeout_seconds,
        "ai_settings_revision": ai_settings_revision(settings),
    }


def _build_advisor(settings: Settings) -> AIAdvisor:
    if settings.ai_provider == "fake":
        return FakeAIAdvisor()
    advisor_type: type[OpenAICompatibleAdvisor] | type[OpenAIResponsesAdvisor]
    if settings.ai_provider == "openai_compatible":
        advisor_type = OpenAICompatibleAdvisor
    elif settings.ai_provider == "openai_responses":
        advisor_type = OpenAIResponsesAdvisor
    else:
        raise ValueError(f"Unsupported AI_PROVIDER: {settings.ai_provider}")
    return advisor_type(
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        max_tokens=settings.ai_max_tokens,
        timeout_seconds=settings.ai_timeout_seconds,
        json_mode=settings.ai_json_mode,
        react_model=settings.ai_react_model or None,
        react_reasoning_effort=settings.ai_react_reasoning_effort or None,
        mcp_model=settings.ai_mcp_model or None,
        mcp_reasoning_effort=settings.ai_mcp_reasoning_effort or None,
        reasoning_effort=settings.ai_reasoning_effort or None,
    )


def _build_tool_result_analyzer(settings: Settings) -> ToolResultAnalyzer:
    """Build the deterministic, non-causal raw-result projector."""

    del settings
    return DeterministicToolResultProcessor()


def _build_notifier(settings: Settings) -> ManagementNotifier:
    if settings.wecom_enabled and settings.wecom_webhook_url and settings.wecom_page_base_url:
        return WeComManagementNotifier(
            settings.wecom_webhook_url,
            settings.wecom_page_base_url,
        )
    return LogManagementNotifier()


def _build_flashduty_client(settings: Settings) -> FlashDutyClient | None:
    if not settings.flashduty_enabled or not settings.flashduty_app_key:
        return None
    return FlashDutyClient(
        settings.flashduty_app_key,
        base_url=settings.flashduty_base_url,
        timeout_seconds=settings.flashduty_timeout_seconds,
        max_retries=settings.flashduty_max_retries,
    )


def _build_external_knowledge_client(settings: Settings) -> ExternalKnowledgeClient | None:
    """Build the optional external knowledge API client.

    Returns ``None`` when the feature is disabled, so downstream code can treat
    the client as purely optional.
    """

    if not settings.external_knowledge_enabled:
        return None
    return ExternalKnowledgeClient(
        base_url=settings.external_knowledge_base_url,
        api_key=settings.effective_external_knowledge_api_key(),
        timeout_seconds=settings.external_knowledge_timeout_seconds,
    )


def _build_knowledge_registry(settings: Settings) -> KnowledgeSourceRegistry:
    sources = []
    client = _build_external_knowledge_client(settings)
    if client is not None:
        sources.append(
            ExternalKnowledgeSource(
                client,
                limit=settings.external_knowledge_limit,
                min_relevance=settings.external_knowledge_min_relevance,
            )
        )
    return KnowledgeSourceRegistry(
        sources,
        source_timeout_seconds=settings.external_knowledge_timeout_seconds,
    )


def _build_archery_mcp_tool(
    settings: Settings,
    model: AIAdvisor,
    repository: AlertRepository | None = None,
) -> ArcherySlowLogEvidenceTool | None:
    if not settings.archery_mcp_enabled or not isinstance(model, MCPToolCallingModel):
        return None
    return ArcherySlowLogEvidenceTool(
        ArcheryMCPClient.from_settings(
            settings.mcp_settings_path,
            model,
            environment={
                "ARCHERY_MCP_URL": settings.archery_mcp_url,
                "ARCHERY_MCP_TOKEN": settings.archery_mcp_token,
            },
            window_seconds=settings.archery_slow_log_window_seconds,
            timeout_seconds=settings.archery_mcp_timeout_seconds,
            investigation_budget_seconds=(settings.archery_investigation_budget_seconds),
            harness_runtime_dependencies=(
                ArcheryHarnessRuntimeDependencies(repository) if repository is not None else None
            ),
        ),
        default_timeout_seconds=settings.archery_mcp_tool_timeout_seconds,
    )


def _build_prometheus_mcp_tool(
    settings: Settings,
    model: AIAdvisor,
    repository: AlertRepository | None = None,
) -> PrometheusMCPEvidenceTool | None:
    """Build the optional Prometheus monitoring evidence tool without loading ``.env``."""

    if not settings.prometheus_mcp_enabled or not isinstance(model, MCPToolCallingModel):
        return None
    return PrometheusMCPEvidenceTool(
        PrometheusMCPClient.from_settings(
            settings.mcp_settings_path,
            model,
            environment={
                "PROMETHEUS_MCP_URL": settings.prometheus_mcp_url,
                "PROMETHEUS_MCP_API_KEY_HEADER": settings.prometheus_mcp_api_key_header,
                "PROMETHEUS_MCP_API_KEY": settings.prometheus_mcp_api_key,
            },
            timeout_seconds=settings.prometheus_mcp_timeout_seconds,
            investigation_budget_seconds=settings.prometheus_investigation_budget_seconds,
            sse_read_timeout_seconds=settings.prometheus_mcp_tool_timeout_seconds,
            harness_runtime_dependencies=(
                PrometheusHarnessRuntimeDependencies(repository) if repository is not None else None
            ),
        ),
        default_timeout_seconds=settings.prometheus_mcp_tool_timeout_seconds,
    )


def _mcp_environment(settings: Settings) -> dict[str, str]:
    """Resolve catalog references at the connection boundary only.

    ``Settings`` intentionally ignores unknown fields, while a newly declared MCP
    can introduce arbitrary environment-variable names. Read the configured dotenv
    files here so those values remain transport-only and never enter Settings,
    runtime APIs, manifests, or Agent prompts.
    """

    environment: dict[str, str] = {}
    raw_env_files = settings.model_config.get("env_file")
    env_files = (
        (raw_env_files,)
        if isinstance(raw_env_files, (str, os.PathLike))
        else tuple(raw_env_files or ())
    )
    encoding = str(settings.model_config.get("env_file_encoding") or "utf-8")
    for raw_path in env_files:
        for name, value in dotenv_values(Path(raw_path), encoding=encoding).items():
            if value is not None:
                environment[name] = value
    environment.update(os.environ)
    environment.update(
        {
            "ARCHERY_MCP_URL": settings.archery_mcp_url,
            "ARCHERY_MCP_TOKEN": settings.archery_mcp_token,
            "PROMETHEUS_MCP_URL": settings.prometheus_mcp_url,
            "PROMETHEUS_MCP_API_KEY_HEADER": settings.prometheus_mcp_api_key_header,
            "PROMETHEUS_MCP_API_KEY": settings.prometheus_mcp_api_key,
        }
    )
    return environment


def _enabled_catalog_servers(
    catalog: MCPCatalog,
    settings: Settings,
) -> tuple[MCPServerDescriptor, ...]:
    environment = _mcp_environment(settings)
    enabled: list[MCPServerDescriptor] = []
    for descriptor in catalog.servers:
        missing = [
            name
            for name in descriptor.referenced_environment_variables
            if not environment.get(name, "").strip()
        ]
        if missing:
            if descriptor.explicitly_enabled:
                raise MCPCatalogConfigurationError(
                    f"Explicitly enabled MCP server {descriptor.name!r} is missing required "
                    "environment variables: " + ", ".join(missing)
                )
            continue
        enabled.append(descriptor)
    return tuple(enabled)


def _mcp_tool_timeout(descriptor: MCPServerDescriptor, settings: Settings) -> float:
    if descriptor.name == "archery":
        return settings.archery_mcp_tool_timeout_seconds
    if descriptor.name == "prometheus":
        return settings.prometheus_mcp_tool_timeout_seconds
    raw = descriptor.provider_options.get("toolTimeoutSeconds", 780)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not 1 <= raw <= 1200:
        raise ValueError(
            f"MCP server {descriptor.name!r} toolTimeoutSeconds must be between 1 and 1200"
        )
    return float(raw)


def _build_mcp_tools(
    settings: Settings,
    advisor: AIAdvisor,
    repository: AlertRepository | None,
) -> list[object]:
    catalog = load_mcp_catalog(settings.mcp_settings_path)
    enabled = _enabled_catalog_servers(catalog, settings)
    if enabled and not isinstance(advisor, MCPToolCallingModel):
        return []

    tools: list[object] = []
    for descriptor in enabled:
        timeout_seconds = _mcp_tool_timeout(descriptor, settings)
        if descriptor.name == "archery":
            tool = _build_archery_mcp_tool(settings, advisor, repository)
        elif descriptor.name == "prometheus":
            tool = _build_prometheus_mcp_tool(settings, advisor, repository)
        else:
            assert isinstance(advisor, MCPToolCallingModel)
            tool = GenericMCPEvidenceTool(
                descriptor,
                descriptor.resolve_connection(
                    _mcp_environment(settings),
                    require_https=settings.app_env.lower() in {"production", "prod"},
                ),
                advisor,
                timeout_seconds=timeout_seconds,
                repository=repository,
            )
        if tool is None:
            continue
        tools.append(tool)
    return tools


def _build_tool_registry(
    settings: Settings,
    advisor: AIAdvisor,
    client: FlashDutyClient | None = None,
    repository: AlertRepository | None = None,
) -> InvestigationToolRegistry:
    registry = build_default_tool_registry()
    if client is not None:
        for tool in build_flashduty_tools(
            client,
            item_limit=settings.flashduty_context_item_limit,
            metrics_ds_name=settings.flashduty_metrics_ds_name,
            logs_ds_name=settings.flashduty_logs_ds_name,
            logs_ds_type=settings.flashduty_logs_ds_type,
            monitors_enabled=settings.flashduty_monitors_enabled,
            changes_enabled=settings.flashduty_changes_enabled,
            channel_ids=settings.flashduty_poll_channel_ids,
        ):
            registry.register(tool)
    mcp_tools = _build_mcp_tools(settings, advisor, repository)
    for tool in mcp_tools:
        registry.register(tool)  # type: ignore[arg-type]
    return registry


def apply_runtime_settings(runtime: Runtime, settings: Settings) -> None:
    """Apply a validated runtime configuration without replacing stateful components."""

    service = runtime.service
    old_advisor = service.advisor
    old_tool_result_analyzer = service.tool_result_analyzer
    # Build every replaceable adapter before mutating the live service. Constructors
    # perform no network I/O, so this synchronous swap cannot yield halfway through.
    advisor = _build_advisor(settings)
    tool_result_analyzer = _build_tool_result_analyzer(settings)
    notifier = _build_notifier(settings)
    replaced_names = {ARCHERY_SLOW_LOG_TOOL_NAME, PROMETHEUS_METRICS_TOOL_NAME}
    replaced_names.update(
        name for name in service.tool_registry.names() if name.startswith("query_mcp_")
    )
    retained_tools = [
        tool
        for name in service.tool_registry.names()
        if name not in replaced_names
        if (tool := service.tool_registry.get(name)) is not None
    ]
    tool_registry = InvestigationToolRegistry(retained_tools)
    mcp_tools = _build_mcp_tools(settings, advisor, service.repository)
    for tool in mcp_tools:
        tool_registry.register(tool)  # type: ignore[arg-type]
    tool_executor = ToolExecutor(tool_registry)
    knowledge_registry = _build_knowledge_registry(settings)
    alert_detail_enricher = (
        FlashDutyAlertDetailEnricher(
            runtime.flashduty_client,
            FlashDutyAlertSourceAdapter(settings.environment_aliases),
        )
        if runtime.flashduty_client is not None
        else None
    )
    agent = InvestigationAgent(
        repository=service.repository,
        knowledge_registry=knowledge_registry,
        advisor=advisor,
        fallback_advisor=service.fallback_advisor,
        rule_validator=service.rule_validator,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        tool_result_analyzer=tool_result_analyzer,
        alert_detail_enricher=alert_detail_enricher,
        knowledge_sources=settings.knowledge_sources,
    )

    service.advisor = advisor
    service.notifier = notifier
    service.alert_detail_enricher = alert_detail_enricher
    service.tool_registry = tool_registry
    service.tool_executor = tool_executor
    service.tool_result_analyzer = tool_result_analyzer
    service.knowledge_registry = knowledge_registry
    service.react_max_rounds = settings.react_max_rounds
    service.analysis_timeout_seconds = settings.analysis_timeout_seconds
    service.alert_analysis_filter_enabled = settings.alert_analysis_filter_enabled
    service.alert_analysis_filter_severities = frozenset(settings.alert_analysis_filter_severities)
    service.ai_fallback_enabled = settings.ai_fallback_enabled
    service.stream_main_agent_reasoning = settings.stream_main_agent_reasoning
    service.external_knowledge_min_relevance = settings.external_knowledge_min_relevance
    service.knowledge_sources = settings.knowledge_sources
    service.runtime_manifest_config = _runtime_manifest_config(settings)
    service.agent = agent
    runtime.settings = settings
    service.retire_adapters(
        old_advisor,
        old_tool_result_analyzer,
    )


def build_runtime(
    settings: Settings,
    *,
    deployment_settings: Settings | None = None,
    repository: AlertRepository | None = None,
    advisor: AIAdvisor | None = None,
    notifier: ManagementNotifier | None = None,
    knowledge_registry: KnowledgeSourceRegistry | None = None,
    source_registry: AlertSourceRegistry | None = None,
    tool_registry: InvestigationToolRegistry | None = None,
    rule_validator: ConclusionValidator | None = None,
    tool_result_analyzer: ToolResultAnalyzer | None = None,
) -> Runtime:
    repository = repository or SQLAlchemyAlertRepository(settings.database_url)
    source_registry = source_registry or AlertSourceRegistry(
        [
            CanonicalAlertSourceAdapter(settings.environment_aliases),
            FlashDutyAlertSourceAdapter(settings.environment_aliases),
        ]
    )
    if advisor is None:
        advisor = _build_advisor(settings)

    if tool_result_analyzer is None:
        tool_result_analyzer = _build_tool_result_analyzer(settings)

    if notifier is None:
        notifier = _build_notifier(settings)

    flashduty_client = _build_flashduty_client(settings)
    alert_detail_enricher = (
        FlashDutyAlertDetailEnricher(
            flashduty_client,
            FlashDutyAlertSourceAdapter(settings.environment_aliases),
        )
        if flashduty_client is not None
        else None
    )
    knowledge_registry = knowledge_registry or _build_knowledge_registry(settings)
    if tool_registry is None:
        tool_registry = _build_tool_registry(
            settings,
            advisor,
            flashduty_client,
            repository,
        )
    rule_validator = rule_validator or RuleConclusionValidator()
    tool_executor = ToolExecutor(tool_registry)

    service = AlertAnalysisService(
        source_registry=source_registry,
        knowledge_registry=knowledge_registry,
        advisor=advisor,
        notifier=notifier,
        repository=repository,
        alert_detail_enricher=alert_detail_enricher,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        tool_result_analyzer=tool_result_analyzer,
        rule_validator=rule_validator,
        fallback_advisor=ConservativeFallbackAdvisor(),
        investigation_lease_seconds=settings.investigation_lease_seconds,
        ai_fallback_enabled=settings.ai_fallback_enabled,
        stream_main_agent_reasoning=settings.stream_main_agent_reasoning,
        react_max_rounds=settings.react_max_rounds,
        analysis_timeout_seconds=settings.analysis_timeout_seconds,
        alert_analysis_filter_enabled=settings.alert_analysis_filter_enabled,
        alert_analysis_filter_severities=settings.alert_analysis_filter_severities,
        external_knowledge_min_relevance=(settings.external_knowledge_min_relevance),
        knowledge_sources=settings.knowledge_sources,
        runtime_manifest_config=_runtime_manifest_config(settings),
    )
    return Runtime(
        settings=settings,
        repository=repository,
        service=service,
        flashduty_client=flashduty_client,
        deployment_settings=(deployment_settings or settings).model_copy(deep=True),
    )
