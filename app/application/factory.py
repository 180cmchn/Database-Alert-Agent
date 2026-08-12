from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from app.adapters.ai import (
    PROMPT_VERSION,
    ConservativeFallbackAdvisor,
    FakeAIAdvisor,
    FakeConclusionValidator,
    OpenAICompatibleAdvisor,
    OpenAICompatibleConclusionValidator,
)
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
from app.adapters.archery_harness import ArcheryHarnessRuntimeDependencies
from app.adapters.archery_mcp import (
    ARCHERY_SLOW_LOG_TOOL_NAME,
    ArcheryMCPClient,
    ArcherySlowLogEvidenceTool,
)
from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.flashduty import (
    FlashDutyAlertDetailEnricher,
    FlashDutyAlertSourceAdapter,
    FlashDutyClient,
    build_flashduty_tools,
)
from app.adapters.generic_mcp import GenericReadOnlyMCPEvidenceTool
from app.adapters.investigation import (
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
    MCPToolBinding,
    ToolExecutor,
    build_default_tool_registry,
)
from app.adapters.notification import (
    LogManagementNotifier,
    WeComManagementNotifier,
)
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.adapters.persistence import SQLAlchemyAlertRepository
from app.adapters.prometheus_harness import PrometheusHarnessRuntimeDependencies
from app.adapters.prometheus_mcp import (
    PROMETHEUS_METRICS_TOOL_NAME,
    PrometheusMCPClient,
    PrometheusMCPEvidenceTool,
)
from app.adapters.tool_result_analysis import (
    FakeToolResultAnalyzer,
    OpenAICompatibleToolResultAnalyzer,
)
from app.agents.graph import InvestigationAgent
from app.application.service import AlertAnalysisService
from app.application.validation import RuleConclusionValidator
from app.config import Settings
from app.domain.ports import (
    AIAdvisor,
    AlertRepository,
    ConclusionValidator,
    InvestigationStrategyProvider,
    ManagementNotifier,
    RunbookProvider,
    RunbookStore,
    ToolResultAnalyzer,
)
from app.domain.tool_calling import MCPServerSelectionModel, MCPToolCallingModel
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
    runbook_provider: RunbookProvider
    runbook_store: RunbookStore
    flashduty_client: FlashDutyClient | None = None


def _flashduty_tool_timeout(settings: Settings) -> float:
    retry_backoff = sum(min(2**attempt, 10) for attempt in range(settings.flashduty_max_retries))
    return min(
        120,
        settings.flashduty_timeout_seconds * (settings.flashduty_max_retries + 1) + retry_backoff,
    )


def _runtime_manifest_config(settings: Settings) -> dict[str, object]:
    """Return non-secret runtime values that must be frozen per investigation."""

    return {
        "code_version": settings.app_code_version,
        "prompt_version": PROMPT_VERSION,
        "ai_timeout_seconds": settings.ai_timeout_seconds,
        "ai_max_retries": settings.ai_max_retries,
        "ai_max_tokens": settings.ai_max_tokens,
        "archery_mcp_max_agent_steps": settings.archery_mcp_max_agent_steps,
        "prometheus_mcp_max_agent_steps": settings.prometheus_mcp_max_agent_steps,
    }


def _build_advisor(settings: Settings) -> AIAdvisor:
    if settings.ai_provider == "fake":
        return FakeAIAdvisor()
    return OpenAICompatibleAdvisor(
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        max_tokens=settings.ai_max_tokens,
        timeout_seconds=settings.ai_timeout_seconds,
        max_retries=settings.ai_max_retries,
        json_mode=settings.ai_json_mode,
    )


def _build_conclusion_validator(settings: Settings) -> ConclusionValidator:
    if settings.ai_provider == "fake":
        return FakeConclusionValidator()
    return OpenAICompatibleConclusionValidator(
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        max_tokens=settings.ai_max_tokens,
        timeout_seconds=settings.ai_timeout_seconds,
        max_retries=settings.ai_max_retries,
        json_mode=settings.ai_json_mode,
    )


def _build_tool_result_analyzer(settings: Settings) -> ToolResultAnalyzer:
    if settings.ai_provider == "fake":
        return FakeToolResultAnalyzer()
    return OpenAICompatibleToolResultAnalyzer(
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        model=settings.ai_model,
        max_tokens=settings.ai_max_tokens,
        timeout_seconds=settings.ai_timeout_seconds,
        max_retries=settings.ai_max_retries,
        json_mode=settings.ai_json_mode,
    )


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
        max_retries=settings.external_knowledge_max_retries,
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
            max_agent_steps=settings.archery_mcp_max_agent_steps,
            timeout_seconds=settings.archery_mcp_timeout_seconds,
            harness_runtime_dependencies=(
                ArcheryHarnessRuntimeDependencies(repository)
                if repository is not None
                else None
            ),
        ),
    )


def _build_prometheus_mcp_tool(
    settings: Settings,
    model: AIAdvisor,
    repository: AlertRepository | None = None,
) -> PrometheusMCPEvidenceTool | None:
    """Build the optional SSE monitoring evidence tool without loading ``.env``."""

    if not settings.prometheus_mcp_enabled or not isinstance(model, MCPToolCallingModel):
        return None
    return PrometheusMCPEvidenceTool(
        PrometheusMCPClient.from_settings(
            settings.mcp_settings_path,
            model,
            environment={
                "PROMETHEUS_MCP_SSE_URL": settings.prometheus_mcp_sse_url,
                "PROMETHEUS_MCP_API_KEY_HEADER": settings.prometheus_mcp_api_key_header,
                "PROMETHEUS_MCP_API_KEY": settings.prometheus_mcp_api_key,
            },
            max_agent_steps=settings.prometheus_mcp_max_agent_steps,
            timeout_seconds=settings.prometheus_mcp_timeout_seconds,
            sse_read_timeout_seconds=settings.prometheus_mcp_tool_timeout_seconds,
            harness_runtime_dependencies=(
                PrometheusHarnessRuntimeDependencies(repository)
                if repository is not None
                else None
            ),
        ),
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
            "PROMETHEUS_MCP_SSE_URL": settings.prometheus_mcp_sse_url,
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
                    "environment variables: "
                    + ", ".join(missing)
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
) -> tuple[list[object], list[MCPToolBinding]]:
    catalog = load_mcp_catalog(settings.mcp_settings_path)
    enabled = _enabled_catalog_servers(catalog, settings)
    if enabled and (
        not isinstance(advisor, MCPToolCallingModel)
        or not isinstance(advisor, MCPServerSelectionModel)
    ):
        # Fake and injected advisors without both capabilities cannot safely host
        # MCP sessions. Readiness reports the deployment mismatch; runtime swaps
        # simply leave those live tools unavailable.
        return [], []

    tools: list[object] = []
    bindings: list[MCPToolBinding] = []
    for descriptor in enabled:
        timeout_seconds = _mcp_tool_timeout(descriptor, settings)
        if descriptor.name == "archery":
            tool = _build_archery_mcp_tool(settings, advisor, repository)
        elif descriptor.name == "prometheus":
            tool = _build_prometheus_mcp_tool(settings, advisor, repository)
        else:
            assert isinstance(advisor, MCPToolCallingModel)
            tool = GenericReadOnlyMCPEvidenceTool(
                descriptor,
                descriptor.resolve_connection(
                    _mcp_environment(settings),
                    require_https=settings.app_env.lower() in {"production", "prod"},
                ),
                advisor,
                timeout_seconds=min(timeout_seconds, 120),
            )
        if tool is None:
            continue
        tools.append(tool)
        bindings.append(
            MCPToolBinding(
                server_name=descriptor.name,
                tool_name=tool.name,
                role=descriptor.prompts.role,
                purpose=descriptor.prompts.purpose,
                timeout_seconds=timeout_seconds,
                read_only=descriptor.read_only,
            )
        )
    return tools, bindings


def _build_tool_registry(
    settings: Settings,
    advisor: AIAdvisor,
    client: FlashDutyClient | None = None,
    repository: AlertRepository | None = None,
) -> tuple[InvestigationToolRegistry, tuple[MCPToolBinding, ...]]:
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
    mcp_tools, bindings = _build_mcp_tools(settings, advisor, repository)
    for tool in mcp_tools:
        registry.register(tool)  # type: ignore[arg-type]
    return registry, tuple(bindings)


def _configured_mcp_bindings(
    settings: Settings,
    registry: InvestigationToolRegistry,
) -> tuple[MCPToolBinding, ...]:
    """Describe configured MCP tools already supplied by an external registry."""

    catalog = load_mcp_catalog(settings.mcp_settings_path)
    bindings: list[MCPToolBinding] = []
    for descriptor in _enabled_catalog_servers(catalog, settings):
        tool_name = (
            ARCHERY_SLOW_LOG_TOOL_NAME
            if descriptor.name == "archery"
            else PROMETHEUS_METRICS_TOOL_NAME
            if descriptor.name == "prometheus"
            else f"query_mcp_{descriptor.name}"
        )
        if registry.get(tool_name) is None:
            continue
        bindings.append(
            MCPToolBinding(
                server_name=descriptor.name,
                tool_name=tool_name,
                role=descriptor.prompts.role,
                purpose=descriptor.prompts.purpose,
                timeout_seconds=_mcp_tool_timeout(descriptor, settings),
                read_only=descriptor.read_only,
            )
        )
    return tuple(bindings)


def _strategy_provider(
    advisor: AIAdvisor,
    registry: InvestigationToolRegistry,
    bindings: tuple[MCPToolBinding, ...],
) -> DefaultInvestigationStrategyProvider:
    if bindings and not isinstance(advisor, MCPServerSelectionModel):
        raise ValueError("Configured MCP servers require MCP relevance selection")
    return DefaultInvestigationStrategyProvider(
        model=advisor if isinstance(advisor, MCPServerSelectionModel) else None,
        mcp_bindings=list(bindings),
        available_tools=registry.available_names(),
    )


def _resolve_runbook_adapters(
    settings: Settings,
    provider: RunbookProvider | None,
    store: RunbookStore | None,
) -> tuple[RunbookProvider, RunbookStore]:
    """Resolve one searchable and inspectable runbook corpus as an atomic pair."""

    if provider is None and store is None:
        library = LocalPDFRunbookLibrary(
            settings.runbook_pdf_dir,
            max_file_bytes=settings.runbook_pdf_max_file_bytes,
            max_text_chars=settings.runbook_pdf_max_text_chars,
            min_score=settings.runbook_match_min_score,
            min_confidence=settings.runbook_match_min_confidence,
        )
        return library, library
    if provider is None or store is None:
        raise ValueError(
            "runbook_provider and runbook_store must be provided together so "
            "administration and analysis use the same runbook corpus"
        )
    return provider, store


def apply_runtime_settings(runtime: Runtime, settings: Settings) -> None:
    """Apply a validated runtime configuration without replacing stateful components."""

    service = runtime.service
    old_advisor = service.advisor
    old_conclusion_validator = service.conclusion_validator
    old_tool_result_analyzer = service.tool_result_analyzer
    # Build every replaceable adapter before mutating the live service. Constructors
    # perform no network I/O, so this synchronous swap cannot yield halfway through.
    advisor = _build_advisor(settings)
    conclusion_validator = _build_conclusion_validator(settings)
    tool_result_analyzer = _build_tool_result_analyzer(settings)
    notifier = _build_notifier(settings)
    old_mcp_bindings = getattr(service.strategy_provider, "mcp_bindings", ())
    replaced_names = {binding.tool_name for binding in old_mcp_bindings}
    replaced_names.update({ARCHERY_SLOW_LOG_TOOL_NAME, PROMETHEUS_METRICS_TOOL_NAME})
    retained_tools = [
        tool
        for name in service.tool_registry.names()
        if name not in replaced_names
        if (tool := service.tool_registry.get(name)) is not None
    ]
    tool_registry = InvestigationToolRegistry(retained_tools)
    mcp_tools, mcp_bindings = _build_mcp_tools(
        settings, advisor, service.repository
    )
    for tool in mcp_tools:
        tool_registry.register(tool)  # type: ignore[arg-type]
    tool_executor = ToolExecutor(tool_registry)
    strategy_provider = _strategy_provider(
        advisor, tool_registry, tuple(mcp_bindings)
    )
    external_knowledge_client = _build_external_knowledge_client(settings)
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
        runbook_provider=service.runbook_provider,
        advisor=advisor,
        fallback_advisor=service.fallback_advisor,
        rule_validator=service.rule_validator,
        conclusion_validator=conclusion_validator,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        tool_result_analyzer=tool_result_analyzer,
        tool_result_analysis_threshold_chars=(
            settings.tool_result_analysis_threshold_chars
        ),
        strategy_provider=strategy_provider,
        alert_detail_enricher=alert_detail_enricher,
        runbook_limit=settings.runbook_limit,
        external_knowledge_client=external_knowledge_client,
        external_knowledge_limit=settings.external_knowledge_limit,
        external_knowledge_min_relevance=(settings.external_knowledge_min_relevance),
        knowledge_sources=settings.knowledge_sources,
    )

    service.advisor = advisor
    service.conclusion_validator = conclusion_validator
    service.notifier = notifier
    service.strategy_provider = strategy_provider
    service.alert_detail_enricher = alert_detail_enricher
    service.tool_registry = tool_registry
    service.tool_executor = tool_executor
    service.tool_result_analyzer = tool_result_analyzer
    service.tool_result_analysis_threshold_chars = (
        settings.tool_result_analysis_threshold_chars
    )
    service.runbook_limit = settings.runbook_limit
    service.react_enabled = settings.react_enabled
    service.max_dynamic_turns = settings.react_max_dynamic_turns if settings.react_enabled else 0
    service.validation_enabled = settings.validation_enabled
    service.ai_fallback_enabled = settings.ai_fallback_enabled
    service.external_knowledge_client = external_knowledge_client
    service.external_knowledge_limit = settings.external_knowledge_limit
    service.external_knowledge_min_relevance = settings.external_knowledge_min_relevance
    service.runbook_match_min_score = settings.runbook_match_min_score
    service.runbook_match_min_confidence = settings.runbook_match_min_confidence
    service.knowledge_sources = settings.knowledge_sources
    service.runtime_manifest_config = _runtime_manifest_config(settings)
    service.agent = agent
    runtime.settings = settings
    service.retire_adapters(
        old_advisor,
        old_conclusion_validator,
        old_tool_result_analyzer,
    )


def build_runtime(
    settings: Settings,
    *,
    repository: AlertRepository | None = None,
    advisor: AIAdvisor | None = None,
    notifier: ManagementNotifier | None = None,
    runbook_provider: RunbookProvider | None = None,
    runbook_store: RunbookStore | None = None,
    source_registry: AlertSourceRegistry | None = None,
    strategy_provider: InvestigationStrategyProvider | None = None,
    tool_registry: InvestigationToolRegistry | None = None,
    rule_validator: ConclusionValidator | None = None,
    conclusion_validator: ConclusionValidator | None = None,
    tool_result_analyzer: ToolResultAnalyzer | None = None,
) -> Runtime:
    runbook_provider, runbook_store = _resolve_runbook_adapters(
        settings, runbook_provider, runbook_store
    )
    repository = repository or SQLAlchemyAlertRepository(settings.database_url)
    source_registry = source_registry or AlertSourceRegistry(
        [
            CanonicalAlertSourceAdapter(settings.environment_aliases),
            FlashDutyAlertSourceAdapter(settings.environment_aliases),
        ]
    )
    if advisor is None:
        advisor = _build_advisor(settings)

    if conclusion_validator is None:
        conclusion_validator = _build_conclusion_validator(settings)

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
    external_knowledge_client = _build_external_knowledge_client(settings)
    if tool_registry is None:
        tool_registry, mcp_bindings = _build_tool_registry(
            settings,
            advisor,
            flashduty_client,
            repository,
        )
    else:
        mcp_bindings = _configured_mcp_bindings(settings, tool_registry)
    strategy_provider = strategy_provider or _strategy_provider(
        advisor, tool_registry, mcp_bindings
    )
    rule_validator = rule_validator or RuleConclusionValidator()
    tool_executor = ToolExecutor(tool_registry)

    service = AlertAnalysisService(
        source_registry=source_registry,
        runbook_provider=runbook_provider,
        advisor=advisor,
        notifier=notifier,
        repository=repository,
        strategy_provider=strategy_provider,
        alert_detail_enricher=alert_detail_enricher,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        tool_result_analyzer=tool_result_analyzer,
        tool_result_analysis_threshold_chars=(
            settings.tool_result_analysis_threshold_chars
        ),
        rule_validator=rule_validator,
        conclusion_validator=conclusion_validator,
        fallback_advisor=ConservativeFallbackAdvisor(),
        runbook_limit=settings.runbook_limit,
        investigation_lease_seconds=settings.investigation_lease_seconds,
        react_enabled=settings.react_enabled,
        validation_enabled=settings.validation_enabled,
        ai_fallback_enabled=settings.ai_fallback_enabled,
        max_dynamic_turns=settings.react_max_dynamic_turns if settings.react_enabled else 0,
        external_knowledge_client=external_knowledge_client,
        external_knowledge_limit=settings.external_knowledge_limit,
        external_knowledge_min_relevance=(settings.external_knowledge_min_relevance),
        runbook_match_min_score=settings.runbook_match_min_score,
        runbook_match_min_confidence=settings.runbook_match_min_confidence,
        knowledge_sources=settings.knowledge_sources,
        runtime_manifest_config=_runtime_manifest_config(settings),
    )
    return Runtime(
        settings=settings,
        repository=repository,
        service=service,
        runbook_provider=runbook_provider,
        runbook_store=runbook_store,
        flashduty_client=flashduty_client,
    )
