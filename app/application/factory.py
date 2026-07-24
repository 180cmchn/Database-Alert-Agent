from __future__ import annotations

from dataclasses import dataclass

from app.adapters.ai import (
    ConservativeFallbackAdvisor,
    FakeAIAdvisor,
    FakeConclusionValidator,
    OpenAICompatibleAdvisor,
    OpenAICompatibleConclusionValidator,
)
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
from app.adapters.flashduty import (
    FlashDutyAlertSourceAdapter,
    FlashDutyClient,
    build_flashduty_tools,
)
from app.adapters.investigation import (
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
    ToolExecutor,
    build_default_tool_registry,
)
from app.adapters.notification import (
    LogManagementNotifier,
    WeComManagementNotifier,
)
from app.adapters.external_knowledge import ExternalKnowledgeClient
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.adapters.persistence import SQLAlchemyAlertRepository
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


def _build_advisor(settings: Settings) -> AIAdvisor:
    if settings.ai_provider == "fake":
        return FakeAIAdvisor()
    return OpenAICompatibleAdvisor(
        api_key=settings.ai_api_key,
        base_url=settings.ai_base_url,
        model=settings.ai_model,
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
        timeout_seconds=settings.ai_timeout_seconds,
        max_retries=settings.ai_max_retries,
        json_mode=settings.ai_json_mode,
    )


def _build_notifier(settings: Settings) -> ManagementNotifier:
    if settings.wecom_webhook_url:
        return WeComManagementNotifier(settings.wecom_webhook_url)
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
        api_key=settings.external_knowledge_api_key,
        timeout_seconds=settings.external_knowledge_timeout_seconds,
        max_retries=settings.external_knowledge_max_retries,
    )


def _build_tool_registry(
    settings: Settings, client: FlashDutyClient | None = None
) -> InvestigationToolRegistry:
    registry = build_default_tool_registry()
    if client is None:
        return registry
    for tool in build_flashduty_tools(
        client,
        item_limit=settings.flashduty_context_item_limit,
        metrics_ds_name=settings.flashduty_metrics_ds_name,
        logs_ds_name=settings.flashduty_logs_ds_name,
        logs_ds_type=settings.flashduty_logs_ds_type,
    ):
        registry.register(tool)
    return registry


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
    # Build every replaceable adapter before mutating the live service. Constructors
    # perform no network I/O, so this synchronous swap cannot yield halfway through.
    advisor = _build_advisor(settings)
    conclusion_validator = _build_conclusion_validator(settings)
    notifier = _build_notifier(settings)
    strategy_provider = DefaultInvestigationStrategyProvider(
        settings.react_max_dynamic_turns if settings.react_enabled else 0,
        external_tool_timeout_seconds=_flashduty_tool_timeout(settings),
    )
    external_knowledge_client = _build_external_knowledge_client(settings)
    agent = InvestigationAgent(
        repository=service.repository,
        runbook_provider=service.runbook_provider,
        advisor=advisor,
        fallback_advisor=service.fallback_advisor,
        rule_validator=service.rule_validator,
        conclusion_validator=conclusion_validator,
        tool_registry=service.tool_registry,
        tool_executor=service.tool_executor,
        strategy_provider=strategy_provider,
        runbook_limit=settings.runbook_limit,
        external_knowledge_client=external_knowledge_client,
        external_knowledge_limit=settings.external_knowledge_limit,
        knowledge_sources=settings.knowledge_sources,
    )

    service.advisor = advisor
    service.conclusion_validator = conclusion_validator
    service.notifier = notifier
    service.strategy_provider = strategy_provider
    service.runbook_limit = settings.runbook_limit
    service.react_enabled = settings.react_enabled
    service.max_dynamic_turns = settings.react_max_dynamic_turns if settings.react_enabled else 0
    service.validation_enabled = settings.validation_enabled
    service.shadow_enabled = settings.shadow_enabled
    service.ai_fallback_enabled = settings.ai_fallback_enabled
    service.external_knowledge_client = external_knowledge_client
    service.external_knowledge_limit = settings.external_knowledge_limit
    service.knowledge_sources = settings.knowledge_sources
    service.agent = agent
    runtime.settings = settings
    service.retire_adapters(old_advisor, old_conclusion_validator)


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

    if notifier is None:
        notifier = _build_notifier(settings)

    flashduty_client = _build_flashduty_client(settings)
    external_knowledge_client = _build_external_knowledge_client(settings)
    tool_registry = tool_registry or _build_tool_registry(settings, flashduty_client)
    strategy_provider = strategy_provider or DefaultInvestigationStrategyProvider(
        settings.react_max_dynamic_turns if settings.react_enabled else 0,
        external_tool_timeout_seconds=_flashduty_tool_timeout(settings),
    )
    rule_validator = rule_validator or RuleConclusionValidator()
    tool_executor = ToolExecutor(tool_registry, settings.tool_max_result_chars)

    service = AlertAnalysisService(
        source_registry=source_registry,
        runbook_provider=runbook_provider,
        advisor=advisor,
        notifier=notifier,
        repository=repository,
        strategy_provider=strategy_provider,
        tool_registry=tool_registry,
        tool_executor=tool_executor,
        rule_validator=rule_validator,
        conclusion_validator=conclusion_validator,
        fallback_advisor=ConservativeFallbackAdvisor(),
        runbook_limit=settings.runbook_limit,
        investigation_lease_seconds=settings.investigation_lease_seconds,
        react_enabled=settings.react_enabled,
        validation_enabled=settings.validation_enabled,
        shadow_enabled=settings.shadow_enabled,
        ai_fallback_enabled=settings.ai_fallback_enabled,
        max_dynamic_turns=settings.react_max_dynamic_turns if settings.react_enabled else 0,
        external_knowledge_client=external_knowledge_client,
        external_knowledge_limit=settings.external_knowledge_limit,
        knowledge_sources=settings.knowledge_sources,
    )
    return Runtime(
        settings=settings,
        repository=repository,
        service=service,
        runbook_provider=runbook_provider,
        runbook_store=runbook_store,
        flashduty_client=flashduty_client,
    )
