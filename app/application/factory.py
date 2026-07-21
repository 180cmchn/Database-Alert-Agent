from __future__ import annotations

from dataclasses import dataclass

from app.adapters.ai import (
    FakeAIAdvisor,
    FakeConclusionValidator,
    OpenAICompatibleAdvisor,
    OpenAICompatibleConclusionValidator,
)
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
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
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.adapters.persistence import SQLAlchemyAlertRepository
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
    )


def _build_notifier(settings: Settings) -> ManagementNotifier:
    if settings.wecom_webhook_url:
        return WeComManagementNotifier(settings.wecom_webhook_url)
    return LogManagementNotifier()


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
    # Build every replaceable adapter before mutating the live service. Constructors
    # perform no network I/O, so this synchronous swap cannot yield halfway through.
    advisor = _build_advisor(settings)
    conclusion_validator = _build_conclusion_validator(settings)
    notifier = _build_notifier(settings)
    strategy_provider = DefaultInvestigationStrategyProvider(
        settings.react_max_dynamic_turns if settings.react_enabled else 0
    )

    service.advisor = advisor
    service.conclusion_validator = conclusion_validator
    service.notifier = notifier
    service.strategy_provider = strategy_provider
    service.runbook_limit = settings.runbook_limit
    service.react_enabled = settings.react_enabled
    service.validation_enabled = settings.validation_enabled
    service.shadow_enabled = settings.shadow_enabled
    runtime.settings = settings


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
            CanonicalAlertSourceAdapter(settings.environment_aliases)
        ]
    )
    if advisor is None:
        advisor = _build_advisor(settings)

    if conclusion_validator is None:
        conclusion_validator = _build_conclusion_validator(settings)

    if notifier is None:
        notifier = _build_notifier(settings)

    tool_registry = tool_registry or build_default_tool_registry()
    strategy_provider = strategy_provider or DefaultInvestigationStrategyProvider(
        settings.react_max_dynamic_turns if settings.react_enabled else 0
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
        runbook_limit=settings.runbook_limit,
        investigation_lease_seconds=settings.investigation_lease_seconds,
        react_enabled=settings.react_enabled,
        validation_enabled=settings.validation_enabled,
        shadow_enabled=settings.shadow_enabled,
    )
    return Runtime(
        settings=settings,
        repository=repository,
        service=service,
        runbook_provider=runbook_provider,
        runbook_store=runbook_store,
    )
