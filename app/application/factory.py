from __future__ import annotations

from dataclasses import dataclass

from app.adapters.ai import (
    FakeAIAdvisor,
    FakeConclusionValidator,
    OpenAICompatibleAdvisor,
    OpenAICompatibleConclusionValidator,
)
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
from app.adapters.escalation import EnterpriseWeComDirectory, EscalationDispatcher
from app.adapters.investigation import (
    DefaultInvestigationStrategyProvider,
    InvestigationToolRegistry,
    ToolExecutor,
    build_default_tool_registry,
)
from app.adapters.notification import (
    LogManagementNotifier,
    WebhookManagementNotifier,
    WeComManagementNotifier,
)
from app.adapters.persistence import SQLAlchemyAlertRepository
from app.adapters.runbook_store import LocalMarkdownRunbookStore
from app.adapters.web_runbooks import AuthenticatedWebRunbookProvider
from app.application.escalation import AlertRoutingService, DurableEscalationScheduler
from app.application.routing_policy import RoutingPolicyEngine, RoutingPolicyLoader
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
    routing_service: AlertRoutingService | None = None
    escalation_scheduler: DurableEscalationScheduler | None = None


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
    if settings.notifier_mode == "wecom":
        return WeComManagementNotifier(settings.wecom_webhook_url)
    if settings.notifier_mode == "webhook":
        return WebhookManagementNotifier(
            settings.management_webhook_url,
            settings.management_webhook_bearer_token,
        )
    if settings.notifier_mode == "log":
        return LogManagementNotifier()
    raise ValueError(f"Unsupported notifier mode: {settings.notifier_mode}")


def _resolve_runbook_adapters(
    settings: Settings,
    provider: RunbookProvider | None,
    store: RunbookStore | None,
) -> tuple[RunbookProvider, RunbookStore]:
    """Resolve one searchable and administrable runbook corpus as an atomic pair."""

    if provider is None and store is None:
        return (
            AuthenticatedWebRunbookProvider(
                settings.runbook_dir,
                allowed_hosts=settings.runbook_web_allowed_hosts,
                auth_mode=settings.runbook_web_auth_mode,
                auth_secret=settings.runbook_web_auth_secret.get_secret_value(),
                timeout_seconds=settings.runbook_web_timeout_seconds,
                cache_ttl_seconds=settings.runbook_web_cache_ttl_seconds,
                max_response_bytes=settings.runbook_web_max_response_bytes,
                verify_tls=settings.runbook_web_verify_tls,
                require_https=settings.app_env.lower() in {"production", "prod"},
            ),
            LocalMarkdownRunbookStore(settings.runbook_dir),
        )
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
    service.escalation_severities = {
        item.value.upper() for item in settings.escalation_severities
    }
    service.runbook_limit = settings.runbook_limit
    service.notification_max_attempts = settings.notification_max_attempts
    service.notification_backoff_seconds = settings.notification_retry_backoff_seconds
    service.react_enabled = settings.react_enabled
    service.validation_enabled = settings.validation_enabled
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
    routing_service: AlertRoutingService | None = None
    escalation_scheduler: DurableEscalationScheduler | None = None
    if settings.alert_routing_enabled and isinstance(
        repository, SQLAlchemyAlertRepository
    ):
        policy_set = RoutingPolicyLoader(settings.alert_routing_policy_path).load()
        policy_engine = RoutingPolicyEngine(policy_set)
        directory = EnterpriseWeComDirectory(
            settings.wecom_oncall_api_url,
            settings.wecom_oncall_api_bearer_token.get_secret_value(),
            settings.fallback_oncall,
            timezone=settings.alert_routing_timezone,
        )
        dispatcher = EscalationDispatcher(
            group_webhook_urls=settings.alert_group_webhook_urls,
            card_api_url=settings.wecom_card_api_url,
            card_api_bearer_token=(
                settings.wecom_card_api_bearer_token.get_secret_value()
            ),
            ack_callback_base_url=settings.wecom_ack_callback_base_url,
            ack_callback_token=settings.wecom_ack_callback_token.get_secret_value(),
            phone_api_url=settings.phone_notification_api_url,
            phone_api_bearer_token=(
                settings.phone_notification_api_bearer_token.get_secret_value()
            ),
            directory=directory,
        )
        routing_service = AlertRoutingService(
            repository=repository,
            policy_engine=policy_engine,
            directory=directory,
        )
        escalation_scheduler = DurableEscalationScheduler(
            routing_repository=repository,
            alert_repository=repository,
            routing_service=routing_service,
            dispatcher=dispatcher,
            poll_seconds=settings.alert_routing_poll_seconds,
        )
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
        escalation_severities={item.value for item in settings.escalation_severities},
        runbook_limit=settings.runbook_limit,
        notification_max_attempts=settings.notification_max_attempts,
        notification_backoff_seconds=settings.notification_retry_backoff_seconds,
        investigation_lease_seconds=settings.investigation_lease_seconds,
        react_enabled=settings.react_enabled,
        validation_enabled=settings.validation_enabled,
        signal_router=routing_service,
    )
    return Runtime(
        settings=settings,
        repository=repository,
        service=service,
        runbook_provider=runbook_provider,
        runbook_store=runbook_store,
        routing_service=routing_service,
        escalation_scheduler=escalation_scheduler,
    )
