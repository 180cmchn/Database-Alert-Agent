from __future__ import annotations

from dataclasses import dataclass

from app.adapters.ai import FakeAIAdvisor, OpenAICompatibleAdvisor
from app.adapters.alert_sources import AlertSourceRegistry, CanonicalAlertSourceAdapter
from app.adapters.notification import LogManagementNotifier, WebhookManagementNotifier
from app.adapters.persistence import SQLAlchemyAlertRepository
from app.adapters.runbooks import LocalMarkdownRunbookProvider
from app.application.service import AlertAnalysisService
from app.config import Settings
from app.domain.ports import AIAdvisor, AlertRepository, ManagementNotifier, RunbookProvider


@dataclass
class Runtime:
    settings: Settings
    repository: AlertRepository
    service: AlertAnalysisService


def build_runtime(
    settings: Settings,
    *,
    repository: AlertRepository | None = None,
    advisor: AIAdvisor | None = None,
    notifier: ManagementNotifier | None = None,
    runbook_provider: RunbookProvider | None = None,
    source_registry: AlertSourceRegistry | None = None,
) -> Runtime:
    repository = repository or SQLAlchemyAlertRepository(settings.database_url)
    source_registry = source_registry or AlertSourceRegistry(
        [CanonicalAlertSourceAdapter(settings.severity_mapping)]
    )
    runbook_provider = runbook_provider or LocalMarkdownRunbookProvider(settings.runbook_dir)

    if advisor is None:
        if settings.ai_provider == "fake":
            advisor = FakeAIAdvisor()
        else:
            advisor = OpenAICompatibleAdvisor(
                api_key=settings.ai_api_key,
                base_url=settings.ai_base_url,
                model=settings.ai_model,
                timeout_seconds=settings.ai_timeout_seconds,
                max_retries=settings.ai_max_retries,
                json_mode=settings.ai_json_mode,
            )

    if notifier is None:
        if settings.notifier_mode == "webhook":
            notifier = WebhookManagementNotifier(
                settings.management_webhook_url,
                settings.management_webhook_bearer_token,
            )
        else:
            notifier = LogManagementNotifier()

    service = AlertAnalysisService(
        source_registry=source_registry,
        runbook_provider=runbook_provider,
        advisor=advisor,
        notifier=notifier,
        repository=repository,
        escalation_severities={item.value for item in settings.escalation_severities},
        runbook_limit=settings.runbook_limit,
        notification_max_attempts=settings.notification_max_attempts,
        notification_backoff_seconds=settings.notification_retry_backoff_seconds,
    )
    return Runtime(settings=settings, repository=repository, service=service)
