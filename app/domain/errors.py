from __future__ import annotations

from app.domain.models import ModelFailure


class AlertAgentError(Exception):
    """Base error for the application."""


class UnknownAlertSourceError(AlertAgentError):
    def __init__(self, source: str) -> None:
        super().__init__(f"Unknown alert source: {source}")
        self.source = source


class InvalidAlertPayloadError(AlertAgentError):
    pass


class AdvisorError(AlertAgentError):
    def __init__(self, message: str, *, failure: ModelFailure | None = None) -> None:
        super().__init__(message)
        self.failure = failure


class AnalysisDispatchPausedError(AlertAgentError):
    def __init__(self, version: int, reason: str) -> None:
        super().__init__(reason)
        self.version = version
        self.reason = reason


class AnalysisSettingsRevisionConflict(AlertAgentError):
    def __init__(self, expected: str, current: str) -> None:
        super().__init__("AI settings changed during dispatch validation")
        self.expected = expected
        self.current = current


class NotificationError(AlertAgentError):
    def __init__(self, message: str, *, unknown_outcome: bool = False) -> None:
        super().__init__(message)
        self.unknown_outcome = unknown_outcome


class AnalysisFailedError(AlertAgentError):
    def __init__(self, alert_id: str, message: str) -> None:
        super().__init__(message)
        self.alert_id = alert_id
        self.message = message


class InvestigationLeaseUnavailableError(AlertAgentError):
    """The alert is already owned by a live investigation lease.

    Queue consumers must treat this as a deferred job rather than a successful
    duplicate or a dead-letter condition.
    """

    def __init__(self, alert_id: str) -> None:
        super().__init__(f"Investigation lease is still active for alert: {alert_id}")
        self.alert_id = alert_id


class AlertNotFoundError(AlertAgentError):
    def __init__(self, alert_id: str) -> None:
        super().__init__(f"Alert not found: {alert_id}")
        self.alert_id = alert_id
