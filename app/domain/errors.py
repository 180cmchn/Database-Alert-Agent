from __future__ import annotations


class AlertAgentError(Exception):
    """Base error for the application."""


class UnknownAlertSourceError(AlertAgentError):
    def __init__(self, source: str) -> None:
        super().__init__(f"Unknown alert source: {source}")
        self.source = source


class InvalidAlertPayloadError(AlertAgentError):
    pass


class AdvisorError(AlertAgentError):
    pass


class RunbookError(AlertAgentError):
    pass


class InvalidRunbookIdError(RunbookError, ValueError):
    pass


class RunbookNotFoundError(RunbookError, LookupError):
    pass


class RunbookConflictError(RunbookError, RuntimeError):
    pass


class NotificationError(AlertAgentError):
    pass


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
