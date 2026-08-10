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


class RunbookAlertTypeNotFoundError(RunbookError, LookupError):
    """The local corpus has no directory for the alert's normalized type."""

    def __init__(self, alert_type: str) -> None:
        super().__init__("匹配本地pdf失败，pdf中没有该类型告警的处理方法")
        self.alert_type = alert_type


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
