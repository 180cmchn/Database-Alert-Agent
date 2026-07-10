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


class NotificationError(AlertAgentError):
    pass


class AnalysisFailedError(AlertAgentError):
    def __init__(self, alert_id: str, message: str) -> None:
        super().__init__(message)
        self.alert_id = alert_id
        self.message = message


class AlertNotFoundError(AlertAgentError):
    def __init__(self, alert_id: str) -> None:
        super().__init__(f"Alert not found: {alert_id}")
        self.alert_id = alert_id
