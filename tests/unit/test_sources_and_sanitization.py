import pytest

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.application.sanitization import REDACTED, sanitize, sanitize_alert, sanitize_text
from app.config import DEFAULT_SEVERITY_MAPPING
from app.domain.errors import InvalidAlertPayloadError
from app.domain.models import Severity


def test_severity_mapping_and_stable_fingerprint() -> None:
    adapter = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING)
    payload = {
        "severity": "p0",
        "title": "Connections exhausted",
        "reason": "connection_exhausted",
        "occurred_at": "2026-07-10T08:00:00Z",
        "database": {"engine": "postgresql", "instance": "orders"},
    }

    first = adapter.normalize(payload)
    second = adapter.normalize(payload)

    assert first.severity == Severity.CRITICAL
    assert first.external_id == second.external_id
    assert first.external_id.startswith("generated-")


def test_unknown_severity_is_preserved_and_conservatively_normalized() -> None:
    alert = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(
        {"severity": "vendor-special", "title": "x", "reason": "y"}
    )
    assert alert.raw_severity == "vendor-special"
    assert alert.severity == Severity.WARNING


@pytest.mark.parametrize("field", ["title", "reason"])
def test_required_text_rejects_whitespace(field: str) -> None:
    payload = {"severity": "HIGH", "title": "Title", "reason": "reason"}
    payload[field] = "   "

    with pytest.raises(InvalidAlertPayloadError):
        CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING).normalize(payload)


def test_incident_fingerprint_ignores_event_identity_and_occurrence_time() -> None:
    adapter = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING)
    common = {
        "environment": "production",
        "service_name": "orders-api",
        "alert_type": "connection_exhausted",
        "metric_name": "connection_usage_percent",
        "severity": "HIGH",
        "title": "Database connections exhausted",
        "reason": "connection_exhausted",
        "description": "Connection usage reached 95% on instance orders-primary",
        "database": {"engine": "postgresql", "instance": "orders-primary"},
    }

    first = adapter.normalize(
        {
            **common,
            "external_id": "event-1001",
            "occurred_at": "2026-07-10T08:00:00Z",
        }
    )
    second = adapter.normalize(
        {
            **common,
            "external_id": "event-1002",
            "occurred_at": "2026-07-10T09:00:00Z",
        }
    )

    assert first.external_id != second.external_id
    assert first.occurred_at != second.occurred_at
    assert first.incident_fingerprint == second.incident_fingerprint


def test_sensitive_data_is_recursively_redacted() -> None:
    payload = {
        "password": "clear-text",
        "nested": {"api_key": "abc", "note": "Bearer top.secret.token"},
        "dsn_value": "postgresql://user:pass@db/orders",
        "safe": "visible",
    }
    sanitized = sanitize(payload)
    assert sanitized["password"] == REDACTED
    assert sanitized["nested"]["api_key"] == REDACTED
    assert sanitized["nested"]["note"] == "Bearer ***REDACTED***"
    assert sanitized["dsn_value"] == REDACTED
    assert sanitized["safe"] == "visible"


@pytest.mark.parametrize(
    ("value", "secret"),
    [
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("Authorization=ApiKey top-secret", "top-secret"),
        ("Proxy-Authorization: Digest digest-secret", "digest-secret"),
        (
            'Proxy-Authorization: Digest username="u", realm="r", response="digest-secret"',
            "digest-secret",
        ),
        ("access_token=access-secret", "access-secret"),
        ("refresh-token: refresh-secret", "refresh-secret"),
        (
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=wecom-secret",
            "wecom-secret",
        ),
    ],
)
def test_sensitive_text_redacts_authorization_and_common_tokens(
    value: str, secret: str
) -> None:
    sanitized = sanitize_text(value)
    assert secret not in sanitized
    assert REDACTED in sanitized


def test_alert_is_sanitized_before_external_use() -> None:
    adapter = CanonicalAlertSourceAdapter(DEFAULT_SEVERITY_MAPPING)
    alert = adapter.normalize(
        {
            "external_id": "sensitive-1",
            "severity": "HIGH",
            "title": "token=secret-value",
            "reason": "leak",
            "features": {"authorization": "Bearer abc"},
        }
    )
    safe = sanitize_alert(alert)
    assert REDACTED in safe.title
    assert safe.features["authorization"] == REDACTED
    assert safe.raw_payload["features"]["authorization"] == REDACTED
