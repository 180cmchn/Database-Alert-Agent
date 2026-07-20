from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

from app.domain.models import NormalizedAlert
from app.domain.routing import RoutingCondition, RoutingPolicy, RoutingPolicySet


class RoutingPolicyError(ValueError):
    pass


class RoutingPolicyLoader:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> RoutingPolicySet:
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            return RoutingPolicySet.model_validate(raw)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            raise RoutingPolicyError(f"Invalid routing policy file {self.path}: {exc}") from exc


class RoutingPolicyEngine:
    """Evaluate policies in file order and stop at the first match."""

    def __init__(self, policy_set: RoutingPolicySet) -> None:
        self.policy_set = policy_set

    def select(
        self, alert: NormalizedAlert, *, is_non_working_time: bool
    ) -> RoutingPolicy | None:
        for policy in self.policy_set.policies:
            if self._matches(policy.match, alert, is_non_working_time):
                return policy
        return None

    def _matches(
        self,
        condition: RoutingCondition,
        alert: NormalizedAlert,
        is_non_working_time: bool,
    ) -> bool:
        if condition.all is not None:
            return all(
                self._matches(item, alert, is_non_working_time) for item in condition.all
            )
        if condition.any is not None:
            return any(
                self._matches(item, alert, is_non_working_time) for item in condition.any
            )

        assert condition.field is not None
        value = self._field_value(alert, condition.field, is_non_working_time)
        if condition.equals is not None:
            if isinstance(condition.equals, bool):
                return bool(value) is condition.equals
            return self._text(value, condition.case_sensitive) == self._text(
                condition.equals, condition.case_sensitive
            )
        if condition.one_of is not None:
            actual = self._text(value, condition.case_sensitive)
            return actual in {
                self._text(item, condition.case_sensitive) for item in condition.one_of
            }
        if condition.glob is not None:
            return fnmatch.fnmatchcase(
                self._text(value, condition.case_sensitive),
                self._text(condition.glob, condition.case_sensitive),
            )
        if condition.regex is not None:
            flags = 0 if condition.case_sensitive else re.IGNORECASE
            return re.fullmatch(condition.regex, str(value or ""), flags=flags) is not None
        return False  # pragma: no cover - model validation prevents this

    @staticmethod
    def _text(value: Any, case_sensitive: bool) -> str:
        result = str(value or "")
        return result if case_sensitive else result.casefold()

    @staticmethod
    def _field_value(
        alert: NormalizedAlert, field: str, is_non_working_time: bool
    ) -> Any:
        if field == "is_non_working_time":
            return is_non_working_time
        if field == "severity":
            return alert.severity.value
        if hasattr(alert, field):
            value = getattr(alert, field)
            if value is not None:
                return value
        for mapping in (alert.labels, alert.attributes, alert.features, alert.raw_payload):
            if field in mapping:
                return mapping[field]
        return None
