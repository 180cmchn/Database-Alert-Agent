from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from app.domain.models import NormalizedAlert, Severity, utc_now


class IncidentState(StrEnum):
    PENDING = "PENDING"
    FIRING = "FIRING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class DeliveryState(StrEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class RoutingCondition(BaseModel):
    field: str | None = None
    equals: str | bool | None = None
    one_of: list[str] | None = None
    glob: str | None = None
    regex: str | None = None
    all: list[RoutingCondition] | None = None
    any: list[RoutingCondition] | None = None
    case_sensitive: bool = False

    @model_validator(mode="after")
    def validate_shape(self) -> RoutingCondition:
        groups = int(self.all is not None) + int(self.any is not None)
        operators = sum(
            item is not None for item in (self.equals, self.one_of, self.glob, self.regex)
        )
        if groups:
            if groups != 1 or self.field is not None or operators:
                raise ValueError("a condition group must contain exactly one of all/any")
            children = self.all if self.all is not None else self.any
            if not children:
                raise ValueError("condition groups cannot be empty")
        elif not self.field or operators != 1:
            raise ValueError("a leaf condition needs field and exactly one match operator")
        return self


class RoutingAction(BaseModel):
    channel: Literal["wecom_group", "wecom_card", "phone"]
    target: str | None = None
    recipient: str | None = None
    severities: list[Severity] = Field(default_factory=list)
    mention_on_call: bool = False


class EscalationStep(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    delay_seconds: int = Field(default=0, ge=0, le=86400)
    actions: list[RoutingAction] = Field(min_length=1)


class RoutingPolicy(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    priority: int
    hold_seconds: int = Field(default=0, ge=0, le=86400)
    match: RoutingCondition
    steps: list[EscalationStep] = Field(min_length=1)


class RoutingPolicySet(BaseModel):
    version: str = Field(min_length=1, max_length=100)
    timezone: str = "Asia/Shanghai"
    policies: list[RoutingPolicy] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_order(self) -> RoutingPolicySet:
        ids = [item.id for item in self.policies]
        if len(ids) != len(set(ids)):
            raise ValueError("routing policy ids must be unique")
        priorities = [item.priority for item in self.policies]
        if any(
            left <= right
            for left, right in zip(priorities, priorities[1:], strict=False)
        ):
            raise ValueError(
                "routing policies must be listed from high to low priority; "
                "priority values must be strictly descending"
            )
        return self


class AlertIncident(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    dedup_key: str
    alert_id: UUID
    policy_id: str
    policy_version: str
    policy_snapshot: RoutingPolicy | None = None
    severity: Severity
    state: IncidentState
    current_step: int = Field(default=0, ge=0)
    next_action_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    resolved_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class EscalationDelivery(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    step_index: int = Field(ge=0)
    action_index: int = Field(ge=0)
    channel: str
    target: str | None = None
    recipient: str | None = None
    state: DeliveryState = DeliveryState.PENDING
    attempts: int = Field(default=0, ge=0)
    external_delivery_id: str | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RoutingDecision(BaseModel):
    policy_id: str
    policy_version: str
    policy_name: str
    priority: int
    hold_seconds: int
    matched: bool = True


class DeliveryResult(BaseModel):
    state: DeliveryState
    recipient: str | None = None
    external_delivery_id: str | None = None
    acknowledged: bool = False
    acknowledged_by: str | None = None
    error: str | None = None


class RoutingContext(BaseModel):
    incident: AlertIncident
    alert: NormalizedAlert
    policy: RoutingPolicy
