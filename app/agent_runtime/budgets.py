"""Concurrency-safe hierarchical budgets for Agent and provider runs."""

from __future__ import annotations

from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

_COUNT_DIMENSIONS = (
    "planner_requests",
    "accepted_decisions",
    "remote_tool_calls",
    "host_bootstrap_calls",
    "session_attempts",
    "model_tokens",
)
_DIMENSIONS = (*_COUNT_DIMENSIONS, "wall_time_seconds")


class BudgetContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BudgetAmounts(BudgetContract):
    planner_requests: int = Field(default=0, ge=0)
    accepted_decisions: int = Field(default=0, ge=0)
    remote_tool_calls: int = Field(default=0, ge=0)
    host_bootstrap_calls: int = Field(default=0, ge=0)
    session_attempts: int = Field(default=0, ge=0)
    model_tokens: int = Field(default=0, ge=0)
    wall_time_seconds: float = Field(default=0, ge=0)

    def is_empty(self) -> bool:
        return all(getattr(self, dimension) == 0 for dimension in _DIMENSIONS)


class BudgetLimits(BudgetContract):
    planner_requests: int | None = Field(default=None, ge=0)
    accepted_decisions: int | None = Field(default=None, ge=0)
    remote_tool_calls: int | None = Field(default=None, ge=0)
    host_bootstrap_calls: int | None = Field(default=None, ge=0)
    session_attempts: int | None = Field(default=None, ge=0)
    model_tokens: int | None = Field(default=None, ge=0)
    wall_time_seconds: float | None = Field(default=None, ge=0)


class BudgetReservation(BudgetContract):
    reservation_id: UUID = Field(default_factory=uuid4)
    ledger_id: UUID
    amounts: BudgetAmounts


class BudgetSnapshot(BudgetContract):
    ledger_id: UUID
    parent_ledger_id: UUID | None = None
    limits: BudgetLimits
    consumed: BudgetAmounts
    reserved: BudgetAmounts
    remaining: BudgetLimits


class BudgetError(RuntimeError):
    """Base class for typed budget failures."""


class BudgetExceededError(BudgetError):
    def __init__(
        self,
        *,
        dimension: str,
        limit: int | float,
        consumed: int | float,
        reserved: int | float,
        requested: int | float,
    ) -> None:
        super().__init__(
            f"Budget exceeded for {dimension}: limit={limit}, consumed={consumed}, "
            f"reserved={reserved}, requested={requested}"
        )
        self.dimension = dimension
        self.limit = limit
        self.consumed = consumed
        self.reserved = reserved
        self.requested = requested


class ChildBudgetLimitError(BudgetError, ValueError):
    def __init__(
        self,
        *,
        dimension: str,
        child_limit: int | float,
        parent_remaining: int | float,
    ) -> None:
        super().__init__(
            f"Child budget for {dimension} ({child_limit}) exceeds parent remaining budget "
            f"({parent_remaining})"
        )
        self.dimension = dimension
        self.child_limit = child_limit
        self.parent_remaining = parent_remaining


class InvalidBudgetReservationError(BudgetError, ValueError):
    pass


class BudgetLedger:
    """Tracks reserved and consumed capacity across a hierarchy of runs.

    A child operation reserves the same capacity in its parent. This keeps
    sibling runs within the global budget even when they execute concurrently.
    """

    def __init__(
        self,
        limits: BudgetLimits | dict[str, Any] | None = None,
        *,
        parent: BudgetLedger | None = None,
        ledger_id: UUID | None = None,
    ) -> None:
        requested_limits = BudgetLimits.model_validate(limits or {})
        self.parent = parent
        self.ledger_id = ledger_id or uuid4()
        self._lock = RLock()
        self._consumed = {dimension: 0 for dimension in _DIMENSIONS}
        self._reserved = {dimension: 0 for dimension in _DIMENSIONS}
        self._reservations: dict[UUID, BudgetReservation] = {}
        self._parent_reservations: dict[UUID, BudgetReservation] = {}
        self.limits = self._bounded_child_limits(requested_limits, parent)

    @staticmethod
    def _bounded_child_limits(
        requested: BudgetLimits,
        parent: BudgetLedger | None,
    ) -> BudgetLimits:
        if parent is None:
            return requested
        parent_remaining = parent.snapshot().remaining
        bounded: dict[str, int | float | None] = {}
        for dimension in _DIMENSIONS:
            requested_limit = getattr(requested, dimension)
            available = getattr(parent_remaining, dimension)
            if requested_limit is None:
                bounded[dimension] = available
                continue
            if available is not None and requested_limit > available:
                raise ChildBudgetLimitError(
                    dimension=dimension,
                    child_limit=requested_limit,
                    parent_remaining=available,
                )
            bounded[dimension] = requested_limit
        return BudgetLimits.model_validate(bounded)

    def create_child(
        self,
        limits: BudgetLimits | dict[str, Any] | None = None,
        *,
        ledger_id: UUID | None = None,
    ) -> BudgetLedger:
        return BudgetLedger(limits, parent=self, ledger_id=ledger_id)

    @classmethod
    def from_snapshot(
        cls,
        snapshot: BudgetSnapshot,
        *,
        parent: BudgetLedger | None = None,
    ) -> BudgetLedger:
        """Restore settled consumption without detaching a child from its parent."""

        if not snapshot.reserved.is_empty():
            raise InvalidBudgetReservationError(
                "cannot restore a budget snapshot with unsettled reservations"
            )
        actual_parent_id = parent.ledger_id if parent is not None else None
        if snapshot.parent_ledger_id != actual_parent_id:
            raise ValueError(
                "restored budget parent does not match the checkpoint snapshot"
            )
        # Prior child consumption must already exist in the restored parent. Do
        # not reserve or debit it a second time; only future child debits flow up.
        ledger = cls(snapshot.limits, ledger_id=snapshot.ledger_id)
        ledger.parent = parent
        ledger._consumed = snapshot.consumed.model_dump(mode="python")
        if ledger.snapshot() != snapshot:
            raise ValueError("budget snapshot is internally inconsistent")
        return ledger

    def reserve(self, **amounts: int | float) -> BudgetReservation:
        requested = self._validated_amounts(amounts)
        with self._lock:
            self._ensure_capacity(requested)
            parent_reservation = (
                self.parent.reserve(**requested.model_dump()) if self.parent is not None else None
            )
            reservation = BudgetReservation(ledger_id=self.ledger_id, amounts=requested)
            for dimension in _DIMENSIONS:
                self._reserved[dimension] += getattr(requested, dimension)
            self._reservations[reservation.reservation_id] = reservation
            if parent_reservation is not None:
                self._parent_reservations[reservation.reservation_id] = parent_reservation
            return reservation

    def debit(
        self,
        reservation: BudgetReservation | None = None,
        **amounts: int | float,
    ) -> BudgetSnapshot:
        if reservation is None:
            temporary = self.reserve(**amounts)
            return self.debit(temporary)
        if amounts:
            raise ValueError("debit accepts either a reservation or dimension amounts, not both")
        with self._lock:
            stored = self._get_reservation(reservation)
            parent_reservation = self._parent_reservations.get(stored.reservation_id)
            if self.parent is not None and parent_reservation is not None:
                self.parent.debit(parent_reservation)
            for dimension in _DIMENSIONS:
                amount = getattr(stored.amounts, dimension)
                self._reserved[dimension] -= amount
                self._consumed[dimension] += amount
            self._reservations.pop(stored.reservation_id)
            self._parent_reservations.pop(stored.reservation_id, None)
            return self.snapshot()

    def release(self, reservation: BudgetReservation) -> BudgetSnapshot:
        with self._lock:
            stored = self._get_reservation(reservation)
            parent_reservation = self._parent_reservations.get(stored.reservation_id)
            if self.parent is not None and parent_reservation is not None:
                self.parent.release(parent_reservation)
            for dimension in _DIMENSIONS:
                self._reserved[dimension] -= getattr(stored.amounts, dimension)
            self._reservations.pop(stored.reservation_id)
            self._parent_reservations.pop(stored.reservation_id, None)
            return self.snapshot()

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            consumed = BudgetAmounts.model_validate(self._consumed)
            reserved = BudgetAmounts.model_validate(self._reserved)
            remaining: dict[str, int | float | None] = {}
            for dimension in _DIMENSIONS:
                limit = getattr(self.limits, dimension)
                if limit is None:
                    remaining[dimension] = None
                else:
                    remaining[dimension] = max(
                        0,
                        limit - self._consumed[dimension] - self._reserved[dimension],
                    )
            return BudgetSnapshot(
                ledger_id=self.ledger_id,
                parent_ledger_id=(
                    self.parent.ledger_id if self.parent is not None else None
                ),
                limits=self.limits,
                consumed=consumed,
                reserved=reserved,
                remaining=BudgetLimits.model_validate(remaining),
            )

    @staticmethod
    def _validated_amounts(amounts: dict[str, int | float]) -> BudgetAmounts:
        requested = BudgetAmounts.model_validate(amounts)
        if requested.is_empty():
            raise ValueError("at least one positive budget amount is required")
        return requested

    def _ensure_capacity(self, requested: BudgetAmounts) -> None:
        for dimension in _DIMENSIONS:
            limit = getattr(self.limits, dimension)
            if limit is None:
                continue
            consumed = self._consumed[dimension]
            reserved = self._reserved[dimension]
            amount = getattr(requested, dimension)
            if consumed + reserved + amount > limit:
                raise BudgetExceededError(
                    dimension=dimension,
                    limit=limit,
                    consumed=consumed,
                    reserved=reserved,
                    requested=amount,
                )

    def _get_reservation(self, reservation: BudgetReservation) -> BudgetReservation:
        if reservation.ledger_id != self.ledger_id:
            raise InvalidBudgetReservationError("reservation belongs to another budget ledger")
        stored = self._reservations.get(reservation.reservation_id)
        if stored is None:
            raise InvalidBudgetReservationError("reservation is unknown or already settled")
        if stored != reservation:
            raise InvalidBudgetReservationError("reservation payload does not match the ledger")
        return stored
