"""Durable codec and checkpoint hook for MCP investigations."""

from __future__ import annotations

import base64
import re
from typing import Any
from uuid import UUID

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.agent_runtime.budgets import BudgetSnapshot
from app.agent_runtime.contracts import RunCheckpoint
from app.domain.ports import AlertRepository
from app.mcp_runtime.contracts import MCPHarnessSnapshot

_PROVIDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CODEC = "jsonplus-msgpack-v2"


class MCPCheckpointDecodeError(RuntimeError):
    pass


class RepositoryMCPCheckpointStore[StateT, ObservationT]:
    """Persist and restore one provider's complete investigation snapshot."""

    def __init__(
        self,
        repository: AlertRepository,
        *,
        provider: str,
        manifest_hash: str,
        dispatch_id: UUID | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
        serializer: JsonPlusSerializer | None = None,
    ) -> None:
        if not _PROVIDER.fullmatch(provider):
            raise ValueError("provider contains unsupported characters")
        if not manifest_hash:
            raise ValueError("manifest_hash must not be empty")
        if (lease_owner is None) != (fencing_token is None):
            raise ValueError("lease_owner and fencing_token must be provided together")
        self.repository = repository
        self.provider = provider
        self.dispatch_id = dispatch_id
        self.namespace = (
            f"mcp:{provider}:{dispatch_id}"
            if dispatch_id is not None
            else f"mcp:{provider}"
        )
        self.manifest_hash = manifest_hash
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self.serializer = serializer or JsonPlusSerializer()

    async def __call__(
        self,
        snapshot: MCPHarnessSnapshot[StateT, ObservationT],
    ) -> None:
        latest = await self.repository.load_checkpoint(
            str(snapshot.run_id),
            namespace=self.namespace,
        )
        expected_version = latest.version if latest is not None else 0
        type_tag, encoded = self.serializer.dumps_typed(snapshot)
        checkpoint = RunCheckpoint(
            run_id=snapshot.run_id,
            namespace=self.namespace,
            version=expected_version + 1,
            sequence=snapshot.event_version,
            state={
                "codec": _CODEC,
                "type": type_tag,
                "payload_base64": base64.b64encode(encoded).decode("ascii"),
            },
            budget_snapshot=snapshot.budget.model_dump(mode="json"),
            manifest_hash=self.manifest_hash,
            stop_reason=(snapshot.finish.reason if snapshot.finish is not None else None),
        )
        await self.repository.save_checkpoint(
            checkpoint,
            expected_version=expected_version,
            lease_owner=self.lease_owner,
            fencing_token=self.fencing_token,
        )

    async def load(
        self,
        run_id: UUID,
    ) -> MCPHarnessSnapshot[StateT, ObservationT] | None:
        checkpoint = await self.repository.load_checkpoint(
            str(run_id),
            namespace=self.namespace,
        )
        if checkpoint is None:
            return None
        if checkpoint.manifest_hash != self.manifest_hash:
            raise MCPCheckpointDecodeError(
                "MCP checkpoint manifest does not match the current run"
            )
        state = checkpoint.state
        if state.get("codec") != _CODEC:
            raise MCPCheckpointDecodeError("MCP checkpoint uses an unsupported codec")
        type_tag = state.get("type")
        payload_base64 = state.get("payload_base64")
        if not isinstance(type_tag, str) or not isinstance(payload_base64, str):
            raise MCPCheckpointDecodeError("MCP checkpoint payload is incomplete")
        try:
            payload = base64.b64decode(payload_base64, validate=True)
            decoded = self.serializer.loads_typed((type_tag, payload))
        except Exception as exc:
            raise MCPCheckpointDecodeError("MCP checkpoint payload could not be decoded") from exc
        snapshot = self._normalize_snapshot(decoded)
        if snapshot.run_id != run_id:
            raise MCPCheckpointDecodeError("MCP checkpoint belongs to another run")
        if snapshot.event_version != checkpoint.sequence:
            raise MCPCheckpointDecodeError("MCP checkpoint event sequence does not match")
        stored_budget = BudgetSnapshot.model_validate(checkpoint.budget_snapshot)
        if snapshot.budget != stored_budget:
            raise MCPCheckpointDecodeError("MCP checkpoint budget snapshot does not match")
        return snapshot

    @staticmethod
    def _normalize_snapshot(value: Any) -> MCPHarnessSnapshot[StateT, ObservationT]:
        required = (
            "run_id",
            "parent_run_id",
            "state",
            "messages",
            "observations",
            "invocations",
            "tool_specs",
            "fingerprints",
            "budget",
            "finish",
            "event_version",
            "deadline",
        )
        if not all(hasattr(value, field) for field in required):
            raise MCPCheckpointDecodeError("decoded MCP checkpoint has an invalid shape")
        return MCPHarnessSnapshot(
            run_id=value.run_id,
            parent_run_id=value.parent_run_id,
            state=value.state,
            messages=tuple(value.messages),
            observations=tuple(value.observations),
            invocations=tuple(value.invocations),
            tool_specs=tuple(value.tool_specs),
            fingerprints=frozenset(value.fingerprints),
            budget=value.budget,
            finish=value.finish,
            event_version=value.event_version,
            deadline=value.deadline,
            wall_time_deadline=getattr(value, "wall_time_deadline", None),
            pending_retry=getattr(value, "pending_retry", None),
            retry_not_before=getattr(value, "retry_not_before", None),
            active_call=getattr(value, "active_call", None),
            remote_responses=tuple(getattr(value, "remote_responses", ())),
        )
