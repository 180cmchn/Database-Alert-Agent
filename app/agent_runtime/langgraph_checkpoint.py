"""LangGraph checkpointer backed by the investigation repository."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import Any
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)
from langgraph.checkpoint.serde.base import SerializerProtocol
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.agent_runtime.contracts import RunCheckpoint
from app.domain.ports import AlertRepository

_SCHEMA_VERSION = "langgraph-checkpoint-v1"
_CODEC = "jsonplus-msgpack-v1"


class LangGraphCheckpointDecodeError(RuntimeError):
    pass


class RepositoryLangGraphCheckpointer(BaseCheckpointSaver[int]):
    """Persist one investigation graph with lease-fenced, append-only checkpoints."""

    def __init__(
        self,
        repository: AlertRepository,
        *,
        run_id: UUID,
        manifest_hash: str,
        lease_owner: str,
        fencing_token: int,
        serde: SerializerProtocol | None = None,
    ) -> None:
        if not manifest_hash:
            raise ValueError("manifest_hash must not be empty")
        if not lease_owner:
            raise ValueError("lease_owner must not be empty")
        if fencing_token < 1:
            raise ValueError("fencing_token must be positive")
        super().__init__(serde=serde or JsonPlusSerializer())
        self.repository = repository
        self.run_id = run_id
        self.manifest_hash = manifest_hash
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self._write_lock = asyncio.Lock()

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        raise NotImplementedError("RepositoryLangGraphCheckpointer is async-only")

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        del config, filter, before, limit
        raise NotImplementedError("RepositoryLangGraphCheckpointer is async-only")

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        del config, checkpoint, metadata, new_versions
        raise NotImplementedError("RepositoryLangGraphCheckpointer is async-only")

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        del config, writes, task_id, task_path
        raise NotImplementedError("RepositoryLangGraphCheckpointer is async-only")

    def delete_thread(self, thread_id: str) -> None:
        del thread_id
        raise NotImplementedError("Agent harness checkpoints are append-only")

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id, checkpoint_ns = self._config_identity(config)
        namespace = self._repository_namespace(checkpoint_ns)
        checkpoint_id = get_checkpoint_id(config)
        if checkpoint_id is None:
            stored = await self.repository.load_checkpoint(thread_id, namespace=namespace)
        else:
            stored = await self.repository.load_checkpoint_by_id(
                thread_id,
                checkpoint_id,
                namespace=namespace,
            )
        if stored is None:
            return None
        return await self._to_tuple(stored, checkpoint_ns=checkpoint_ns)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        if config is None:
            thread_id = str(self.run_id)
            checkpoint_ns = ""
        else:
            thread_id, checkpoint_ns = self._config_identity(config)
        namespace = self._repository_namespace(checkpoint_ns)
        before_version: int | None = None
        if before is not None and (before_id := get_checkpoint_id(before)) is not None:
            before_stored = await self.repository.load_checkpoint_by_id(
                thread_id,
                before_id,
                namespace=namespace,
            )
            if before_stored is None:
                return
            before_version = before_stored.version
        stored_items = await self.repository.list_checkpoints(
            thread_id,
            namespace=namespace,
            before_version=before_version,
            limit=None,
        )
        emitted = 0
        for stored in stored_items:
            item = await self._to_tuple(stored, checkpoint_ns=checkpoint_ns)
            if filter and not all(item.metadata.get(key) == value for key, value in filter.items()):
                continue
            if limit is not None and emitted >= limit:
                return
            emitted += 1
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        del new_versions
        thread_id, checkpoint_ns = self._config_identity(config)
        namespace = self._repository_namespace(checkpoint_ns)
        checkpoint_id = str(checkpoint["id"])
        try:
            persisted_id = UUID(checkpoint_id)
        except ValueError as exc:
            raise ValueError("LangGraph checkpoint id must be a UUID") from exc
        parent_checkpoint_id = get_checkpoint_id(config)
        stored_metadata = get_checkpoint_metadata(config, metadata)
        state = self._encode_state(
            checkpoint,
            stored_metadata,
            parent_checkpoint_id=parent_checkpoint_id,
        )

        async with self._write_lock:
            existing = await self.repository.load_checkpoint_by_id(
                thread_id,
                checkpoint_id,
                namespace=namespace,
            )
            if existing is not None:
                self._validate_stored(existing)
                if existing.state != state:
                    raise RuntimeError(
                        "LangGraph checkpoint id was reused with different content: "
                        f"{checkpoint_id}"
                    )
                return self._checkpoint_config(
                    thread_id,
                    checkpoint_ns,
                    checkpoint_id,
                )

            latest = await self.repository.load_checkpoint(thread_id, namespace=namespace)
            expected_version = latest.version if latest is not None else 0
            stored = RunCheckpoint(
                checkpoint_id=persisted_id,
                run_id=self.run_id,
                namespace=namespace,
                version=expected_version + 1,
                sequence=max(int(stored_metadata.get("step", -1)) + 1, 0),
                state=state,
                manifest_hash=self.manifest_hash,
            )
            await self.repository.save_checkpoint(
                stored,
                expected_version=expected_version,
                lease_owner=self.lease_owner,
                fencing_token=self.fencing_token,
            )
        return self._checkpoint_config(thread_id, checkpoint_ns, checkpoint_id)

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id, _checkpoint_ns = self._config_identity(config)
        checkpoint_id = get_checkpoint_id(config)
        if checkpoint_id is None:
            raise ValueError("checkpoint_id is required when persisting LangGraph writes")
        encoded: list[dict[str, Any]] = []
        for index, (channel, value) in enumerate(writes):
            value_type, value_bytes = self.serde.dumps_typed(value)
            encoded.append(
                {
                    "task_id": task_id,
                    "write_index": WRITES_IDX_MAP.get(channel, index),
                    "channel": channel,
                    "value_type": value_type,
                    "value_base64": base64.b64encode(value_bytes).decode("ascii"),
                    "task_path": task_path,
                }
            )
        async with self._write_lock:
            await self.repository.put_checkpoint_writes(
                thread_id,
                checkpoint_id,
                encoded,
                lease_owner=self.lease_owner,
                fencing_token=self.fencing_token,
            )

    async def adelete_thread(self, thread_id: str) -> None:
        self._require_thread(thread_id)
        raise NotImplementedError("Agent harness checkpoints are append-only")

    async def _to_tuple(
        self,
        stored: RunCheckpoint,
        *,
        checkpoint_ns: str,
    ) -> CheckpointTuple:
        checkpoint, metadata, parent_checkpoint_id = self._decode_state(stored)
        writes = await self.repository.list_checkpoint_writes(
            str(self.run_id),
            str(stored.checkpoint_id),
        )
        pending_writes = [
            (
                write["task_id"],
                write["channel"],
                self.serde.loads_typed(
                    (
                        write["value_type"],
                        base64.b64decode(write["value_base64"], validate=True),
                    )
                ),
            )
            for write in writes
        ]
        config = self._checkpoint_config(
            str(self.run_id),
            checkpoint_ns,
            str(stored.checkpoint_id),
        )
        parent_config = (
            self._checkpoint_config(
                str(self.run_id),
                checkpoint_ns,
                parent_checkpoint_id,
            )
            if parent_checkpoint_id is not None
            else None
        )
        return CheckpointTuple(
            config=config,
            checkpoint=checkpoint,
            metadata=metadata,
            parent_config=parent_config,
            pending_writes=pending_writes,
        )

    def _encode_state(
        self,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        *,
        parent_checkpoint_id: str | None,
    ) -> dict[str, Any]:
        checkpoint_type, checkpoint_bytes = self.serde.dumps_typed(checkpoint)
        metadata_type, metadata_bytes = self.serde.dumps_typed(metadata)
        return {
            "schema_version": _SCHEMA_VERSION,
            "codec": _CODEC,
            "checkpoint": {
                "type": checkpoint_type,
                "payload_base64": base64.b64encode(checkpoint_bytes).decode("ascii"),
            },
            "metadata": {
                "type": metadata_type,
                "payload_base64": base64.b64encode(metadata_bytes).decode("ascii"),
            },
            "parent_checkpoint_id": parent_checkpoint_id,
        }

    def _decode_state(
        self,
        stored: RunCheckpoint,
    ) -> tuple[Checkpoint, CheckpointMetadata, str | None]:
        self._validate_stored(stored)
        state = stored.state
        checkpoint = self._decode_typed(state.get("checkpoint"), label="checkpoint")
        metadata = self._decode_typed(state.get("metadata"), label="metadata")
        if not isinstance(checkpoint, dict):
            raise LangGraphCheckpointDecodeError("decoded checkpoint is not an object")
        if not isinstance(metadata, dict):
            raise LangGraphCheckpointDecodeError("decoded checkpoint metadata is not an object")
        parent_checkpoint_id = state.get("parent_checkpoint_id")
        if parent_checkpoint_id is not None and not isinstance(parent_checkpoint_id, str):
            raise LangGraphCheckpointDecodeError("parent checkpoint id is invalid")
        return checkpoint, metadata, parent_checkpoint_id

    def _decode_typed(self, value: Any, *, label: str) -> Any:
        if not isinstance(value, Mapping):
            raise LangGraphCheckpointDecodeError(f"stored {label} payload is missing")
        value_type = value.get("type")
        payload_base64 = value.get("payload_base64")
        if not isinstance(value_type, str) or not isinstance(payload_base64, str):
            raise LangGraphCheckpointDecodeError(f"stored {label} payload is incomplete")
        try:
            payload = base64.b64decode(payload_base64, validate=True)
            return self.serde.loads_typed((value_type, payload))
        except Exception as exc:
            raise LangGraphCheckpointDecodeError(
                f"stored {label} payload could not be decoded"
            ) from exc

    def _validate_stored(self, stored: RunCheckpoint) -> None:
        if stored.run_id != self.run_id:
            raise LangGraphCheckpointDecodeError("checkpoint belongs to another run")
        if stored.manifest_hash != self.manifest_hash:
            raise LangGraphCheckpointDecodeError(
                "checkpoint manifest does not match the current run"
            )
        if stored.state.get("schema_version") != _SCHEMA_VERSION:
            raise LangGraphCheckpointDecodeError("checkpoint schema version is unsupported")
        if stored.state.get("codec") != _CODEC:
            raise LangGraphCheckpointDecodeError("checkpoint codec is unsupported")

    def _config_identity(self, config: RunnableConfig) -> tuple[str, str]:
        configurable = config.get("configurable")
        if not isinstance(configurable, Mapping):
            raise ValueError("LangGraph checkpoint config requires configurable values")
        thread_id = configurable.get("thread_id")
        if not isinstance(thread_id, str):
            raise ValueError("LangGraph checkpoint config requires a string thread_id")
        self._require_thread(thread_id)
        checkpoint_ns = configurable.get("checkpoint_ns", "")
        if not isinstance(checkpoint_ns, str):
            raise ValueError("LangGraph checkpoint_ns must be a string")
        return thread_id, checkpoint_ns

    def _require_thread(self, thread_id: str) -> None:
        if thread_id != str(self.run_id):
            raise ValueError("LangGraph thread_id must match the investigation run id")

    @staticmethod
    def _repository_namespace(checkpoint_ns: str) -> str:
        namespace = "agent" if not checkpoint_ns else f"agent:{checkpoint_ns}"
        if len(namespace) > 256 or "\x00" in namespace:
            raise ValueError("LangGraph checkpoint namespace is invalid")
        return namespace

    @staticmethod
    def _checkpoint_config(
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
    ) -> RunnableConfig:
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        }
