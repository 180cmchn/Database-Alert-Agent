from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import RUNTIME_SETTINGS_KEYS, Settings, load_runtime_overrides


class RuntimeSettingsManager:
    """Validate and atomically persist the administrative runtime whitelist."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._overrides = load_runtime_overrides(path)

    @property
    def revision(self) -> str:
        encoded = json.dumps(
            self._overrides, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(encoded).hexdigest()[:16]

    async def patch(
        self, current: Settings, updates: dict[str, Any]
    ) -> tuple[Settings, str, list[str]]:
        unexpected = set(updates) - RUNTIME_SETTINGS_KEYS
        if unexpected:
            raise ValueError(f"Runtime setting is not editable: {sorted(unexpected)[0]}")
        if not updates:
            return current, self.revision, []

        async with self._lock:
            candidate_overrides = {**self._overrides, **updates}
            candidate = Settings.model_validate(
                {**current.model_dump(mode="python"), **candidate_overrides}
            )
            current_values = current.model_dump(mode="json")
            serialized = candidate.model_dump(mode="json")
            changed_fields = sorted(
                key
                for key in updates
                if serialized.get(key) != current_values.get(key)
            )
            if not changed_fields:
                return current, self.revision, []
            persisted = {
                key: serialized[key]
                for key in {*self._overrides, *changed_fields}
                if key in RUNTIME_SETTINGS_KEYS
            }
            await asyncio.to_thread(self._write_atomic_sync, persisted)
            self._overrides = persisted
            return candidate, self.revision, changed_fields

    async def reload_if_changed(
        self, current: Settings
    ) -> tuple[Settings, bool, str]:
        """Refresh another process (for example the Kafka worker) from disk."""

        async with self._lock:
            overrides = await asyncio.to_thread(load_runtime_overrides, self.path)
            encoded = json.dumps(
                overrides, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
            revision = hashlib.sha256(encoded).hexdigest()[:16]
            if revision == self.revision:
                return current, False, revision
            updated = Settings.model_validate(
                {**current.model_dump(mode="python"), **overrides}
            )
            self._overrides = overrides
            return updated, True, revision

    def _write_atomic_sync(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            os.chmod(self.path, 0o600)
        finally:
            temporary_path.unlink(missing_ok=True)


class AdminAuditLogger:
    """Append mutation metadata without recording request values or secrets."""

    def __init__(self, runtime_settings_path: Path) -> None:
        self.path = runtime_settings_path.with_name(
            f"{runtime_settings_path.stem}.audit.jsonl"
        )
        self._lock = asyncio.Lock()

    async def record(
        self,
        *,
        action: str,
        target: str,
        fields: list[str] | None = None,
        actor: str = "admin",
        status: str = "success",
    ) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "fields": sorted(fields or []),
            "status": status,
        }
        async with self._lock:
            await asyncio.to_thread(self._append_sync, event)

    def _append_sync(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        file_descriptor = os.open(self.path, flags, 0o600)
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
