from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import RUNTIME_SETTINGS_KEYS, Settings, load_runtime_overrides

try:  # Unix file locking.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None

try:  # Windows file locking.
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised on Unix
    _msvcrt = None

_FCHMOD = getattr(os, "fchmod", None)


def _restrict_file_descriptor(file_descriptor: int) -> None:
    """Apply owner-only permissions where the operating system supports them."""

    if _FCHMOD is not None:
        _FCHMOD(file_descriptor, 0o600)


def _acquire_file_lock(file_descriptor: int) -> None:
    if _fcntl is not None:
        _fcntl.flock(file_descriptor, _fcntl.LOCK_EX)
        return
    if _msvcrt is not None:
        # msvcrt locks a byte range starting at the current file position. Keep a
        # stable byte in the lock file so every Windows process locks the same range.
        if os.fstat(file_descriptor).st_size == 0:
            os.write(file_descriptor, b"\0")
            os.fsync(file_descriptor)
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        _msvcrt.locking(file_descriptor, _msvcrt.LK_LOCK, 1)
        return
    raise RuntimeError("No supported file-locking backend is available")


def _release_file_lock(file_descriptor: int) -> None:
    if _fcntl is not None:
        _fcntl.flock(file_descriptor, _fcntl.LOCK_UN)
        return
    if _msvcrt is not None:
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        _msvcrt.locking(file_descriptor, _msvcrt.LK_UNLCK, 1)
        return
    raise RuntimeError("No supported file-locking backend is available")


def _revision_for(overrides: dict[str, Any]) -> str:
    encoded = json.dumps(
        overrides, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def runtime_configuration_issues(settings: Settings) -> list[str]:
    """Return non-sensitive issues that prevent a usable runtime configuration."""

    issues = list(settings.readiness_issues())
    if settings.ai_provider == "openai_compatible":
        if not settings.ai_api_key.strip():
            issues.append("AI_API_KEY is required for openai_compatible provider")
        if not settings.ai_model.strip():
            issues.append("AI_MODEL is required for openai_compatible provider")
    if settings.app_env.lower() in {"production", "prod"} and settings.ai_provider == "fake":
        issues.append("AI_PROVIDER=fake is not allowed in production")
    return list(dict.fromkeys(issues))


class RuntimeSettingsConflictError(RuntimeError):
    def __init__(self, *, expected_revision: str, current_revision: str) -> None:
        super().__init__(
            "Runtime settings changed; reload them before retrying "
            f"(expected={expected_revision}, current={current_revision})"
        )
        self.expected_revision = expected_revision
        self.current_revision = current_revision


class RuntimeSettingsManager:
    """Validate and atomically persist the administrative runtime whitelist."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._overrides = load_runtime_overrides(path)

    @property
    def revision(self) -> str:
        return _revision_for(self._overrides)

    async def patch(
        self,
        current: Settings,
        updates: dict[str, Any],
        *,
        expected_revision: str,
    ) -> tuple[Settings, str, list[str]]:
        updates = updates.copy()
        if not expected_revision:
            raise ValueError("expected_revision is required")
        unexpected = set(updates) - RUNTIME_SETTINGS_KEYS
        if unexpected:
            raise ValueError(f"Runtime setting is not editable: {sorted(unexpected)[0]}")

        async with self._lock:
            candidate, persisted, revision, changed_fields = await asyncio.to_thread(
                self._patch_locked_sync,
                current,
                updates,
                expected_revision,
            )
            self._overrides = persisted
            return candidate, revision, changed_fields

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
            if revision == _revision_for(self._overrides):
                return current, False, revision
            updated = Settings.model_validate(
                {**current.model_dump(mode="python"), **overrides}
            )
            self._validate_runnable(updated)
            self._overrides = overrides
            return updated, True, revision

    def _patch_locked_sync(
        self,
        current: Settings,
        updates: dict[str, Any],
        expected_revision: str,
    ) -> tuple[Settings, dict[str, Any], str, list[str]]:
        with self._settings_file_lock_sync():
            latest_overrides = load_runtime_overrides(self.path)
            latest_revision = _revision_for(latest_overrides)
            if expected_revision != latest_revision:
                raise RuntimeSettingsConflictError(
                    expected_revision=expected_revision,
                    current_revision=latest_revision,
                )

            effective_current = Settings.model_validate(
                {**current.model_dump(mode="python"), **latest_overrides}
            )
            candidate_overrides = {**latest_overrides, **updates}
            candidate = Settings.model_validate(
                {**current.model_dump(mode="python"), **candidate_overrides}
            )
            self._validate_runnable(candidate)
            current_values = effective_current.model_dump(mode="json")
            serialized = candidate.model_dump(mode="json")
            changed_fields = sorted(
                key
                for key in updates
                if serialized.get(key) != current_values.get(key)
            )
            if not changed_fields:
                return effective_current, latest_overrides, latest_revision, []

            persisted = {
                key: serialized[key]
                for key in {*latest_overrides, *changed_fields}
                if key in RUNTIME_SETTINGS_KEYS
            }
            self._write_atomic_sync(persisted)
            return candidate, persisted, _revision_for(persisted), changed_fields

    @contextmanager
    def _settings_file_lock_sync(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(lock_path, flags, 0o600)
        locked = False
        try:
            if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
                raise ValueError("Runtime settings lock is not a regular file")
            _restrict_file_descriptor(file_descriptor)
            _acquire_file_lock(file_descriptor)
            locked = True
            yield
        finally:
            if locked:
                _release_file_lock(file_descriptor)
            os.close(file_descriptor)

    @staticmethod
    def _validate_runnable(settings: Settings) -> None:
        blocking: list[str] = []
        if settings.ai_provider == "openai_compatible":
            if not settings.ai_api_key.strip():
                blocking.append("AI API key is required for openai_compatible provider")
            if not settings.ai_model.strip():
                blocking.append("AI model is required for openai_compatible provider")
        if (
            settings.app_env.lower() in {"production", "prod"}
            and not settings.wecom_webhook_url.strip()
        ):
            blocking.append("WeCom webhook URL is required in production")
        if (
            settings.app_env.lower() in {"production", "prod"}
            and settings.ai_provider == "fake"
        ):
            blocking.append("Fake AI provider is not allowed in production")
        if (
            settings.app_env.lower() in {"production", "prod"}
            and not settings.shadow_enabled
            and not settings.production_gate_approved
        ):
            blocking.append(
                "Production gate approval is required before disabling shadow mode"
            )
        if settings.external_knowledge_enabled and not settings.external_knowledge_base_url.strip():
            blocking.append("External knowledge base URL is required when external knowledge is enabled")
        if blocking:
            raise ValueError("; ".join(blocking))

    def _write_atomic_sync(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            _restrict_file_descriptor(file_descriptor)
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
        _restrict_file_descriptor(file_descriptor)
        with os.fdopen(file_descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
