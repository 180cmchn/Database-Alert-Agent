from __future__ import annotations

import asyncio
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from app.adapters.runbooks import _parse_markdown, _runbook_directory_lock
from app.domain.models import RunbookDocument, utc_now

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_RESERVED_METADATA = {
    "id",
    "title",
    "section",
    "reasons",
    "keywords",
    "severities",
    "labels",
    "version",
    "updated_at",
}


class InvalidRunbookIdError(ValueError):
    pass


class RunbookNotFoundError(LookupError):
    pass


class RunbookConflictError(RuntimeError):
    pass


class LocalMarkdownRunbookStore:
    """CRUD store for the same Markdown/YAML format used by the search provider."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._lock = asyncio.Lock()

    async def list(self) -> list[RunbookDocument]:
        async with self._lock:
            return await asyncio.to_thread(self._list_locked_sync)

    async def get(self, runbook_id: str) -> RunbookDocument:
        path = self._path_for(runbook_id)
        async with self._lock:
            return await asyncio.to_thread(self._get_locked_sync, path, runbook_id)

    async def create(self, document: RunbookDocument) -> RunbookDocument:
        path = self._path_for(document.id)
        async with self._lock:
            return await asyncio.to_thread(self._create_locked_sync, path, document)

    async def update(
        self,
        runbook_id: str,
        document: RunbookDocument,
        *,
        expected_version: int | None = None,
    ) -> RunbookDocument:
        path = self._path_for(runbook_id)
        if document.id != runbook_id:
            raise InvalidRunbookIdError("Runbook ID in path and document must match")
        async with self._lock:
            return await asyncio.to_thread(
                self._update_locked_sync,
                path,
                runbook_id,
                document,
                expected_version,
            )

    async def delete(self, runbook_id: str) -> None:
        path = self._path_for(runbook_id)
        async with self._lock:
            await asyncio.to_thread(self._delete_locked_sync, path, runbook_id)

    def _list_locked_sync(self) -> list[RunbookDocument]:
        with _runbook_directory_lock(
            self._directory, exclusive=True, create_directory=True
        ):
            return self._list_sync()

    def _get_locked_sync(self, path: Path, runbook_id: str) -> RunbookDocument:
        with _runbook_directory_lock(
            self._directory, exclusive=True, create_directory=True
        ):
            return self._read_sync(path, runbook_id)

    def _create_locked_sync(
        self, path: Path, document: RunbookDocument
    ) -> RunbookDocument:
        with _runbook_directory_lock(
            self._directory, exclusive=True, create_directory=True
        ):
            if path.exists():
                raise RunbookConflictError(f"Runbook already exists: {document.id}")
            saved = document.model_copy(update={"version": 1, "updated_at": utc_now()})
            self._write_atomic_sync(path, saved)
            return saved

    def _update_locked_sync(
        self,
        path: Path,
        runbook_id: str,
        document: RunbookDocument,
        expected_version: int | None,
    ) -> RunbookDocument:
        with _runbook_directory_lock(
            self._directory, exclusive=True, create_directory=True
        ):
            if not path.exists():
                raise RunbookNotFoundError(f"Runbook not found: {runbook_id}")
            current = self._read_sync(path, runbook_id)
            if expected_version is not None and current.version != expected_version:
                raise RunbookConflictError(
                    f"Runbook version conflict: expected {expected_version}, "
                    f"current {current.version}"
                )
            saved = document.model_copy(
                update={"version": current.version + 1, "updated_at": utc_now()}
            )
            self._write_atomic_sync(path, saved)
            return saved

    def _delete_locked_sync(self, path: Path, runbook_id: str) -> None:
        with _runbook_directory_lock(
            self._directory, exclusive=True, create_directory=True
        ):
            if not path.exists():
                raise RunbookNotFoundError(f"Runbook not found: {runbook_id}")
            self._assert_regular_path(path)
            path.unlink()

    def _list_sync(self) -> list[RunbookDocument]:
        if not self._directory.exists():
            return []
        documents: list[RunbookDocument] = []
        for path in sorted(self._directory.glob("*.md")):
            if path.name.casefold() == "readme.md":
                continue
            documents.append(self._read_sync(path, path.stem))
        return documents

    def _read_sync(self, path: Path, requested_id: str) -> RunbookDocument:
        if not path.exists():
            raise RunbookNotFoundError(f"Runbook not found: {requested_id}")
        self._assert_regular_path(path)
        metadata, content = _parse_markdown(path)
        actual_id = str(metadata.get("id") or path.stem)
        if actual_id != path.stem:
            raise InvalidRunbookIdError(
                f"Runbook metadata ID must match its filename: {path.name}"
            )
        extras = {key: value for key, value in metadata.items() if key not in _RESERVED_METADATA}
        return RunbookDocument(
            id=actual_id,
            title=str(metadata.get("title") or actual_id),
            section=str(metadata.get("section") or "main"),
            reasons=self._string_list(metadata.get("reasons")),
            keywords=self._string_list(metadata.get("keywords")),
            severities=[item.upper() for item in self._string_list(metadata.get("severities"))],
            labels={
                str(key): str(value)
                for key, value in (metadata.get("labels") or {}).items()
            },
            content=content,
            metadata=extras,
            version=int(metadata.get("version") or 1),
            updated_at=metadata.get("updated_at") or path.stat().st_mtime,
        )

    def _path_for(self, runbook_id: str) -> Path:
        if (
            not _SAFE_RUNBOOK_ID.fullmatch(runbook_id)
            or runbook_id.casefold() == "readme"
        ):
            raise InvalidRunbookIdError(
                "Runbook ID must use 1-128 letters, digits, underscores or hyphens"
            )
        root = self._directory.resolve()
        path = self._directory / f"{runbook_id}.md"
        if path.resolve(strict=False).parent != root:
            raise InvalidRunbookIdError("Runbook path escapes the configured directory")
        return path

    def _assert_regular_path(self, path: Path) -> None:
        root = self._directory.resolve()
        if path.is_symlink() or path.resolve().parent != root or not path.is_file():
            raise InvalidRunbookIdError("Runbook path is not a regular managed file")

    def _write_atomic_sync(self, path: Path, document: RunbookDocument) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        metadata: dict[str, Any] = {
            **{
                key: value
                for key, value in document.metadata.items()
                if key not in _RESERVED_METADATA
            },
            "id": document.id,
            "title": document.title,
            "section": document.section,
            "reasons": document.reasons,
            "keywords": document.keywords,
            "severities": [item.upper() for item in document.severities],
            "labels": document.labels,
            "version": document.version,
            "updated_at": document.updated_at.isoformat(),
        }
        front_matter = yaml.safe_dump(
            metadata,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ).strip()
        rendered = f"---\n{front_matter}\n---\n\n{document.content.strip()}\n"
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".runbook-", suffix=".tmp", dir=self._directory
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            os.chmod(path, 0o600)
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ValueError("Runbook list metadata must be an array or string")
        return [str(item) for item in value]
