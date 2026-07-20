from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from app.domain.errors import RunbookError
from app.domain.models import NormalizedAlert


@contextmanager
def _runbook_directory_lock(
    directory: Path,
    *,
    exclusive: bool,
    create_directory: bool = False,
) -> Iterator[None]:
    """Coordinate readers and CRUD writers across threads and API processes."""

    if create_directory:
        directory.mkdir(parents=True, exist_ok=True)
    if not directory.exists():
        raise RunbookError(f"Runbook directory does not exist: {directory}")
    lock_path = directory / ".runbooks.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RunbookError(f"Cannot open runbook directory lock: {directory}") from exc
    try:
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise RunbookError(f"Runbook directory lock is not a regular file: {lock_path}")
        os.fchmod(file_descriptor, 0o600)
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(file_descriptor, operation)
        yield
    finally:
        fcntl.flock(file_descriptor, fcntl.LOCK_UN)
        os.close(file_descriptor)


def _as_lower_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return [str(item).strip().lower() for item in value if str(item).strip()]


def _parse_markdown(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, text.strip()
    parts = text.split("---", 2)
    if len(parts) != 3:
        raise RunbookError(f"Invalid YAML front matter in {path}")
    try:
        metadata = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise RunbookError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(metadata, dict):
        raise RunbookError(f"Runbook metadata must be an object: {path}")
    return metadata, parts[2].strip()


def _score_runbook(metadata: dict[str, Any], content: str, alert: NormalizedAlert) -> float:
    semantic_score = 0.0
    reason = alert.reason.strip().lower()
    title_and_reason = f"{alert.title} {alert.reason} {alert.description}".lower()
    reasons = _as_lower_strings(metadata.get("reasons"))
    keywords = _as_lower_strings(metadata.get("keywords"))
    severities = {item.upper() for item in _as_lower_strings(metadata.get("severities"))}
    label_rules = metadata.get("labels") or {}

    for candidate in reasons:
        if reason == candidate:
            semantic_score += 10
        elif candidate in reason or reason in candidate:
            semantic_score += 6
    semantic_score += sum(3 for keyword in keywords if keyword in title_and_reason)

    # Content is a weak secondary match; explicit metadata remains authoritative.
    if reason and reason in content.lower():
        semantic_score += 1

    # Severity and labels describe applicability, but do not identify the alert
    # type. Treating either as a standalone hit makes every CRITICAL alert match
    # every CRITICAL runbook, so they only boost an existing semantic match.
    if semantic_score <= 0:
        return 0.0

    score = semantic_score
    if alert.severity.value in severities:
        score += 2
    if isinstance(label_rules, dict):
        for key, expected in label_rules.items():
            if alert.labels.get(str(key), "").lower() == str(expected).lower():
                score += 2
    return score
