from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import yaml

from app.domain.errors import RunbookError
from app.domain.models import NormalizedAlert, RunbookExcerpt


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
    score = 0.0
    reason = alert.reason.lower()
    title_and_reason = f"{alert.title} {alert.reason} {alert.description}".lower()
    reasons = _as_lower_strings(metadata.get("reasons"))
    keywords = _as_lower_strings(metadata.get("keywords"))
    severities = {item.upper() for item in _as_lower_strings(metadata.get("severities"))}
    label_rules = metadata.get("labels") or {}

    for candidate in reasons:
        if reason == candidate:
            score += 10
        elif candidate in reason or reason in candidate:
            score += 6
    score += sum(3 for keyword in keywords if keyword in title_and_reason)
    if alert.severity.value in severities:
        score += 2
    if isinstance(label_rules, dict):
        for key, expected in label_rules.items():
            if alert.labels.get(str(key), "").lower() == str(expected).lower():
                score += 2

    # Content is a weak secondary match; explicit metadata remains authoritative.
    if reason and reason in content.lower():
        score += 1
    return score


class LocalMarkdownRunbookProvider:
    def __init__(self, directory: Path) -> None:
        self._directory = directory

    async def search(self, alert: NormalizedAlert, limit: int = 5) -> list[RunbookExcerpt]:
        return await asyncio.to_thread(self._search_sync, alert, limit)

    def _search_sync(self, alert: NormalizedAlert, limit: int) -> list[RunbookExcerpt]:
        if not self._directory.exists():
            raise RunbookError(f"Runbook directory does not exist: {self._directory}")

        matches: list[RunbookExcerpt] = []
        for path in sorted(self._directory.glob("*.md")):
            if path.name.lower() == "readme.md":
                continue
            metadata, content = _parse_markdown(path)
            score = _score_runbook(metadata, content, alert)
            if score <= 0:
                continue
            matches.append(
                RunbookExcerpt(
                    runbook_id=str(metadata.get("id") or path.stem),
                    title=str(metadata.get("title") or path.stem),
                    section=str(metadata.get("section") or "main"),
                    content=content,
                    score=score,
                    metadata=metadata,
                )
            )
        matches.sort(key=lambda item: (-item.score, item.runbook_id))
        return matches[:limit]
