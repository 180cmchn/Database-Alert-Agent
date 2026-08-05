#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.adapters.pdf_runbooks import derive_runbook_alert_types
from app.domain.errors import RunbookError

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_LEGACY_REVIEW_FIELDS = frozenset(
    {
        "quality_status",
        "review_status",
        "review_notes",
        "visual_review_complete",
    }
)


def _remove_legacy_review_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _remove_legacy_review_fields(item)
            for key, item in value.items()
            if key not in _LEGACY_REVIEW_FIELDS
        }
    if isinstance(value, list):
        return [_remove_legacy_review_fields(item) for item in value]
    return value


def _sanitize_annotation(annotation: dict[str, Any]) -> dict[str, Any]:
    """Copy an annotation without legacy runbook review fields."""

    sanitized = _remove_legacy_review_fields(annotation)
    if (
        annotation.get("quality_status") == "deprecated"
        and "deprecated" not in annotation
    ):
        sanitized["deprecated"] = True
    return sanitized


def _read_source_index(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    if not path.exists():
        raise RunbookError(f"Source annotation index does not exist: {path}")
    if not path.is_file() or path.is_symlink():
        raise RunbookError(f"Runbook annotation index must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunbookError(f"Cannot read runbook annotation index: {path}") from exc
    if payload.get("schema_version") not in {1, 2, 3} or not isinstance(
        payload.get("runbooks"), list
    ):
        raise RunbookError(
            "Source annotation index must use schema_version=1, 2 or 3"
        )
    annotations: dict[str, dict[str, Any]] = {}
    for item in payload["runbooks"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("runbook_id"), str)
            or not _SAFE_RUNBOOK_ID.fullmatch(item["runbook_id"])
        ):
            raise RunbookError("Source annotation contains an invalid runbook_id")
        runbook_id = item["runbook_id"]
        if runbook_id in annotations:
            raise RunbookError(f"Duplicate source runbook annotation: {runbook_id}")
        annotations[runbook_id] = item
    return annotations


def _extract_text(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.suffix.casefold() != ".pdf":
        raise RunbookError(f"PDF runbook is not a regular source file: {path}")
    try:
        reader = PdfReader(str(path), strict=False)
        if reader.is_encrypted:
            raise RunbookError(f"Encrypted PDF runbook is not supported: {path.name}")
        text = "\n\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except RunbookError:
        raise
    except (OSError, PdfReadError, ValueError) as exc:
        raise RunbookError(f"Cannot read PDF runbook: {path.name}") from exc
    if len(text) < 20:
        raise RunbookError(
            f"PDF runbook has no usable text layer; OCR is required: {path.name}"
        )
    return text


def process_pdf_runbooks(
    source_pdf_dir: Path,
    source_index: Path | None,
    output_dir: Path,
) -> dict[str, Any]:
    """Classify flat source PDFs and emit one self-contained directory per type."""

    if not source_pdf_dir.is_dir():
        raise RunbookError(f"Source PDF directory does not exist: {source_pdf_dir}")
    if source_pdf_dir.resolve() == output_dir.resolve():
        raise RunbookError("Output directory must differ from the flat source directory")
    if output_dir.exists():
        raise RunbookError(f"Output directory already exists: {output_dir}")

    annotations = _read_source_index(source_index)
    source_pdfs = sorted(source_pdf_dir.glob("*.pdf"))
    if not source_pdfs:
        raise RunbookError(f"No source PDF runbooks found in: {source_pdf_dir}")

    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = defaultdict(list)
    source_ids: set[str] = set()
    for path in source_pdfs:
        if not _SAFE_RUNBOOK_ID.fullmatch(path.stem):
            raise RunbookError(f"PDF has an invalid runbook ID: {path.name}")
        source_ids.add(path.stem)
        source_annotation = _sanitize_annotation(
            dict(annotations.get(path.stem) or {"runbook_id": path.stem})
        )
        pdf_text = _extract_text(path)
        try:
            alert_types = derive_runbook_alert_types(pdf_text, source_annotation)
        except (RunbookError, ValueError) as exc:
            raise RunbookError(f"Cannot classify PDF {path.name}: {exc}") from exc

        source_annotation.pop("alert_types", None)
        source_annotation["runbook_id"] = path.stem
        for alert_type in alert_types:
            annotation = dict(source_annotation)
            annotation["alert_type"] = alert_type
            grouped[alert_type].append((path, annotation))

    unknown_annotations = set(annotations) - source_ids
    if unknown_annotations:
        raise RunbookError(
            "Source annotations reference missing PDFs: "
            + ", ".join(sorted(unknown_annotations))
        )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.processing-",
            dir=output_dir.parent,
        )
    )
    try:
        for alert_type, records in sorted(grouped.items()):
            type_directory = staging / alert_type
            type_directory.mkdir()
            for source_path, _ in records:
                shutil.copy2(source_path, type_directory / source_path.name)
            payload = {
                "schema_version": 3,
                "alert_type": alert_type,
                "runbooks": [annotation for _, annotation in records],
            }
            (type_directory / "index.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        staging.replace(output_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {
        "source_pdf_dir": str(source_pdf_dir),
        "source_index": str(source_index) if source_index is not None else None,
        "output_dir": str(output_dir),
        "runbook_count": len(source_pdfs),
        "emitted_runbook_count": sum(len(records) for records in grouped.values()),
        "alert_type_count": len(grouped),
        "alert_types": {
            alert_type: [path.stem for path, _ in records]
            for alert_type, records in sorted(grouped.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Classify flat PDF runbooks by their alert type and create per-type "
            "PDF/index directories"
        )
    )
    parser.add_argument(
        "--source-pdf-dir",
        type=Path,
        required=True,
        help="Flat directory containing the source PDF files",
    )
    parser.add_argument(
        "--source-index",
        type=Path,
        help=(
            "Optional source annotation index; use alert_types for a PDF that "
            "covers multiple alert types"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New output directory for per-alert-type PDF indexes",
    )
    args = parser.parse_args()

    report = process_pdf_runbooks(
        args.source_pdf_dir,
        args.source_index,
        args.output_dir,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
