#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.adapters.pdf_runbooks import (
    alert_type_directory_name,
    derive_runbook_alert_types,
)
from app.domain.errors import RunbookError

_SAFE_RUNBOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_SEVERITY_PATTERN = re.compile(r"(?i)\[(critical|warning|info)\]")
_DATASET_FILENAMES = (
    "runbook_matching.jsonl",
    "root_cause_diagnosis.jsonl",
)


@dataclass(frozen=True)
class _PDFContent:
    text: str
    title: str
    page_count: int
    sha256: str


@dataclass(frozen=True)
class _RunbookSource:
    path: Path
    relative_path: str
    runbook_id: str
    alert_type: str
    alert_type_source: str
    annotation: dict[str, Any]
    content: _PDFContent


def _normalize_pdf_text(value: str) -> str:
    lines: list[str] = []
    for line in value.replace("\x00", "").splitlines():
        normalized = re.sub(r"[\t\r\f\v ]+", " ", line).strip()
        if normalized:
            lines.append(normalized)
    return "\n".join(lines)


def _title_from_pdf_text(text: str, fallback: str) -> str:
    for line in text.splitlines()[:20]:
        candidate = line.strip(" \t-—_:：")
        if len(candidate) >= 3 and not candidate.isdigit():
            return candidate[:300]
    return fallback[:300]


def _read_pdf(path: Path) -> _PDFContent:
    if not path.is_file() or path.is_symlink() or path.suffix.casefold() != ".pdf":
        raise RunbookError(f"PDF runbook is not a regular source file: {path}")
    try:
        reader = PdfReader(str(path), strict=False)
        if reader.is_encrypted:
            raise RunbookError(f"Encrypted PDF runbook is not supported: {path.name}")
        page_texts: list[str] = []
        for page_number, page in enumerate(reader.pages, start=1):
            try:
                page_texts.append(_normalize_pdf_text(page.extract_text() or ""))
            except Exception as exc:
                raise RunbookError(
                    f"Cannot extract text from {path.name} page {page_number}"
                ) from exc
    except RunbookError:
        raise
    except (OSError, PdfReadError, ValueError) as exc:
        raise RunbookError(f"Cannot read PDF runbook: {path.name}") from exc

    text = "\n\n".join(item for item in page_texts if item).strip()
    if len(text) < 20:
        raise RunbookError(
            f"PDF runbook has no usable text layer; OCR is required: {path.name}"
        )
    return _PDFContent(
        text=text,
        title=_title_from_pdf_text(text, path.stem),
        page_count=len(reader.pages),
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value if item is not None]
    else:
        return []
    return [item.strip() for item in values if item.strip()]


def _read_index(path: Path | None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if path is None:
        return {}, {}
    if not path.exists():
        raise RunbookError(f"Runbook annotation index does not exist: {path}")
    if not path.is_file() or path.is_symlink():
        raise RunbookError(f"Runbook annotation index must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunbookError(f"Cannot read runbook annotation index: {path}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") not in {1, 2, 3}
        or not isinstance(payload.get("runbooks"), list)
    ):
        raise RunbookError("Runbook annotation index must use schema_version=1, 2 or 3")

    annotations: dict[str, dict[str, Any]] = {}
    for raw_annotation in payload["runbooks"]:
        if not isinstance(raw_annotation, dict):
            raise RunbookError("Runbook annotation must be an object")
        runbook_id = raw_annotation.get("runbook_id")
        if not isinstance(runbook_id, str) or not _SAFE_RUNBOOK_ID.fullmatch(runbook_id):
            raise RunbookError("Runbook annotation contains an invalid runbook_id")
        if runbook_id in annotations:
            raise RunbookError(f"Duplicate runbook annotation: {runbook_id}")
        annotations[runbook_id] = raw_annotation
    return payload, annotations


def _validate_runbook_id(path: Path) -> str:
    if not _SAFE_RUNBOOK_ID.fullmatch(path.stem):
        raise RunbookError(f"PDF has an invalid runbook ID: {path.name}")
    return path.stem


def _derive_flat_alert_types(
    content: _PDFContent,
    annotation: dict[str, Any],
    *,
    strict_alert_types: bool,
) -> tuple[list[str], str]:
    structured_fields = {
        "alert_type",
        "alert_types",
    } & annotation.keys()
    match = annotation.get("match") or {}
    structured_match = isinstance(match, dict) and any(
        _string_values(match.get(field)) for field in ("alert_names", "metric_names")
    )
    if structured_fields or structured_match:
        return derive_runbook_alert_types(content.text, annotation), "source_index"

    try:
        title_alert_types = derive_runbook_alert_types(content.title)
    except (RunbookError, ValueError):
        title_alert_types = []
    if len(title_alert_types) == 1:
        return title_alert_types, "pdf_title"

    try:
        text_alert_types = derive_runbook_alert_types(content.text)
    except (RunbookError, ValueError) as exc:
        if strict_alert_types:
            raise RunbookError(
                "Cannot derive alert type from PDF text; provide a source index"
            ) from exc
        try:
            return [alert_type_directory_name(content.title)], "pdf_heading_fallback"
        except ValueError as exc:
            raise RunbookError(
                "Cannot derive alert type from PDF heading; provide a source index"
            ) from exc

    title_key = alert_type_directory_name(content.title)
    title_matches = [item for item in text_alert_types if item in title_key]
    if title_matches:
        best_match = max(title_matches, key=lambda item: (len(item), item))
        return [best_match], "pdf_text_title_match"
    if len(text_alert_types) == 1:
        return text_alert_types, "pdf_text"
    if strict_alert_types:
        raise RunbookError(
            "PDF text contains multiple alert types and its title does not select one; "
            "provide a source index"
        )
    return [title_key], "pdf_heading_fallback"


def _typed_sources(pdf_dir: Path) -> list[_RunbookSource]:
    sources: list[_RunbookSource] = []
    for directory in sorted(path for path in pdf_dir.iterdir() if path.is_dir()):
        if directory.is_symlink() or directory.name.startswith("."):
            continue
        try:
            alert_type = alert_type_directory_name(directory.name)
        except ValueError as exc:
            raise RunbookError(f"Invalid alert type directory: {directory.name}") from exc
        if alert_type != directory.name:
            raise RunbookError(f"Invalid alert type directory: {directory.name}")

        index_path = directory / "index.json"
        payload, annotations = _read_index(index_path if index_path.exists() else None)
        declared_alert_type = payload.get("alert_type")
        if declared_alert_type is not None:
            try:
                declared_key = alert_type_directory_name(str(declared_alert_type))
            except ValueError as exc:
                raise RunbookError(
                    f"Runbook annotation index has invalid alert_type: {index_path}"
                ) from exc
            if declared_key != alert_type:
                raise RunbookError(
                    "Runbook annotation alert_type does not match its directory: "
                    f"{index_path}"
                )

        pdf_paths = sorted(directory.glob("*.pdf"))
        pdf_ids = {_validate_runbook_id(path) for path in pdf_paths}
        unknown_annotations = set(annotations) - pdf_ids
        if unknown_annotations:
            raise RunbookError(
                "Runbook annotations reference missing PDFs: "
                + ", ".join(sorted(unknown_annotations))
            )
        for path in pdf_paths:
            runbook_id = path.stem
            content = _read_pdf(path)
            annotation = dict(
                annotations.get(runbook_id)
                or {"runbook_id": runbook_id, "alert_type": alert_type}
            )
            if annotations:
                declared_types = derive_runbook_alert_types(content.text, annotation)
                if alert_type not in declared_types:
                    raise RunbookError(
                        f"Runbook annotation does not include directory alert type: {path}"
                    )
            sources.append(
                _RunbookSource(
                    path=path,
                    relative_path=path.relative_to(pdf_dir).as_posix(),
                    runbook_id=runbook_id,
                    alert_type=alert_type,
                    alert_type_source="typed_directory",
                    annotation=annotation,
                    content=content,
                )
            )
    return sources


def _flat_sources(
    pdf_dir: Path,
    source_index: Path | None,
    *,
    strict_alert_types: bool,
) -> list[_RunbookSource]:
    if source_index is None and (pdf_dir / "index.json").exists():
        source_index = pdf_dir / "index.json"
    _, annotations = _read_index(source_index)
    pdf_paths = sorted(pdf_dir.glob("*.pdf"))
    pdf_ids = {_validate_runbook_id(path) for path in pdf_paths}
    unknown_annotations = set(annotations) - pdf_ids
    if unknown_annotations:
        raise RunbookError(
            "Runbook annotations reference missing PDFs: "
            + ", ".join(sorted(unknown_annotations))
        )

    sources: list[_RunbookSource] = []
    for path in pdf_paths:
        runbook_id = path.stem
        annotation = dict(annotations.get(runbook_id) or {"runbook_id": runbook_id})
        content = _read_pdf(path)
        alert_types, alert_type_source = _derive_flat_alert_types(
            content,
            annotation,
            strict_alert_types=strict_alert_types,
        )
        for alert_type in alert_types:
            sources.append(
                _RunbookSource(
                    path=path,
                    relative_path=path.relative_to(pdf_dir).as_posix(),
                    runbook_id=runbook_id,
                    alert_type=alert_type,
                    alert_type_source=alert_type_source,
                    annotation=annotation,
                    content=content,
                )
            )
    return sources


def _discover_sources(
    pdf_dir: Path,
    source_index: Path | None,
    *,
    strict_alert_types: bool,
) -> tuple[str, list[_RunbookSource]]:
    if not pdf_dir.is_dir():
        raise RunbookError(f"PDF runbook directory does not exist: {pdf_dir}")
    flat_pdfs = sorted(pdf_dir.glob("*.pdf"))
    typed_directories = [
        path
        for path in pdf_dir.iterdir()
        if path.is_dir() and not path.name.startswith(".") and list(path.glob("*.pdf"))
    ]
    if flat_pdfs and typed_directories:
        raise RunbookError("PDF directory cannot mix flat and alert-type layouts")
    if flat_pdfs:
        return (
            "flat",
            _flat_sources(
                pdf_dir,
                source_index,
                strict_alert_types=strict_alert_types,
            ),
        )
    if source_index is not None:
        raise RunbookError("--source-index is only supported for a flat PDF directory")
    sources = _typed_sources(pdf_dir)
    if not sources:
        raise RunbookError(f"No PDF runbooks found in: {pdf_dir}")
    return "typed", sources


def _case_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\x00".join(values).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _section_ids(annotation: dict[str, Any]) -> list[str]:
    raw_sections = annotation.get("sections") or []
    if not isinstance(raw_sections, list):
        raise RunbookError("Runbook annotation sections must be a list")
    if not raw_sections:
        return ["PDF"]
    section_ids: list[str] = []
    for section in raw_sections:
        section_id = section.get("id") if isinstance(section, dict) else None
        if not isinstance(section_id, str) or not section_id.strip():
            raise RunbookError("Runbook annotation section has an invalid id")
        if section_id in section_ids:
            raise RunbookError(f"Duplicate runbook section id: {section_id}")
        section_ids.append(section_id)
    return section_ids


def _causes(annotation: dict[str, Any], section_ids: list[str]) -> list[dict[str, Any]]:
    raw_causes = annotation.get("causes") or []
    if not isinstance(raw_causes, list):
        raise RunbookError("Runbook annotation causes must be a list")
    causes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cause in raw_causes:
        if not isinstance(cause, dict):
            raise RunbookError("Runbook annotation cause must be an object")
        cause_id = cause.get("cause_id")
        hypothesis = cause.get("hypothesis")
        if not isinstance(cause_id, str) or not cause_id.strip():
            raise RunbookError("Runbook annotation cause has an invalid cause_id")
        if not isinstance(hypothesis, str) or not hypothesis.strip():
            raise RunbookError(f"Runbook cause has no hypothesis: {cause_id}")
        if cause_id in seen:
            raise RunbookError(f"Duplicate runbook cause id: {cause_id}")
        referenced_sections = _string_values(cause.get("section_ids"))
        unknown_sections = set(referenced_sections) - set(section_ids)
        if unknown_sections:
            raise RunbookError(
                f"Runbook cause references unknown sections: {sorted(unknown_sections)}"
            )
        seen.add(cause_id)
        causes.append(cause)
    return causes


def _severity(text: str) -> str:
    matches = {match.group(1).upper() for match in _SEVERITY_PATTERN.finditer(text)}
    for value in ("CRITICAL", "WARNING", "INFO"):
        if value in matches:
            return value
    return "WARNING"


def _base_alert(source: _RunbookSource) -> dict[str, Any]:
    match = source.annotation.get("match") or {}
    if not isinstance(match, dict):
        raise RunbookError("Runbook annotation match must be an object")
    alert_names = _string_values(match.get("alert_names"))
    metric_names = _string_values(match.get("metric_names"))
    aliases = _string_values(match.get("aliases"))
    title = (alert_names or aliases or [source.content.title])[0]
    reason = (metric_names or alert_names or aliases or [source.alert_type])[0]
    alert: dict[str, Any] = {
        "severity": _severity(source.content.text),
        "title": title[:300],
        "reason": reason[:1000],
        "alert_type": source.alert_type,
        "alert_name": (alert_names or [title])[0][:300],
        "environment": "evaluation",
    }
    if metric_names:
        alert["metric_name"] = metric_names[0][:300]

    scope = source.annotation.get("scope") or {}
    if not isinstance(scope, dict):
        raise RunbookError("Runbook annotation scope must be an object")
    database_engines = _string_values(scope.get("database_engines"))
    if database_engines:
        alert["database"] = {"engine": database_engines[0]}
    components = _string_values(scope.get("components"))
    if components:
        alert["labels"] = {"component": components[0]}

    required_conditions = _string_values(match.get("required_conditions"))
    if required_conditions:
        alert["description"] = "; ".join(required_conditions)[:2000]
    return alert


def _source_metadata(source: _RunbookSource) -> dict[str, Any]:
    return {
        "kind": "pdf_runbook",
        "pdf_path": source.relative_path,
        "page_count": source.content.page_count,
        "content_sha256": source.content.sha256,
        "alert_type_source": source.alert_type_source,
    }


def _build_records(
    sources: list[_RunbookSource],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], int]:
    matching: list[dict[str, Any]] = []
    diagnosis: list[dict[str, Any]] = []
    skipped_no_causes: list[str] = []
    skipped_ineligible = 0
    seen_matching_ids: set[str] = set()
    seen_diagnosis_ids: set[str] = set()
    for source in sorted(
        sources,
        key=lambda item: (item.alert_type, item.runbook_id, item.relative_path),
    ):
        if source.annotation.get("deprecated") is True or source.annotation.get(
            "knowledge_type"
        ) == "incomplete":
            skipped_ineligible += 1
            continue
        section_ids = _section_ids(source.annotation)
        alert = _base_alert(source)
        metadata = _source_metadata(source)
        matching_id = _case_id(
            "pdf-match",
            source.alert_type,
            source.runbook_id,
            source.content.sha256,
        )
        if matching_id in seen_matching_ids:
            raise RunbookError(f"Duplicate generated matching case: {matching_id}")
        seen_matching_ids.add(matching_id)
        matching.append(
            {
                "case_id": matching_id,
                "alert": alert,
                "gold_runbook_ids": [source.runbook_id],
                "gold_sections": section_ids,
                "review_status": "review_required",
                "source": metadata,
            }
        )

        causes = _causes(source.annotation, section_ids)
        if not causes:
            skipped_no_causes.append(f"{source.alert_type}/{source.runbook_id}")
            continue
        for cause in causes:
            cause_id = str(cause["cause_id"])
            diagnosis_id = _case_id(
                "pdf-cause",
                source.alert_type,
                source.runbook_id,
                cause_id,
                source.content.sha256,
            )
            if diagnosis_id in seen_diagnosis_ids:
                raise RunbookError(f"Duplicate generated diagnosis case: {diagnosis_id}")
            seen_diagnosis_ids.add(diagnosis_id)
            diagnosis_alert = dict(alert)
            description_parts = [
                str(alert.get("description") or "").strip(),
                str(cause["hypothesis"]).strip(),
            ]
            diagnosis_alert["description"] = "\n".join(
                item for item in description_parts if item
            )[:2000]
            diagnosis.append(
                {
                    "case_id": diagnosis_id,
                    "alert": diagnosis_alert,
                    "gold_runbook_id": source.runbook_id,
                    "expected_cause_ids": [cause_id],
                    "review_status": "review_required",
                    "source": metadata,
                }
            )
    return matching, diagnosis, skipped_no_causes, skipped_ineligible


def _jsonl(records: list[dict[str, Any]]) -> str:
    if not records:
        return ""
    return "".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        for record in records
    )


def _write_datasets(
    output_dir: Path,
    matching: list[dict[str, Any]],
    diagnosis: list[dict[str, Any]],
    *,
    force: bool,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    targets = {name: output_dir / name for name in _DATASET_FILENAMES}
    existing = [path for path in targets.values() if path.exists()]
    if existing and not force:
        raise RunbookError(
            "Evaluation dataset already exists; pass --force to replace: "
            + ", ".join(str(path) for path in existing)
        )
    for path in existing:
        if not path.is_file() or path.is_symlink():
            raise RunbookError(f"Evaluation dataset is not a regular file: {path}")

    staging = Path(
        tempfile.mkdtemp(prefix=".evaluation-datasets-", dir=output_dir)
    )
    try:
        (staging / "runbook_matching.jsonl").write_text(
            _jsonl(matching),
            encoding="utf-8",
        )
        (staging / "root_cause_diagnosis.jsonl").write_text(
            _jsonl(diagnosis),
            encoding="utf-8",
        )
        for name, target in targets.items():
            (staging / name).replace(target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def generate_evaluation_datasets(
    pdf_dir: Path,
    output_dir: Path,
    *,
    source_index: Path | None = None,
    force: bool = False,
    strict_alert_types: bool = False,
) -> dict[str, Any]:
    """Generate deterministic, review-required JSONL cases from local PDF runbooks."""

    layout, sources = _discover_sources(
        pdf_dir,
        source_index,
        strict_alert_types=strict_alert_types,
    )
    matching, diagnosis, skipped_no_causes, skipped_ineligible = _build_records(sources)
    if not matching:
        raise RunbookError("No eligible PDF runbooks were available for dataset generation")
    _write_datasets(output_dir, matching, diagnosis, force=force)
    return {
        "pdf_dir": str(pdf_dir),
        "layout": layout,
        "source_index": str(source_index) if source_index is not None else None,
        "output_dir": str(output_dir),
        "pdf_count": len({source.path.resolve() for source in sources}),
        "matching_case_count": len(matching),
        "diagnosis_case_count": len(diagnosis),
        "skipped_ineligible_count": skipped_ineligible,
        "skipped_root_cause_runbooks": skipped_no_causes,
        "review_status": "review_required",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate review-required evaluation JSONL from PDF runbooks"
    )
    parser.add_argument("--pdf-dir", type=Path, default=Path("runbooks/pdfs"))
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("evaluation/datasets"),
    )
    parser.add_argument(
        "--source-index",
        type=Path,
        help="Optional legacy global index for a flat PDF directory",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing generated JSONL files",
    )
    parser.add_argument(
        "--strict-alert-types",
        action="store_true",
        help="Reject PDFs without an explicit or labelled alert type",
    )
    args = parser.parse_args()

    report = generate_evaluation_datasets(
        args.pdf_dir,
        args.output_dir,
        source_index=args.source_index,
        force=args.force,
        strict_alert_types=args.strict_alert_types,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
