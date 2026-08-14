#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
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
from app.adapters.runbook_indexing import (
    RUNBOOK_INDEX_PROMPT_VERSION,
    OpenAICompatibleRunbookIndexer,
)
from app.config import REAL_AI_PROVIDERS, get_settings
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


def _extract_pages(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink() or path.suffix.casefold() != ".pdf":
        raise RunbookError(f"PDF runbook is not a regular source file: {path}")
    try:
        reader = PdfReader(str(path), strict=False)
        if reader.is_encrypted:
            raise RunbookError(f"Encrypted PDF runbook is not supported: {path.name}")
        pages = [page.extract_text() or "" for page in reader.pages]
    except RunbookError:
        raise
    except (OSError, PdfReadError, ValueError) as exc:
        raise RunbookError(f"Cannot read PDF runbook: {path.name}") from exc
    text = "\n\n".join(pages).strip()
    if len(text) < 20:
        raise RunbookError(
            f"PDF runbook has no usable text layer; OCR is required: {path.name}"
        )
    return pages


def _extract_text(path: Path) -> str:
    return "\n\n".join(_extract_pages(path)).strip()


def _content_sha256(pages: list[str]) -> str:
    return hashlib.sha256("\n\n".join(pages).encode("utf-8")).hexdigest()


def _apply_runtime_output_gate(
    report: dict[str, Any],
    runtime_pdf_dir: Path,
    generated_output_dir: Path,
) -> None:
    matches_generated_output = (
        runtime_pdf_dir.resolve() == generated_output_dir.resolve()
    )
    report["runtime_configuration"] = {
        "runbook_pdf_dir": str(runtime_pdf_dir),
        "generated_output_dir": str(generated_output_dir),
        "matches_generated_output": matches_generated_output,
    }
    if matches_generated_output:
        return

    gate = report["acceptance"]["production_gate"]
    gate["passed"] = False
    gate["failures"].append(
        f"RUNBOOK_PDF_DIR={runtime_pdf_dir} does not point to generated output: "
        f"{generated_output_dir}"
    )


def _has_structured_alert_types(annotation: dict[str, Any]) -> bool:
    if "alert_type" in annotation or "alert_types" in annotation:
        return True
    match = annotation.get("match") or {}
    if not isinstance(match, dict):
        return False
    return any(match.get(field) for field in ("alert_names", "metric_names"))


def _load_generated_annotation_cache(output_dir: Path) -> dict[str, dict[str, Any]]:
    if not output_dir.is_dir() or output_dir.is_symlink():
        return {}
    cached: dict[str, dict[str, Any]] = {}
    alert_types_by_id: dict[str, set[str]] = defaultdict(set)
    invalid_ids: set[str] = set()
    for index_path in sorted(output_dir.glob("*/index.json")):
        if not index_path.is_file() or index_path.is_symlink():
            continue
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or not isinstance(payload.get("runbooks"), list):
            continue
        for raw_annotation in payload["runbooks"]:
            if not isinstance(raw_annotation, dict):
                continue
            runbook_id = raw_annotation.get("runbook_id")
            alert_type = raw_annotation.get("alert_type")
            auto_index = (raw_annotation.get("metadata") or {}).get("auto_index") or {}
            if (
                not isinstance(runbook_id, str)
                or not isinstance(alert_type, str)
                or not isinstance(auto_index, dict)
                or not isinstance(auto_index.get("content_sha256"), str)
            ):
                continue
            if runbook_id in invalid_ids:
                continue
            candidate = dict(raw_annotation)
            candidate.pop("alert_type", None)
            existing = cached.get(runbook_id)
            if existing is not None and existing != candidate:
                cached.pop(runbook_id, None)
                alert_types_by_id.pop(runbook_id, None)
                invalid_ids.add(runbook_id)
                continue
            cached[runbook_id] = candidate
            alert_types_by_id[runbook_id].add(alert_type)
    for runbook_id, annotation in list(cached.items()):
        alert_types = sorted(alert_types_by_id.get(runbook_id) or [])
        if not alert_types:
            cached.pop(runbook_id, None)
            continue
        annotation["alert_types"] = alert_types
    return cached


async def _generate_auto_annotations(
    source_pdf_dir: Path,
    source_index: Path | None,
    output_dir: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    source_annotations = _read_source_index(source_index)
    cache = _load_generated_annotation_cache(output_dir)
    settings = get_settings()
    generated: dict[str, dict[str, Any]] = {}
    pending: list[tuple[Path, list[str]]] = []
    cache_hits = 0
    source_paths = await asyncio.to_thread(
        lambda: sorted(source_pdf_dir.glob("*.pdf"))
    )
    for path in source_paths:
        if not _SAFE_RUNBOOK_ID.fullmatch(path.stem):
            raise RunbookError(f"PDF has an invalid runbook ID: {path.name}")
        source_annotation = source_annotations.get(path.stem) or {}
        if _has_structured_alert_types(source_annotation):
            continue
        pages = await asyncio.to_thread(_extract_pages, path)
        digest = _content_sha256(pages)
        cached = cache.get(path.stem)
        cached_auto_index = ((cached or {}).get("metadata") or {}).get(
            "auto_index"
        ) or {}
        cache_matches = (
            bool(cached)
            and cached_auto_index.get("content_sha256") == digest
            and cached_auto_index.get("prompt_version")
            == RUNBOOK_INDEX_PROMPT_VERSION
            and cached_auto_index.get("generator") == settings.ai_provider
            and (
                not settings.ai_model
                or cached_auto_index.get("model") == settings.ai_model
            )
        )
        if cache_matches:
            generated[path.stem] = cached or {}
            cache_hits += 1
            continue
        pending.append((path, pages))

    if pending and settings.ai_provider not in REAL_AI_PROVIDERS:
        raise RunbookError(
            "Automatic PDF indexing requires AI_PROVIDER=openai_compatible "
            "or AI_PROVIDER=openai_responses"
        )
    if pending:
        indexer = OpenAICompatibleRunbookIndexer(
            provider=settings.ai_provider,
            api_key=settings.ai_api_key,
            base_url=settings.ai_base_url,
            model=settings.ai_model,
            max_tokens=settings.ai_max_tokens,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
            json_mode=settings.ai_json_mode,
        )
        try:
            for path, pages in pending:
                try:
                    generated[path.stem] = await indexer.generate_annotation(
                        path.stem,
                        pages,
                    )
                except RunbookError as exc:
                    raise RunbookError(
                        f"Cannot automatically index PDF {path.name}: {exc}"
                    ) from exc
        finally:
            await indexer.aclose()
    return generated, {
        "cache_hits": cache_hits,
        "model_indexed_pdfs": len(pending),
    }


def _install_staged_output(staging: Path, output_dir: Path) -> None:
    """Install a complete staging tree without replacing an existing directory.

    Windows can reject ``os.replace`` for a directory tree when a file watcher or
    antivirus briefly opens one of its children. Once the old output has been
    moved aside, a non-overwriting rename is preferred; a copy is the portable
    fallback when Windows still denies the directory rename.
    """

    if output_dir.exists():
        raise RunbookError(
            f"Cannot install generated output because target still exists: {output_dir}"
        )
    try:
        staging.rename(output_dir)
        return
    except PermissionError:
        if output_dir.exists():
            raise
    try:
        shutil.copytree(staging, output_dir, copy_function=shutil.copy2)
    except Exception:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise
    shutil.rmtree(staging, ignore_errors=True)


def process_pdf_runbooks(
    source_pdf_dir: Path,
    source_index: Path | None,
    output_dir: Path,
    *,
    generated_annotations: dict[str, dict[str, Any]] | None = None,
    replace_output: bool = False,
) -> dict[str, Any]:
    """Classify flat source PDFs and emit one self-contained directory per type."""

    if not source_pdf_dir.is_dir():
        raise RunbookError(f"Source PDF directory does not exist: {source_pdf_dir}")
    if source_pdf_dir.resolve() == output_dir.resolve():
        raise RunbookError("Output directory must differ from the flat source directory")
    if output_dir.exists() and not replace_output:
        raise RunbookError(f"Output directory already exists: {output_dir}")
    if output_dir.exists() and (
        not output_dir.is_dir() or output_dir.is_symlink()
    ):
        raise RunbookError(f"Output path must be a regular directory: {output_dir}")

    annotations = _read_source_index(source_index)
    generated_annotations = generated_annotations or {}
    source_pdfs = sorted(source_pdf_dir.glob("*.pdf"))
    if not source_pdfs:
        raise RunbookError(f"No source PDF runbooks found in: {source_pdf_dir}")

    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = defaultdict(list)
    source_ids: set[str] = set()
    for path in source_pdfs:
        if not _SAFE_RUNBOOK_ID.fullmatch(path.stem):
            raise RunbookError(f"PDF has an invalid runbook ID: {path.name}")
        source_ids.add(path.stem)
        generated_annotation = dict(generated_annotations.get(path.stem) or {})
        source_annotation = _sanitize_annotation(
            {
                **generated_annotation,
                **dict(annotations.get(path.stem) or {}),
                "runbook_id": path.stem,
            }
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
    unknown_generated = set(generated_annotations) - source_ids
    if unknown_generated:
        raise RunbookError(
            "Generated annotations reference missing PDFs: "
            + ", ".join(sorted(unknown_generated))
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
        backup: Path | None = None
        if output_dir.exists():
            backup = Path(
                tempfile.mkdtemp(
                    prefix=f".{output_dir.name}.backup-",
                    dir=output_dir.parent,
                )
            )
            backup.rmdir()
            output_dir.rename(backup)
        try:
            _install_staged_output(staging, output_dir)
        except Exception as install_error:
            shutil.rmtree(output_dir, ignore_errors=True)
            if backup is not None and backup.exists():
                if output_dir.exists():
                    raise RunbookError(
                        "Cannot remove partial generated output or restore the "
                        f"previous output; backup remains at: {backup}"
                    ) from install_error
                try:
                    backup.rename(output_dir)
                except OSError as rollback_error:
                    raise RunbookError(
                        "Cannot restore the previous generated output; backup "
                        f"remains at: {backup}"
                    ) from rollback_error
            raise
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    report = {
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
    if generated_annotations:
        report["generated_annotation_count"] = len(generated_annotations)
    return report


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
    parser.add_argument(
        "--auto-index",
        action="store_true",
        help=(
            "Use the configured AI model to extract all handled alert types and "
            "structured annotations from PDFs without explicit source annotations"
        ),
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Atomically replace an existing generated output directory",
    )
    parser.add_argument(
        "--skip-evaluation-datasets",
        action="store_true",
        help="Do not synchronize generated evaluation cases after --auto-index",
    )
    parser.add_argument(
        "--evaluation-output-dir",
        type=Path,
        default=Path("evaluation/datasets"),
        help="Evaluation dataset directory synchronized after --auto-index",
    )
    parser.add_argument(
        "--gates",
        type=Path,
        default=Path("policies/production-gates.json"),
        help="Coverage-based production gate policy",
    )
    parser.add_argument(
        "--enforce-gates",
        action="store_true",
        help="Return a non-zero exit code when generated acceptance cases fail",
    )
    args = parser.parse_args()
    if args.enforce_gates and (
        not args.auto_index or args.skip_evaluation_datasets
    ):
        parser.error("--enforce-gates requires --auto-index with evaluation enabled")

    generated_annotations: dict[str, dict[str, Any]] = {}
    auto_index_report: dict[str, int] = {}
    if args.auto_index:
        generated_annotations, auto_index_report = asyncio.run(
            _generate_auto_annotations(
                args.source_pdf_dir,
                args.source_index,
                args.output_dir,
            )
        )
    report = process_pdf_runbooks(
        args.source_pdf_dir,
        args.source_index,
        args.output_dir,
        generated_annotations=generated_annotations,
        replace_output=args.sync,
    )
    if args.auto_index:
        report["auto_index"] = auto_index_report
        if not args.skip_evaluation_datasets:
            from tools.generate_evaluation_datasets import (
                generate_evaluation_datasets,
            )

            report["evaluation"] = generate_evaluation_datasets(
                args.output_dir,
                args.evaluation_output_dir,
                sync=True,
            )
            from tools.evaluate_runbooks import _gate_report, evaluate

            settings = get_settings()
            evaluation_report = asyncio.run(
                evaluate(
                    argparse.Namespace(
                        pdf_dir=args.output_dir,
                        matching_dataset=(
                            args.evaluation_output_dir / "runbook_matching.jsonl"
                        ),
                        diagnosis_dataset=(
                            args.evaluation_output_dir
                            / "root_cause_diagnosis.jsonl"
                        ),
                        min_score=settings.runbook_match_min_score,
                        min_confidence=settings.runbook_match_min_confidence,
                    )
                )
            )
            gates = json.loads(args.gates.read_text(encoding="utf-8"))
            evaluation_report["production_gate"] = _gate_report(
                evaluation_report,
                gates,
            )
            report["acceptance"] = evaluation_report
            _apply_runtime_output_gate(
                report,
                settings.runbook_pdf_dir,
                args.output_dir,
            )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.enforce_gates and not report["acceptance"]["production_gate"]["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
