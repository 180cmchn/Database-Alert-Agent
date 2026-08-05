#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.domain.errors import RunbookAlertTypeNotFoundError
from app.domain.models import RunbookKnowledgeType


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Expected an object at {path}:{line_number}")
        records.append(value)
    return records


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _coverage_ratio(numerator: int, denominator: int) -> float:
    """Treat an empty set of required targets as fully covered."""

    return round(numerator / denominator, 4) if denominator else 1.0


def _metadata_strings(metadata: dict[str, Any], key: str) -> list[str]:
    value = metadata.get(key)
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


async def _search(
    library: LocalPDFRunbookLibrary,
    alert: Any,
) -> list[Any]:
    try:
        return await library.search(alert, limit=5)
    except RunbookAlertTypeNotFoundError:
        return []


async def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    adapter = CanonicalAlertSourceAdapter()
    library = LocalPDFRunbookLibrary(
        args.pdf_dir,
        min_score=args.min_score,
        min_confidence=args.min_confidence,
    )
    matching_cases = _load_jsonl(args.matching_dataset)
    diagnosis_cases = _load_jsonl(args.diagnosis_dataset)

    match_total = 0
    top_one_hits = 0
    recall_hits = 0
    section_hits = 0
    no_match_total = 0
    no_match_hits = 0
    evaluated_runbook_types: set[tuple[str, str]] = set()
    evaluated_causes: set[tuple[str, str]] = set()
    generated_case_count = 0
    fresh_generated_case_count = 0
    failures: list[dict[str, Any]] = []
    for case in matching_cases:
        alert = adapter.normalize({"external_id": case["case_id"], **case["alert"]})
        results = await _search(library, alert)
        retrieved_ids = [item.runbook_id for item in results]
        gold_ids = list(case.get("gold_runbook_ids") or [])
        case_alert_type = str(case["alert"].get("alert_type") or "")
        evaluated_runbook_types.update(
            (str(runbook_id), case_alert_type) for runbook_id in gold_ids
        )
        if not gold_ids:
            no_match_total += 1
            if not results:
                no_match_hits += 1
            else:
                failures.append(
                    {
                        "case_id": case["case_id"],
                        "failure": "false_positive",
                        "retrieved": retrieved_ids,
                    }
                )
            continue
        match_total += 1
        if retrieved_ids and retrieved_ids[0] in gold_ids:
            top_one_hits += 1
        if set(retrieved_ids) & set(gold_ids):
            recall_hits += 1
        gold_sections = set(case.get("gold_sections") or [])
        if any(
            item.runbook_id in gold_ids and (not gold_sections or item.section in gold_sections)
            for item in results
        ):
            section_hits += 1
        if not set(retrieved_ids) & set(gold_ids):
            failures.append(
                {"case_id": case["case_id"], "failure": "miss", "retrieved": retrieved_ids}
            )

    cause_expected = 0
    cause_found = 0
    for case in diagnosis_cases:
        alert = adapter.normalize({"external_id": case["case_id"], **case["alert"]})
        results = await _search(library, alert)
        result = next(
            (item for item in results if item.runbook_id == case["gold_runbook_id"]), None
        )
        available = {cause.cause_id for cause in result.causes} if result else set()
        expected = set(case.get("expected_cause_ids") or [])
        evaluated_causes.update(
            (str(case["gold_runbook_id"]), str(cause_id))
            for cause_id in expected
        )
        cause_expected += len(expected)
        cause_found += len(expected & available)
        if not expected.issubset(available):
            failures.append(
                {
                    "case_id": case["case_id"],
                    "failure": "cause_coverage",
                    "missing": sorted(expected - available),
                }
            )

    documents = await library.list()
    eligible = [
        item
        for item in documents
        if item.knowledge_type != RunbookKnowledgeType.INCOMPLETE
        and not item.deprecated
    ]
    eligible_runbook_types = {
        (str(getattr(item, "id", "")), alert_type)
        for item in eligible
        for alert_type in (
            _metadata_strings(getattr(item, "metadata", {}), "alert_types")
            or _metadata_strings(getattr(item, "metadata", {}), "alert_type")
        )
        if getattr(item, "id", "")
    }
    eligible_causes = {
        (str(getattr(item, "id", "")), cause.cause_id)
        for item in eligible
        for cause in getattr(item, "causes", [])
        if getattr(item, "id", "")
    }
    current_hashes = {
        (str(getattr(item, "id", "")), alert_type): str(
            getattr(item, "metadata", {}).get("content_sha256") or ""
        )
        for item in eligible
        for alert_type in (
            _metadata_strings(getattr(item, "metadata", {}), "alert_types")
            or _metadata_strings(getattr(item, "metadata", {}), "alert_type")
        )
        if getattr(item, "id", "")
    }
    for case in [*matching_cases, *diagnosis_cases]:
        source = case.get("source") or {}
        if not isinstance(source, dict) or source.get("kind") != "pdf_runbook":
            continue
        generated_case_count += 1
        alert_type = str(case.get("alert", {}).get("alert_type") or "")
        source_alert_type = str(source.get("source_alert_type") or alert_type)
        runbook_ids = list(case.get("gold_runbook_ids") or [])
        if not runbook_ids and case.get("gold_runbook_id"):
            runbook_ids = [case["gold_runbook_id"]]
        if not runbook_ids:
            pdf_path = str(source.get("pdf_path") or "")
            runbook_id = Path(pdf_path).stem if pdf_path else ""
            runbook_ids = [runbook_id] if runbook_id else []
        expected_hash = str(source.get("content_sha256") or "")
        if expected_hash and runbook_ids and all(
            current_hashes.get((str(runbook_id), source_alert_type)) == expected_hash
            for runbook_id in runbook_ids
        ):
            fresh_generated_case_count += 1
        else:
            failures.append(
                {
                    "case_id": case.get("case_id"),
                    "failure": "stale_generated_case",
                }
            )
    metrics = {
        "runbook_recall_at_5": _ratio(recall_hits, match_total),
        "runbook_precision_at_1": _ratio(top_one_hits, match_total),
        "no_match_accuracy": _ratio(no_match_hits, no_match_total),
        "section_hit_rate": _ratio(section_hits, match_total),
        "cause_candidate_recall": _coverage_ratio(cause_found, cause_expected),
        "runbook_case_coverage": _coverage_ratio(
            len(eligible_runbook_types & evaluated_runbook_types),
            len(eligible_runbook_types),
        ),
        "cause_case_coverage": _coverage_ratio(
            len(eligible_causes & evaluated_causes),
            len(eligible_causes),
        ),
        "generated_case_freshness": _coverage_ratio(
            fresh_generated_case_count,
            generated_case_count,
        ),
    }
    return {
        "metrics": metrics,
        "counts": {
            "matching_cases": len(matching_cases),
            "positive_matching_cases": match_total,
            "no_match_cases": no_match_total,
            "diagnosis_cases": len(diagnosis_cases),
            "eligible_runbooks": len(eligible),
            "eligible_runbook_alert_types": len(eligible_runbook_types),
            "annotated_cause_targets": len(eligible_causes),
            "generated_cases": generated_case_count,
        },
        "failures": failures,
    }


def _gate_report(report: dict[str, Any], gates: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    dataset_policy = gates.get("dataset_policy") or {}
    counts = report["counts"]
    for count_key, policy_key in (
        ("positive_matching_cases", "minimum_positive_matching_cases"),
        ("no_match_cases", "minimum_no_match_cases"),
    ):
        minimum = int(dataset_policy.get(policy_key, 0))
        actual_count = int(counts.get(count_key, 0))
        if actual_count < minimum:
            failures.append(f"{count_key}={actual_count} is below {minimum}")
    for metric, threshold in (gates.get("metric_thresholds") or {}).items():
        actual = float(report["metrics"].get(metric, 0))
        if actual < float(threshold):
            failures.append(f"{metric}={actual:.4f} is below {float(threshold):.4f}")
    return {"passed": not failures, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate runbook retrieval and diagnosis coverage"
    )
    parser.add_argument(
        "--pdf-dir", type=Path, default=Path("runbooks/pdfs-typed")
    )
    parser.add_argument(
        "--matching-dataset",
        type=Path,
        default=Path("evaluation/datasets/runbook_matching.jsonl"),
    )
    parser.add_argument(
        "--diagnosis-dataset",
        type=Path,
        default=Path("evaluation/datasets/root_cause_diagnosis.jsonl"),
    )
    parser.add_argument("--gates", type=Path, default=Path("policies/production-gates.json"))
    parser.add_argument("--min-score", type=float, default=12.0)
    parser.add_argument("--min-confidence", type=float, default=0.35)
    parser.add_argument("--enforce-gates", action="store_true")
    args = parser.parse_args()

    report = asyncio.run(evaluate(args))
    gates = json.loads(args.gates.read_text(encoding="utf-8"))
    report["production_gate"] = _gate_report(report, gates)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if args.enforce_gates and not report["production_gate"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
