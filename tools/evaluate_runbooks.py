#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.domain.models import RunbookKnowledgeType, RunbookQualityStatus


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


async def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    adapter = CanonicalAlertSourceAdapter()
    library = LocalPDFRunbookLibrary(
        args.pdf_dir,
        annotation_path=args.annotation,
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
    failures: list[dict[str, Any]] = []
    for case in matching_cases:
        alert = adapter.normalize({"external_id": case["case_id"], **case["alert"]})
        results = await library.search(alert, limit=5)
        retrieved_ids = [item.runbook_id for item in results]
        gold_ids = list(case.get("gold_runbook_ids") or [])
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
        results = await library.search(alert, limit=5)
        result = next(
            (item for item in results if item.runbook_id == case["gold_runbook_id"]), None
        )
        available = {cause.cause_id for cause in result.causes} if result else set()
        expected = set(case.get("expected_cause_ids") or [])
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
        and item.quality_status != RunbookQualityStatus.DEPRECATED
    ]
    approved = [
        item for item in eligible if item.quality_status == RunbookQualityStatus.APPROVED
    ]
    metrics = {
        "runbook_recall_at_5": _ratio(recall_hits, match_total),
        "runbook_precision_at_1": _ratio(top_one_hits, match_total),
        "no_match_accuracy": _ratio(no_match_hits, no_match_total),
        "section_hit_rate": _ratio(section_hits, match_total),
        "cause_candidate_recall": _ratio(cause_found, cause_expected),
        "approved_runbook_ratio": _ratio(len(approved), len(eligible)),
    }
    all_reviewed = all(
        item.get("review_status") == "approved"
        for item in [*matching_cases, *diagnosis_cases]
    )
    return {
        "metrics": metrics,
        "counts": {
            "matching_cases": len(matching_cases),
            "diagnosis_cases": len(diagnosis_cases),
            "eligible_runbooks": len(eligible),
            "approved_runbooks": len(approved),
        },
        "dataset_reviewed": all_reviewed,
        "failures": failures,
    }


def _gate_report(report: dict[str, Any], gates: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    dataset_policy = gates.get("dataset_policy") or {}
    counts = report["counts"]
    if dataset_policy.get("require_all_cases_reviewed") and not report["dataset_reviewed"]:
        failures.append("evaluation datasets still contain unapproved cases")
    for count_key, policy_key in (
        ("matching_cases", "minimum_matching_cases"),
        ("diagnosis_cases", "minimum_diagnosis_cases"),
    ):
        minimum = int(dataset_policy.get(policy_key, 0))
        if counts[count_key] < minimum:
            failures.append(f"{count_key}={counts[count_key]} is below {minimum}")
    for metric, threshold in (gates.get("metric_thresholds") or {}).items():
        actual = float(report["metrics"].get(metric, 0))
        if actual < float(threshold):
            failures.append(f"{metric}={actual:.4f} is below {float(threshold):.4f}")
    return {"passed": not failures, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate runbook retrieval and diagnosis coverage"
    )
    parser.add_argument("--pdf-dir", type=Path, default=Path("runbooks/pdfs"))
    parser.add_argument("--annotation", type=Path, default=Path("runbooks/index.json"))
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
