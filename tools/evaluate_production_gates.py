#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _non_negative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def evaluate_production_gate(
    report: dict[str, Any],
    gates: dict[str, Any],
) -> dict[str, Any]:
    failures: list[str] = []
    violations = report.get("violations")
    for violation_name in gates.get("zero_tolerance") or []:
        if not isinstance(violations, dict) or violation_name not in violations:
            failures.append(f"violations.{violation_name} is missing")
            continue
        count = violations[violation_name]
        if not _non_negative_integer(count):
            failures.append(
                f"violations.{violation_name} must be a non-negative integer"
            )
        elif count:
            failures.append(
                f"violations.{violation_name}={count} violates zero tolerance"
            )

    harness_policy = gates.get("harness_policy") or {}
    if harness_policy.get("enabled") is True:
        scenario_count = report.get("scenario_count")
        minimum_scenarios = int(harness_policy.get("minimum_harness_scenarios", 0))
        if not _non_negative_integer(scenario_count):
            failures.append("scenario_count must be a non-negative integer")
        elif scenario_count < minimum_scenarios:
            failures.append(
                f"scenario_count={scenario_count} is below {minimum_scenarios}"
            )

        fault_families = report.get("fault_families")
        for family in harness_policy.get("required_fault_families") or []:
            if not isinstance(fault_families, dict) or family not in fault_families:
                failures.append(f"fault_families.{family} is missing")
                continue
            family_count = fault_families[family]
            if not _non_negative_integer(family_count) or family_count < 1:
                failures.append(
                    f"fault_families.{family} must contain at least one scenario"
                )

    return {"passed": not failures, "failures": failures}


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a provider-independent Agent harness report"
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--gates",
        type=Path,
        default=Path("policies/production-gates.json"),
    )
    parser.add_argument("--enforce-gates", action="store_true")
    args = parser.parse_args()

    report = _load_object(args.report, label="report")
    gates = _load_object(args.gates, label="gates")
    output = {
        **report,
        "production_gate": evaluate_production_gate(report, gates),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 1 if args.enforce_gates and not output["production_gate"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
