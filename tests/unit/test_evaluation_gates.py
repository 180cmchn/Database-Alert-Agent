from tools.evaluate_runbooks import _attach_harness_report, _gate_report


def make_report() -> dict[str, object]:
    return {
        "counts": {
            "positive_matching_cases": 2,
            "no_match_cases": 2,
            "diagnosis_cases": 2,
        },
        "metrics": {
            "cause_candidate_recall": 1.0,
            "cause_case_coverage": 1.0,
        },
        "violations": {
            "fabricated_runbook_references": 0,
            "fabricated_evidence": 0,
            "unapproved_change_actions": 0,
        },
    }


def make_gates() -> dict[str, object]:
    return {
        "dataset_policy": {
            "minimum_positive_matching_cases": 1,
            "minimum_no_match_cases": 1,
            "minimum_diagnosis_cases": 1,
        },
        "metric_thresholds": {
            "cause_candidate_recall": 0.95,
            "cause_case_coverage": 1.0,
        },
        "zero_tolerance": [
            "fabricated_runbook_references",
            "fabricated_evidence",
            "unapproved_change_actions",
        ],
        "harness_policy": {"enabled": False},
    }


def test_empty_diagnosis_dataset_hard_fails_even_with_perfect_metrics() -> None:
    report = make_report()
    report["counts"]["diagnosis_cases"] = 0  # type: ignore[index]

    gate = _gate_report(report, make_gates())

    assert gate["passed"] is False
    assert "diagnosis_cases=0 is below 1" in gate["failures"]


def test_zero_tolerance_violation_fails_the_gate() -> None:
    report = make_report()
    report["violations"]["fabricated_evidence"] = 1  # type: ignore[index]

    gate = _gate_report(report, make_gates())

    assert gate["passed"] is False
    assert (
        "violations.fabricated_evidence=1 violates zero tolerance"
        in gate["failures"]
    )


def test_missing_zero_tolerance_count_does_not_silently_pass() -> None:
    report = make_report()
    del report["violations"]["unapproved_change_actions"]  # type: ignore[index]

    gate = _gate_report(report, make_gates())

    assert gate["passed"] is False
    assert "violations.unapproved_change_actions is missing" in gate["failures"]


def test_complete_report_passes_when_harness_gate_is_disabled() -> None:
    assert _gate_report(make_report(), make_gates()) == {
        "passed": True,
        "failures": [],
    }


def test_enabled_harness_gate_uses_independent_scenario_report() -> None:
    gates = make_gates()
    gates["harness_policy"] = {
        "enabled": True,
        "minimum_harness_scenarios": 2,
        "required_fault_families": ["mcp_timeout", "checkpoint_resume"],
    }
    report = _attach_harness_report(
        make_report(),
        {
            "scenario_count": 2,
            "fault_families": {"mcp_timeout": 1, "checkpoint_resume": 1},
            "violations": {
                "fabricated_runbook_references": 0,
                "fabricated_evidence": 0,
                "unapproved_change_actions": 0,
            },
        },
    )

    assert _gate_report(report, gates) == {"passed": True, "failures": []}
