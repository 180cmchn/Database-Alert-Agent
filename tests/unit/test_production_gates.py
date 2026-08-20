from tools.evaluate_production_gates import evaluate_production_gate


def make_gates() -> dict[str, object]:
    return {
        "zero_tolerance": [
            "fabricated_knowledge_references",
            "fabricated_evidence",
            "unapproved_change_actions",
        ],
        "harness_policy": {
            "enabled": True,
            "minimum_harness_scenarios": 2,
            "required_fault_families": [
                "knowledge_source_timeout",
                "checkpoint_resume",
            ],
        },
    }


def make_report() -> dict[str, object]:
    return {
        "scenario_count": 2,
        "fault_families": {
            "knowledge_source_timeout": 1,
            "checkpoint_resume": 1,
        },
        "violations": {
            "fabricated_knowledge_references": 0,
            "fabricated_evidence": 0,
            "unapproved_change_actions": 0,
        },
    }


def test_complete_provider_independent_harness_report_passes() -> None:
    assert evaluate_production_gate(make_report(), make_gates()) == {
        "passed": True,
        "failures": [],
    }


def test_zero_tolerance_violation_fails_the_gate() -> None:
    report = make_report()
    report["violations"]["fabricated_evidence"] = 1  # type: ignore[index]

    result = evaluate_production_gate(report, make_gates())

    assert result["passed"] is False
    assert (
        "violations.fabricated_evidence=1 violates zero tolerance"
        in result["failures"]
    )


def test_missing_or_invalid_zero_tolerance_counts_fail_closed() -> None:
    report = make_report()
    del report["violations"]["fabricated_knowledge_references"]  # type: ignore[index]
    report["violations"]["unapproved_change_actions"] = True  # type: ignore[index]

    result = evaluate_production_gate(report, make_gates())

    assert result["passed"] is False
    assert "violations.fabricated_knowledge_references is missing" in result["failures"]
    assert (
        "violations.unapproved_change_actions must be a non-negative integer"
        in result["failures"]
    )


def test_required_fault_family_and_minimum_scenario_count_fail_closed() -> None:
    report = make_report()
    report["scenario_count"] = 1
    del report["fault_families"]["checkpoint_resume"]  # type: ignore[index]

    result = evaluate_production_gate(report, make_gates())

    assert result["passed"] is False
    assert "scenario_count=1 is below 2" in result["failures"]
    assert "fault_families.checkpoint_resume is missing" in result["failures"]
