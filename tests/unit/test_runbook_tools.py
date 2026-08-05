from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain.models import RunbookKnowledgeType
from tools import audit_runbook_visuals, evaluate_runbooks


@pytest.mark.asyncio
async def test_evaluation_has_no_handbook_approval_metrics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeLibrary:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def list(self) -> list[SimpleNamespace]:
            return [
                SimpleNamespace(
                    knowledge_type=RunbookKnowledgeType.RUNBOOK,
                    deprecated=False,
                ),
                SimpleNamespace(
                    knowledge_type=RunbookKnowledgeType.INCOMPLETE,
                    deprecated=False,
                ),
                SimpleNamespace(
                    knowledge_type=RunbookKnowledgeType.RUNBOOK,
                    deprecated=True,
                ),
            ]

    monkeypatch.setattr(evaluate_runbooks, "LocalPDFRunbookLibrary", FakeLibrary)
    matching_dataset = tmp_path / "matching.jsonl"
    diagnosis_dataset = tmp_path / "diagnosis.jsonl"
    matching_dataset.write_text("", encoding="utf-8")
    diagnosis_dataset.write_text("", encoding="utf-8")

    report = await evaluate_runbooks.evaluate(
        Namespace(
            pdf_dir=tmp_path,
            min_score=12.0,
            min_confidence=0.35,
            matching_dataset=matching_dataset,
            diagnosis_dataset=diagnosis_dataset,
        )
    )

    assert report["counts"]["eligible_runbooks"] == 1
    assert "approved_runbooks" not in report["counts"]
    assert "approved_runbook_ratio" not in report["metrics"]
    assert report["dataset_reviewed"] is True


def test_evaluation_case_review_gate_is_preserved() -> None:
    report = {
        "counts": {"matching_cases": 1, "diagnosis_cases": 1},
        "metrics": {},
        "dataset_reviewed": False,
    }

    gate = evaluate_runbooks._gate_report(
        report,
        {"dataset_policy": {"require_all_cases_reviewed": True}},
    )

    assert gate == {
        "passed": False,
        "failures": ["evaluation datasets still contain unapproved cases"],
    }


@pytest.mark.asyncio
async def test_visual_audit_checks_coverage_without_review_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeLibrary:
        def __init__(self, pdf_dir: Path) -> None:
            pass

        async def list(self) -> list[SimpleNamespace]:
            return [
                SimpleNamespace(
                    id="runbook-1",
                    metadata={
                        "image_pages": [1, 2],
                        "unannotated_image_pages": [2],
                    },
                    visual_evidence=[object()],
                )
            ]

    monkeypatch.setattr(audit_runbook_visuals, "LocalPDFRunbookLibrary", FakeLibrary)

    report = await audit_runbook_visuals.audit(Namespace(pdf_dir=tmp_path))

    assert report["summary"] == {
        "runbooks": 1,
        "missing_visual_coverage": 1,
    }
    assert report["missing_coverage_runbooks"] == ["runbook-1"]
    assert report["runbooks"][0]["visual_coverage_complete"] is False
    assert "pending_review_runbooks" not in report
    assert "pending_visual_evidence_count" not in report["runbooks"][0]
