import json
from argparse import Namespace
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject

from app.domain.errors import RunbookError
from tools import evaluate_runbooks
from tools.generate_evaluation_datasets import generate_evaluation_datasets


def _write_text_pdf(path: Path, text: str) -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
            NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): writer._add_object(font)}
            )
        }
    )
    escaped_lines = [
        line.encode("ascii")
        .replace(b"\\", b"\\\\")
        .replace(b"(", b"\\(")
        .replace(b")", b"\\)")
        for line in text.splitlines()
    ]
    stream = StreamObject()
    operations = b") Tj T* (".join(escaped_lines)
    stream.set_data(b"BT /F1 12 Tf 14 TL 72 720 Td (" + operations + b") Tj ET")
    page[NameObject("/Contents")] = writer._add_object(stream)
    with path.open("wb") as handle:
        writer.write(handle)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.asyncio
async def test_generate_typed_pdf_datasets_and_evaluate_them(tmp_path: Path) -> None:
    pdf_dir = tmp_path / "typed"
    type_dir = pdf_dir / "mysql_slow_query_400"
    type_dir.mkdir(parents=True)
    _write_text_pdf(
        type_dir / "slow-query.pdf",
        "[WARNING] MySQL slow query diagnosis with full table scan checks.",
    )
    (type_dir / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "alert_type": "mysql_slow_query_400",
                "runbooks": [
                    {
                        "runbook_id": "slow-query",
                        "alert_type": "mysql_slow_query_400",
                        "match": {
                            "alert_names": ["MySQL slow query 400"],
                            "metric_names": ["mysql_slow_query_400"],
                            "required_conditions": ["cluster=orders"],
                        },
                        "scope": {
                            "database_engines": ["mysql"],
                            "components": ["mysqld"],
                        },
                        "sections": [
                            {
                                "id": "diagnosis",
                                "title": "Diagnosis",
                                "pages": [1],
                                "match_terms": ["full table scan"],
                            }
                        ],
                        "causes": [
                            {
                                "cause_id": "full-table-scan",
                                "hypothesis": "A query performs a full table scan.",
                                "section_ids": ["diagnosis"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "evaluation" / "datasets"

    report = generate_evaluation_datasets(pdf_dir, output_dir)

    assert report == {
        "pdf_dir": str(pdf_dir),
        "layout": "typed",
        "source_index": None,
        "output_dir": str(output_dir),
        "pdf_count": 1,
        "matching_case_count": 1,
        "diagnosis_case_count": 1,
        "skipped_ineligible_count": 0,
        "skipped_root_cause_runbooks": [],
        "review_status": "review_required",
    }
    matching = _read_jsonl(output_dir / "runbook_matching.jsonl")
    diagnosis = _read_jsonl(output_dir / "root_cause_diagnosis.jsonl")
    assert matching[0]["alert"] == {
        "severity": "WARNING",
        "title": "MySQL slow query 400",
        "reason": "mysql_slow_query_400",
        "alert_type": "mysql_slow_query_400",
        "alert_name": "MySQL slow query 400",
        "environment": "evaluation",
        "metric_name": "mysql_slow_query_400",
        "database": {"engine": "mysql"},
        "labels": {"component": "mysqld"},
        "description": "cluster=orders",
    }
    assert matching[0]["gold_runbook_ids"] == ["slow-query"]
    assert matching[0]["gold_sections"] == ["diagnosis"]
    assert matching[0]["review_status"] == "review_required"
    assert matching[0]["source"]["page_count"] == 1
    assert len(matching[0]["source"]["content_sha256"]) == 64
    assert diagnosis[0]["gold_runbook_id"] == "slow-query"
    assert diagnosis[0]["expected_cause_ids"] == ["full-table-scan"]
    assert "full table scan" in diagnosis[0]["alert"]["description"]

    evaluation = await evaluate_runbooks.evaluate(
        Namespace(
            pdf_dir=pdf_dir,
            min_score=12.0,
            min_confidence=0.35,
            matching_dataset=output_dir / "runbook_matching.jsonl",
            diagnosis_dataset=output_dir / "root_cause_diagnosis.jsonl",
        )
    )
    assert evaluation["counts"]["matching_cases"] == 1
    assert evaluation["counts"]["diagnosis_cases"] == 1
    assert evaluation["metrics"]["runbook_recall_at_5"] == 1.0
    assert evaluation["metrics"]["cause_candidate_recall"] == 1.0
    assert evaluation["dataset_reviewed"] is False


def test_generate_flat_pdf_dataset_from_pdf_text(tmp_path: Path) -> None:
    pdf_dir = tmp_path / "flat"
    pdf_dir.mkdir()
    _write_text_pdf(
        pdf_dir / "replica-lag.pdf",
        "Alert type: replica_lag",
    )
    output_dir = tmp_path / "datasets"

    report = generate_evaluation_datasets(
        pdf_dir,
        output_dir,
        strict_alert_types=True,
    )

    assert report["layout"] == "flat"
    assert report["matching_case_count"] == 1
    assert report["diagnosis_case_count"] == 0
    assert report["skipped_root_cause_runbooks"] == ["replica_lag/replica-lag"]
    matching = _read_jsonl(output_dir / "runbook_matching.jsonl")
    assert matching[0]["alert"]["alert_type"] == "replica_lag"
    assert matching[0]["alert"]["title"].startswith("Alert type: replica_lag")
    assert matching[0]["source"]["alert_type_source"] == "pdf_title"
    assert (output_dir / "root_cause_diagnosis.jsonl").read_text() == ""

    with pytest.raises(RunbookError, match="pass --force"):
        generate_evaluation_datasets(pdf_dir, output_dir)
    generate_evaluation_datasets(pdf_dir, output_dir, force=True)


def test_flat_pdf_title_selects_one_candidate_from_full_text(tmp_path: Path) -> None:
    pdf_dir = tmp_path / "flat"
    pdf_dir.mkdir()
    _write_text_pdf(
        pdf_dir / "replica-lag.pdf",
        "ReplicaLag alert\nAlert type: ReplicaLag, UnrelatedClusterHigh",
    )
    output_dir = tmp_path / "datasets"

    report = generate_evaluation_datasets(pdf_dir, output_dir)

    assert report["matching_case_count"] == 1
    matching = _read_jsonl(output_dir / "runbook_matching.jsonl")
    assert matching[0]["alert"]["alert_type"] == "replicalag"
    assert matching[0]["source"]["alert_type_source"] == "pdf_text_title_match"


def test_generation_rejects_pdf_without_text_before_writing(tmp_path: Path) -> None:
    pdf_dir = tmp_path / "flat"
    pdf_dir.mkdir()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with (pdf_dir / "blank.pdf").open("wb") as handle:
        writer.write(handle)
    output_dir = tmp_path / "datasets"

    with pytest.raises(RunbookError, match="OCR is required"):
        generate_evaluation_datasets(pdf_dir, output_dir)

    assert not output_dir.exists()
