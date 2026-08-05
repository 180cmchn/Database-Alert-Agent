import json
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.pdf_runbooks import (
    LocalPDFRunbookLibrary,
    derive_runbook_alert_type,
)
from app.domain.errors import RunbookError
from tools.process_pdf_runbooks import process_pdf_runbooks


def _write_text_pdf(path: Path, text: str) -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): writer._add_object(font)}
            )
        }
    )
    escaped = (
        text.encode("ascii")
        .replace(b"\\", b"\\\\")
        .replace(b"(", b"\\(")
        .replace(b")", b"\\)")
    )
    stream = StreamObject()
    stream.set_data(b"BT /F1 12 Tf 72 720 Td (" + escaped + b") Tj ET")
    page[NameObject("/Contents")] = writer._add_object(stream)
    with path.open("wb") as handle:
        writer.write(handle)


@pytest.mark.asyncio
async def test_processing_splits_pdfs_and_results_by_alert_type(
    tmp_path: Path,
) -> None:
    source = tmp_path / "flat"
    source.mkdir()
    _write_text_pdf(
        source / "slow-query.pdf",
        "MySQL slow query 400 troubleshooting guide with safe diagnostic steps.",
    )
    _write_text_pdf(
        source / "replica-lag.pdf",
        "Replica lag troubleshooting guide with safe diagnostic steps.",
    )
    source_index = tmp_path / "index.json"
    source_index.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runbooks": [
                    {
                        "runbook_id": "slow-query",
                        "alert_type": "MySQL/Slow Query 400",
                        "quality_status": "approved",
                        "match": {
                            "alert_names": ["MySQL/Slow Query 400"],
                            "metric_names": [],
                            "aliases": [],
                            "keywords": [],
                        },
                        "visual_evidence": [
                            {
                                "page": 1,
                                "kind": "screenshot",
                                "text": "Query latency chart",
                                "review_status": "approved",
                                "keywords": ["latency"],
                                "metadata": {
                                    "review_notes": "checked",
                                    "owner": "database-team",
                                },
                            }
                        ],
                        "metadata": {
                            "review_status": "source-reviewed",
                            "visual_review_complete": True,
                            "owner": "database-team",
                        },
                    },
                    {
                        "runbook_id": "replica-lag",
                        "quality_status": "deprecated",
                        "match": {
                            "alert_names": ["ReplicaLag"],
                            "metric_names": [],
                            "aliases": [],
                            "keywords": [],
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "typed"

    report = process_pdf_runbooks(source, source_index, output)

    assert report["alert_types"] == {
        "mysql_slow_query_400": ["slow-query"],
        "replicalag": ["replica-lag"],
    }
    assert (output / "mysql_slow_query_400" / "slow-query.pdf").is_file()
    typed_index = json.loads(
        (output / "mysql_slow_query_400" / "index.json").read_text(
            encoding="utf-8"
        )
    )
    assert typed_index["schema_version"] == 3
    assert typed_index["alert_type"] == "mysql_slow_query_400"
    annotation = typed_index["runbooks"][0]
    assert "quality_status" not in annotation
    assert "review_status" not in annotation["visual_evidence"][0]
    assert annotation["visual_evidence"][0]["keywords"] == ["latency"]
    assert annotation["visual_evidence"][0]["metadata"] == {
        "owner": "database-team"
    }
    assert annotation["metadata"] == {"owner": "database-team"}
    replica_annotation = json.loads(
        (output / "replicalag" / "index.json").read_text(encoding="utf-8")
    )["runbooks"][0]
    assert replica_annotation["deprecated"] is True

    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "MySQL slow query 400",
            "reason": "mysql_slow_query_400",
            "alert_type": "MySQL/Slow Query 400",
        }
    )
    matches = await LocalPDFRunbookLibrary(output).search(alert)
    assert [item.runbook_id for item in matches] == ["slow-query"]
    assert matches[0].metadata["alert_type_directory"] == "mysql_slow_query_400"


def test_processing_derives_label_from_pdf_text_and_rejects_ambiguity() -> None:
    assert (
        derive_runbook_alert_type(
            "Alert type: mysql_slow_query_400\nTroubleshooting steps."
        )
        == "mysql_slow_query_400"
    )
    with pytest.raises(RunbookError, match="multiple structured alert types"):
        derive_runbook_alert_type(
            "No labelled alert type is present in this troubleshooting guide.",
            {
                "match": {
                    "alert_names": ["ReplicaLag"],
                    "metric_names": ["ConnectionsHigh"],
                }
            },
        )


def test_processing_never_overwrites_an_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "flat"
    source.mkdir()
    _write_text_pdf(
        source / "replica-lag.pdf",
        "Replica lag troubleshooting guide with safe diagnostic steps.",
    )
    source_index = tmp_path / "index.json"
    source_index.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runbooks": [
                    {
                        "runbook_id": "replica-lag",
                        "alert_type": "ReplicaLag",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "typed"
    output.mkdir()

    with pytest.raises(RunbookError, match="already exists"):
        process_pdf_runbooks(source, source_index, output)
