import json
from pathlib import Path
from shutil import copy2
from typing import Any

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.domain.errors import InvalidRunbookIdError, RunbookError

SOURCE_PDFS = Path(__file__).parents[2] / "runbooks" / "pdfs"
TIKV_PDF = (
    SOURCE_PDFS
    / "INFRA-2025-07-03TiDB--TiKV_server_report_failure_msg_total-210726-1007-4073.pdf"
)
DMP_PDF = SOURCE_PDFS / "INFRA-224075463-210726-1007-4075.pdf"
MYSQL_CRASH_PDF = SOURCE_PDFS / "INFRA-231966487-210726-1008-4079.pdf"
PT_ARCHIVER_PDF = SOURCE_PDFS / "INFRA-201503239-210726-1007-4077.pdf"
RUNBOOK_INDEX = SOURCE_PDFS.parent / "index.json"


def _repository_annotations_available() -> bool:
    if not RUNBOOK_INDEX.is_file():
        return False
    try:
        payload = json.loads(RUNBOOK_INDEX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    runbooks = payload.get("runbooks")
    if not isinstance(runbooks, list):
        return False
    runbook_ids = [
        item.get("runbook_id") for item in runbooks if isinstance(item, dict)
    ]
    return bool(runbook_ids) and all(
        isinstance(runbook_id, str)
        and (SOURCE_PDFS / f"{runbook_id}.pdf").is_file()
        for runbook_id in runbook_ids
    )


requires_repository_annotations = pytest.mark.skipif(
    not _repository_annotations_available(),
    reason="external runbook corpus PDFs and annotation index are not installed",
)


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
    font_reference = writer._add_object(font)
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): font_reference}
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


def _self_contained_library(
    tmp_path: Path,
    *,
    scope: dict[str, list[str]] | None = None,
    match: dict[str, Any] | None = None,
) -> LocalPDFRunbookLibrary:
    pdf_dir = tmp_path / "pdfs"
    pdf_dir.mkdir()
    runbook_id = "replica-lag-runbook"
    _write_text_pdf(
        pdf_dir / f"{runbook_id}.pdf",
        "Replica lag diagnostic guide with safe investigation steps and evidence.",
    )
    annotation_path = tmp_path / "index.json"
    annotation_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runbooks": [
                    {
                        "runbook_id": runbook_id,
                        "knowledge_type": "runbook",
                        "quality_status": "approved",
                        "scope": scope or {},
                        "match": {
                            "alert_names": ["ReplicaLag"],
                            "metric_names": [],
                            "aliases": [],
                            "keywords": [],
                            **(match or {}),
                        },
                        "sections": [
                            {
                                "id": "diagnosis",
                                "title": "Replica lag diagnosis",
                                "pages": [1],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return LocalPDFRunbookLibrary(pdf_dir, annotation_path=annotation_path)


@pytest.mark.asyncio
async def test_local_pdf_runbook_extracts_text_matches_alert_and_caches(
    tmp_path: Path,
) -> None:
    tikv_pdf = tmp_path / "tikv-sample.pdf"
    unrelated_pdf = tmp_path / "urman-sample.pdf"
    _write_text_pdf(
        tikv_pdf,
        "TiKV server report failure diagnosis guide and safe investigation steps.",
    )
    _write_text_pdf(
        unrelated_pdf,
        "URMAN task permission failure diagnosis and connectivity investigation.",
    )
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "TiKV server report failure",
            "reason": "TiKV_server_report_failure_msg_total",
            "database": {"engine": "TiDB"},
            "labels": {"type": "unreachable"},
        }
    )

    first = await library.search(alert)
    first_documents = await library.list()
    second_documents = await library.list()

    assert [item.runbook_id for item in first] == [tikv_pdf.stem]
    assert "diagnosis guide" in first[0].content
    assert first[0].section == "PDF"
    assert first[0].metadata["source_type"] == "local_pdf"
    assert first[0].metadata["page_count"] == 1
    assert first_documents[0] is second_documents[0]


@pytest.mark.asyncio
async def test_local_pdf_runbook_does_not_match_unrelated_alert(tmp_path: Path) -> None:
    _write_text_pdf(
        tmp_path / "urman-sample.pdf",
        "URMAN task permission failure diagnosis and connectivity investigation.",
    )
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "磁盘使用率过高",
            "reason": "disk_usage_high",
        }
    )

    assert await library.search(alert) == []


@pytest.mark.asyncio
@requires_repository_annotations
async def test_local_pdf_runbook_matches_identifier_terms_split_by_chinese(
    tmp_path: Path,
) -> None:
    copy2(MYSQL_CRASH_PDF, tmp_path / MYSQL_CRASH_PDF.name)
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {"severity": "WARNING", "title": "MySQL Crash", "reason": "MySQL Crash"}
    )

    matches = await library.search(alert)

    assert [item.runbook_id for item in matches] == [MYSQL_CRASH_PDF.stem]


@pytest.mark.asyncio
async def test_local_pdf_runbook_rejects_image_only_pdf(tmp_path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    with (tmp_path / "image-only.pdf").open("wb") as handle:
        writer.write(handle)

    with pytest.raises(RunbookError, match="OCR is required"):
        await LocalPDFRunbookLibrary(tmp_path).list()


@pytest.mark.asyncio
async def test_local_pdf_runbook_get_rejects_unsafe_id(tmp_path: Path) -> None:
    library = LocalPDFRunbookLibrary(tmp_path)

    with pytest.raises(InvalidRunbookIdError):
        await library.get("../escape")


@pytest.mark.asyncio
@requires_repository_annotations
async def test_repository_annotations_provide_sections_quality_and_diagnosis_graph() -> None:
    library = LocalPDFRunbookLibrary(SOURCE_PDFS)
    documents = await library.list()
    template = next(item for item in documents if item.id == "INFRA-229346366-210726-1007-4071")
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "TiKV server report failure",
            "reason": "TiKV_server_report_failure_msg_total",
            "database": {"engine": "TiDB"},
            "labels": {"type": "unreachable"},
        }
    )

    matches = await library.search(alert)

    assert template.knowledge_type.value == "incomplete"
    assert template.quality_status.value == "draft"
    assert all(item.runbook_id != template.id for item in matches)
    assert matches[0].section != "PDF"
    assert matches[0].page_refs
    assert matches[0].match_confidence >= 0.35
    assert {cause.cause_id for cause in matches[0].causes} >= {
        "tikv_host_down",
        "tikv_resource_pressure",
        "tikv_oom_kill",
    }
    assert any("Dashboard 慢查询页" in action.action for action in matches[0].actions)
    assert any("最大内存降序" in action.action for action in matches[0].actions)
    assert matches[0].visual_evidence
    tikv = next(item for item in documents if item.id == TIKV_PDF.stem)
    assert tikv.metadata["image_pages"] == [1, 2, 3]
    assert tikv.metadata["unannotated_image_pages"] == []
    assert tikv.metadata["visual_coverage_complete"] is True
    assert tikv.metadata["visual_review_complete"] is False


@pytest.mark.asyncio
@requires_repository_annotations
@pytest.mark.parametrize(
    ("reason", "error_pattern", "engine", "section", "cause_id", "action_text"),
    [
        (
            "归档条件存在中文，生成 SQL 乱码",
            None,
            "MySQL",
            "chinese-condition-encoding",
            "archive_condition_chinese_encoding",
            'use encoding "utf8"',
        ),
        (
            "LOAD DATA LOCAL INFILE failed",
            "Invalid utf8 character string",
            "MySQL",
            "bulk-insert-special-character",
            "archive_bulk_insert_special_character_charset",
            "CHARACTER SET utf8mb4",
        ),
        (
            "Character set mismatch",
            "source DSN uses utf8mb4, table uses",
            "OceanBase",
            "ob-charset-mismatch",
            "archive_ob_dsn_table_charset_mismatch",
            "--no-check-charset",
        ),
    ],
)
async def test_pt_archiver_three_causes_map_to_distinct_sections_and_actions(
    reason: str,
    error_pattern: str | None,
    engine: str,
    section: str,
    cause_id: str,
    action_text: str,
) -> None:
    library = LocalPDFRunbookLibrary(SOURCE_PDFS)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "pt-archiver 归档报错",
            "reason": reason,
            "error_pattern": error_pattern,
            "database": {"engine": engine},
        }
    )

    matches = await library.search(alert)

    assert matches[0].runbook_id == PT_ARCHIVER_PDF.stem
    assert matches[0].section == section
    assert [cause.cause_id for cause in matches[0].causes] == [cause_id]
    assert len(matches[0].actions) == 1
    assert action_text in matches[0].actions[0].action


@pytest.mark.asyncio
@requires_repository_annotations
async def test_visual_error_text_participates_in_matching() -> None:
    library = LocalPDFRunbookLibrary(SOURCE_PDFS)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "TiKV service exited",
            "reason": "tiflash service entered failed state",
            "error_pattern": "code=killed, status=9/KILL",
            "database": {"engine": "TiDB"},
            "labels": {"type": "unreachable"},
        }
    )

    matches = await library.search(alert)

    assert matches[0].runbook_id == TIKV_PDF.stem
    assert matches[0].section == "diagnosis"
    assert any("图片关键报错" in reason for reason in matches[0].match_reasons)
    assert any(item.page == 2 for item in matches[0].visual_evidence)


@pytest.mark.asyncio
async def test_required_conditions_are_all_mandatory(tmp_path: Path) -> None:
    library = _self_contained_library(
        tmp_path,
        match={
            "required_conditions": ["type=unreachable", "region=cn-east"],
            "exclusion_conditions": [],
        },
    )
    matching = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "labels": {"type": "unreachable", "region": "cn-east"},
        }
    )
    missing_one = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "labels": {"type": "unreachable"},
        }
    )

    assert [item.runbook_id for item in await library.search(matching)] == [
        "replica-lag-runbook"
    ]
    assert await library.search(missing_one) == []


@pytest.mark.asyncio
async def test_exclusion_condition_rejects_an_otherwise_exact_match(
    tmp_path: Path,
) -> None:
    library = _self_contained_library(
        tmp_path,
        match={
            "required_conditions": [],
            "exclusion_conditions": ["maintenance=true"],
        },
    )
    active = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "labels": {"maintenance": "false"},
        }
    )
    maintenance = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "attributes": {"maintenance": True},
        }
    )

    assert [item.runbook_id for item in await library.search(active)] == [
        "replica-lag-runbook"
    ]
    assert await library.search(maintenance) == []


@pytest.mark.asyncio
async def test_component_scope_uses_alert_values_and_identifier_boundaries(
    tmp_path: Path,
) -> None:
    library = _self_contained_library(
        tmp_path,
        scope={"database_engines": [], "components": ["dm"]},
    )
    matching = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "labels": {"component": "dm-validator"},
        }
    )
    unrelated = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "labels": {"component": "admin-api"},
        }
    )

    assert [item.runbook_id for item in await library.search(matching)] == [
        "replica-lag-runbook"
    ]
    assert await library.search(unrelated) == []


@pytest.mark.asyncio
@requires_repository_annotations
async def test_approved_runbook_rejects_unannotated_image_pages(tmp_path: Path) -> None:
    pdf_dir = tmp_path / "pdfs"
    pdf_dir.mkdir()
    copy2(TIKV_PDF, pdf_dir / TIKV_PDF.name)
    annotation_path = tmp_path / "index.json"
    annotation_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runbooks": [
                    {
                        "runbook_id": TIKV_PDF.stem,
                        "knowledge_type": "runbook",
                        "quality_status": "approved",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RunbookError, match="unannotated image pages"):
        await LocalPDFRunbookLibrary(
            pdf_dir, annotation_path=annotation_path
        ).list()
