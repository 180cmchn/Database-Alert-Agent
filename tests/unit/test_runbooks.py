import json
from pathlib import Path
from shutil import copy2

import pytest
from pypdf import PdfWriter

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


@pytest.mark.asyncio
async def test_local_pdf_runbook_extracts_text_matches_alert_and_caches(
    tmp_path: Path,
) -> None:
    copy2(TIKV_PDF, tmp_path / TIKV_PDF.name)
    copy2(DMP_PDF, tmp_path / DMP_PDF.name)
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "TiKV server report failure",
            "reason": "TiKV_server_report_failure_msg_total",
            "database": {"engine": "TiDB"},
        }
    )

    first = await library.search(alert)
    first_documents = await library.list()
    second_documents = await library.list()

    assert [item.runbook_id for item in first] == [TIKV_PDF.stem]
    assert "排查步骤" in first[0].content
    assert first[0].section == "PDF"
    assert first[0].metadata["source_type"] == "local_pdf"
    assert first[0].metadata["page_count"] == 3
    assert first_documents[0] is second_documents[0]


@pytest.mark.asyncio
async def test_local_pdf_runbook_does_not_match_unrelated_alert(tmp_path: Path) -> None:
    copy2(DMP_PDF, tmp_path / DMP_PDF.name)
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
async def test_visual_error_text_participates_in_matching() -> None:
    library = LocalPDFRunbookLibrary(SOURCE_PDFS)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "TiKV service exited",
            "reason": "tiflash service entered failed state",
            "error_pattern": "code=killed, status=9/KILL",
            "database": {"engine": "TiDB"},
        }
    )

    matches = await library.search(alert)

    assert matches[0].runbook_id == TIKV_PDF.stem
    assert matches[0].section == "diagnosis"
    assert any("图片关键报错" in reason for reason in matches[0].match_reasons)
    assert any(item.page == 2 for item in matches[0].visual_evidence)


@pytest.mark.asyncio
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
