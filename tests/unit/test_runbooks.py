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
