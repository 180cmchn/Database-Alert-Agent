from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

TIKV_RUNBOOK_ID = (
    "INFRA-2025-07-03TiDB--"
    "TiKV_server_report_failure_msg_total-210726-1007-4073"
)
TIKV_RUNBOOK_PDF_NAME = f"{TIKV_RUNBOOK_ID}.pdf"
TIKV_METRIC_NAME = "TiKV_server_report_failure_msg_total"
_TIKV_RUNBOOK_TEXT = (
    f"{TIKV_METRIC_NAME} troubleshooting runbook: inspect TiKV logs and server health."
)


def create_tikv_runbook_pdf(directory: Path) -> Path:
    """Create a small text-layer PDF used by runbook integration tests."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / TIKV_RUNBOOK_PDF_NAME

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
    content = DecodedStreamObject()
    content.set_data(
        f"BT /F1 12 Tf 72 720 Td ({_TIKV_RUNBOOK_TEXT}) Tj ET".encode("ascii")
    )
    page[NameObject("/Contents")] = writer._add_object(content)

    with path.open("wb") as handle:
        writer.write(handle)

    with path.open("rb") as handle:
        extracted = "\n".join(
            page.extract_text() or "" for page in PdfReader(handle).pages
        )
    assert TIKV_METRIC_NAME in extracted
    return path
