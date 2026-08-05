import json
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

TIKV_RUNBOOK_ID = "synthetic-replica-lag-runbook"
TIKV_RUNBOOK_PDF_NAME = f"{TIKV_RUNBOOK_ID}.pdf"
TIKV_METRIC_NAME = "synthetic_replica_lag_high"
TIKV_ALERT_TYPE_DIRECTORY = "synthetic_replica_lag_high"
_TIKV_RUNBOOK_TEXT = (
    f"{TIKV_METRIC_NAME} troubleshooting runbook: inspect TiKV logs and server health."
)


def create_tikv_runbook_pdf(directory: Path) -> Path:
    """Create a small text-layer PDF used by runbook integration tests."""

    alert_type_directory = directory / TIKV_ALERT_TYPE_DIRECTORY
    alert_type_directory.mkdir(parents=True, exist_ok=True)
    path = alert_type_directory / TIKV_RUNBOOK_PDF_NAME

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
    (alert_type_directory / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "alert_type": TIKV_ALERT_TYPE_DIRECTORY,
                "runbooks": [
                    {
                        "runbook_id": TIKV_RUNBOOK_ID,
                        "alert_type": TIKV_ALERT_TYPE_DIRECTORY,
                        "match": {
                            "alert_names": [TIKV_METRIC_NAME],
                            "metric_names": [TIKV_ALERT_TYPE_DIRECTORY],
                            "aliases": [],
                            "keywords": [],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path
