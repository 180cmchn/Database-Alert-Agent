#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary


async def audit(args: argparse.Namespace) -> dict[str, Any]:
    library = LocalPDFRunbookLibrary(args.pdf_dir)
    documents = await library.list()
    records: list[dict[str, Any]] = []
    missing_coverage: list[str] = []
    for document in documents:
        image_pages = list(document.metadata.get("image_pages") or [])
        unannotated_pages = list(
            document.metadata.get("unannotated_image_pages") or []
        )
        if unannotated_pages:
            missing_coverage.append(document.id)
        records.append(
            {
                "runbook_id": document.id,
                "image_pages": image_pages,
                "visual_evidence_count": len(document.visual_evidence),
                "unannotated_image_pages": unannotated_pages,
                "visual_coverage_complete": not unannotated_pages,
            }
        )
    return {
        "summary": {
            "runbooks": len(documents),
            "missing_visual_coverage": len(missing_coverage),
        },
        "missing_coverage_runbooks": missing_coverage,
        "runbooks": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit image-page annotation coverage for PDF runbooks"
    )
    parser.add_argument(
        "--pdf-dir", type=Path, default=Path("runbooks/pdfs-typed")
    )
    args = parser.parse_args()

    report = asyncio.run(audit(args))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["summary"]["missing_visual_coverage"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
