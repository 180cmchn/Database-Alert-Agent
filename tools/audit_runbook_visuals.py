#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from app.adapters.pdf_runbooks import LocalPDFRunbookLibrary
from app.domain.models import RunbookQualityStatus


async def audit(args: argparse.Namespace) -> dict[str, Any]:
    library = LocalPDFRunbookLibrary(
        args.pdf_dir,
        annotation_path=args.annotation,
    )
    documents = await library.list()
    records: list[dict[str, Any]] = []
    missing_coverage: list[str] = []
    pending_review: list[str] = []
    for document in documents:
        image_pages = list(document.metadata.get("image_pages") or [])
        unannotated_pages = list(
            document.metadata.get("unannotated_image_pages") or []
        )
        pending_items = [
            item
            for item in document.visual_evidence
            if item.review_status != RunbookQualityStatus.APPROVED
        ]
        if unannotated_pages:
            missing_coverage.append(document.id)
        if pending_items:
            pending_review.append(document.id)
        records.append(
            {
                "runbook_id": document.id,
                "image_pages": image_pages,
                "visual_evidence_count": len(document.visual_evidence),
                "unannotated_image_pages": unannotated_pages,
                "visual_coverage_complete": not unannotated_pages,
                "pending_visual_evidence_count": len(pending_items),
            }
        )
    return {
        "summary": {
            "runbooks": len(documents),
            "missing_visual_coverage": len(missing_coverage),
            "pending_visual_review": len(pending_review),
        },
        "missing_coverage_runbooks": missing_coverage,
        "pending_review_runbooks": pending_review,
        "runbooks": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit image-page coverage and review state for PDF runbooks"
    )
    parser.add_argument("--pdf-dir", type=Path, default=Path("runbooks/pdfs"))
    parser.add_argument("--annotation", type=Path, default=Path("runbooks/index.json"))
    parser.add_argument(
        "--require-approved",
        action="store_true",
        help="also fail when visual evidence is not approved",
    )
    args = parser.parse_args()

    report = asyncio.run(audit(args))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["summary"]["missing_visual_coverage"]:
        return 1
    if args.require_approved and report["summary"]["pending_visual_review"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
