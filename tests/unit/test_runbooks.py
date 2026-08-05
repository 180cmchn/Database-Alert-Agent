import json
from pathlib import Path
from shutil import copy2
from typing import Any

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject

from app.adapters.alert_sources import CanonicalAlertSourceAdapter
from app.adapters.pdf_runbooks import (
    LocalPDFRunbookLibrary,
    alert_type_directory_name,
    derive_runbook_alert_type,
    derive_runbook_alert_types,
)
from app.domain.errors import (
    InvalidRunbookIdError,
    RunbookAlertTypeNotFoundError,
    RunbookError,
)
from app.domain.models import RunbookDocument, RunbookExcerpt, RunbookVisualEvidence

SOURCE_PDFS = Path(__file__).parents[2] / "runbooks" / "pdfs"
TIKV_PDF = (
    SOURCE_PDFS
    / "synthetic_replica_lag_high"
    / "SYNTHETIC-RUNBOOK-ID.pdf"
)
DMP_PDF = (
    SOURCE_PDFS / "synthetic_backup_task_failed" / "SYNTHETIC-RUNBOOK-ID.pdf"
)
MYSQL_CRASH_PDF = (
    SOURCE_PDFS / "mysql_crash" / "SYNTHETIC-RUNBOOK-ID.pdf"
)
PT_ARCHIVER_PDF = (
    SOURCE_PDFS
    / "synthetic_archive_task_failed"
    / "SYNTHETIC-RUNBOOK-ID.pdf"
)


def _repository_annotations_available() -> bool:
    indexes = sorted(SOURCE_PDFS.glob("*/index.json"))
    if not indexes:
        return False
    for index in indexes:
        try:
            payload = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        runbooks = payload.get("runbooks")
        if not isinstance(runbooks, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("runbook_id"), str)
            and (index.parent / f"{item['runbook_id']}.pdf").is_file()
            for item in runbooks
        ):
            return False
    return True


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


def _write_minimal_index(
    directory: Path,
    alert_type: str,
    runbook_id: str,
    *,
    annotation_fields: dict[str, Any] | None = None,
) -> None:
    (directory / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "alert_type": alert_type,
                "runbooks": [
                    {
                        "runbook_id": runbook_id,
                        "alert_type": alert_type,
                        "knowledge_type": "runbook",
                        **(annotation_fields or {}),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _self_contained_library(
    tmp_path: Path,
    *,
    scope: dict[str, list[str]] | None = None,
    match: dict[str, Any] | None = None,
) -> LocalPDFRunbookLibrary:
    pdf_dir = tmp_path / "pdfs"
    alert_type_dir = pdf_dir / "replica_lag"
    alert_type_dir.mkdir(parents=True)
    runbook_id = "replica-lag-runbook"
    _write_text_pdf(
        alert_type_dir / f"{runbook_id}.pdf",
        "Replica lag diagnostic guide with safe investigation steps and evidence.",
    )
    annotation_path = alert_type_dir / "index.json"
    annotation_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "alert_type": "replica_lag",
                "runbooks": [
                    {
                        "runbook_id": runbook_id,
                        "alert_type": "replica_lag",
                        "knowledge_type": "runbook",
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
    return LocalPDFRunbookLibrary(pdf_dir)


@pytest.mark.asyncio
async def test_local_pdf_runbook_extracts_text_matches_alert_and_caches(
    tmp_path: Path,
) -> None:
    tikv_directory = tmp_path / "synthetic_replica_lag_high"
    urman_directory = tmp_path / "synthetic_backup_task_failed"
    tikv_directory.mkdir()
    urman_directory.mkdir()
    tikv_pdf = tikv_directory / "tikv-sample.pdf"
    unrelated_pdf = urman_directory / "urman-sample.pdf"
    _write_text_pdf(
        tikv_pdf,
        "Synthetic replica lag alert diagnosis guide and safe investigation steps.",
    )
    _write_text_pdf(
        unrelated_pdf,
        "URMAN task permission failure diagnosis and connectivity investigation.",
    )
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "Synthetic replica lag alert",
            "reason": "synthetic_replica_lag_high",
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
async def test_local_pdf_runbook_reports_missing_alert_type_directory(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "synthetic_backup_task_failed"
    directory.mkdir()
    _write_text_pdf(
        directory / "urman-sample.pdf",
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

    with pytest.raises(
        RunbookAlertTypeNotFoundError,
        match="匹配本地pdf失败，pdf中没有该类型告警的处理方法",
    ):
        await library.search(alert)


@pytest.mark.asyncio
async def test_local_pdf_search_never_falls_back_to_another_alert_type(
    tmp_path: Path,
) -> None:
    requested_directory = tmp_path / "mysql_slow_query_400"
    other_directory = tmp_path / "replica_lag"
    requested_directory.mkdir()
    other_directory.mkdir()
    _write_text_pdf(
        requested_directory / "unrelated.pdf",
        "Connection pool troubleshooting guide with safe diagnostic steps.",
    )
    _write_text_pdf(
        other_directory / "strong-but-wrong-type.pdf",
        "MySQL slow query 400 troubleshooting guide and diagnostic steps.",
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "MySQL slow query 400",
            "reason": "mysql_slow_query_400",
        }
    )

    assert await LocalPDFRunbookLibrary(tmp_path).search(alert) == []


@pytest.mark.asyncio
async def test_exact_cause_evidence_outweighs_alert_definition_section(
    tmp_path: Path,
) -> None:
    alert_type = "hostswapisfillingup"
    directory = tmp_path / alert_type
    directory.mkdir()
    runbook_id = "host-swap-guide"
    _write_text_pdf(
        directory / f"{runbook_id}.pdf",
        "HostSwapIsFillingUp warning and swap configuration diagnostic guide.",
    )
    hypothesis = "Swap usage is high while RAM is available due to configuration drift."
    _write_minimal_index(
        directory,
        alert_type,
        runbook_id,
        annotation_fields={
            "match": {
                "alert_names": ["HostSwapIsFillingUp"],
                "metric_names": [],
                "aliases": [],
                "keywords": [],
            },
            "sections": [
                {
                    "id": "alert-definition",
                    "title": "Alert definition",
                    "pages": [1],
                    "match_terms": ["HostSwapIsFillingUp"],
                },
                {
                    "id": "swap-diagnosis",
                    "title": "Swap and RAM diagnosis",
                    "pages": [1],
                },
            ],
            "causes": [
                {
                    "cause_id": "swap-config-drift",
                    "hypothesis": hypothesis,
                    "section_ids": ["swap-diagnosis"],
                }
            ],
        },
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "HostSwapIsFillingUp",
            "reason": "HostSwapIsFillingUp",
            "alert_type": alert_type,
            "alert_name": "HostSwapIsFillingUp",
            "error_summary": hypothesis,
            "description": hypothesis,
        }
    )

    matches = await LocalPDFRunbookLibrary(tmp_path).search(alert)

    assert matches[0].section == "swap-diagnosis"
    assert [cause.cause_id for cause in matches[0].causes] == [
        "swap-config-drift"
    ]
    assert "候选原因证据命中" in matches[0].match_reasons


def test_alert_type_directory_name_is_shared_and_path_safe() -> None:
    assert alert_type_directory_name(" MySQL/Slow Query 400 ") == (
        "mysql_slow_query_400"
    )
    assert alert_type_directory_name("DM-validator.binlog") == (
        "dm_validator_binlog"
    )


def test_derive_runbook_alert_types_collects_all_normalized_candidates() -> None:
    assert derive_runbook_alert_types(
        "ignored",
        {
            "alert_type": "Replica Lag",
            "alert_types": ["Replica Lag", "MySQL/Crash", "Replica Lag"],
        },
    ) == ["replica_lag", "mysql_crash"]
    assert derive_runbook_alert_types(
        "This text does not need a labelled fallback.",
        {
            "match": {
                "alert_names": ["Replica Lag", "MySQL/Crash"],
                "metric_names": ["Replica Lag"],
            }
        },
    ) == ["mysql_crash", "replica_lag"]
    assert derive_runbook_alert_types(
        "Alert Type: MySQL/Crash, Replica Lag\nAlert Name: MySQL/Crash"
    ) == ["mysql_crash", "replica_lag"]
    assert derive_runbook_alert_types("告警名称: ReplicaLag 告警") == ["replicalag"]

    with pytest.raises(RunbookError, match="multiple alert types"):
        derive_runbook_alert_type(
            "ignored",
            {"match": {"alert_names": ["Replica Lag", "MySQL/Crash"]}},
        )
    with pytest.raises(RunbookError, match="must also be included"):
        derive_runbook_alert_types(
            "ignored",
            {
                "alert_type": "Disk Full",
                "alert_types": ["Replica Lag", "MySQL/Crash"],
            },
        )


def test_runbook_models_do_not_expose_quality_or_review_status_fields() -> None:
    assert "quality_status" not in RunbookExcerpt.model_fields
    assert "quality_status" not in RunbookDocument.model_fields
    assert "review_status" not in RunbookVisualEvidence.model_fields


@pytest.mark.asyncio
@requires_repository_annotations
async def test_local_pdf_runbook_matches_identifier_terms_split_by_chinese(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "mysql_crash"
    directory.mkdir()
    copy2(MYSQL_CRASH_PDF, directory / MYSQL_CRASH_PDF.name)
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Synthetic database crash",
            "reason": "Synthetic database crash",
        }
    )

    matches = await library.search(alert)

    assert [item.runbook_id for item in matches] == [MYSQL_CRASH_PDF.stem]


@pytest.mark.asyncio
async def test_local_pdf_runbook_rejects_image_only_pdf(tmp_path: Path) -> None:
    directory = tmp_path / "image_only"
    directory.mkdir()
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    with (directory / "image-only.pdf").open("wb") as handle:
        writer.write(handle)

    with pytest.raises(RunbookError, match="OCR is required"):
        await LocalPDFRunbookLibrary(tmp_path).list()


@pytest.mark.asyncio
async def test_local_pdf_runbook_get_rejects_unsafe_id(tmp_path: Path) -> None:
    library = LocalPDFRunbookLibrary(tmp_path)

    with pytest.raises(InvalidRunbookIdError):
        await library.get("../escape")


@pytest.mark.asyncio
async def test_identical_multi_alert_copies_are_deduplicated_globally(
    tmp_path: Path,
) -> None:
    first_type = "connection_failure"
    second_type = "replica_lag"
    runbook_id = "shared-diagnosis"
    first_directory = tmp_path / first_type
    second_directory = tmp_path / second_type
    first_directory.mkdir()
    second_directory.mkdir()
    first_pdf = first_directory / f"{runbook_id}.pdf"
    second_pdf = second_directory / f"{runbook_id}.pdf"
    _write_text_pdf(
        first_pdf,
        "Shared database diagnosis guide with safe investigation steps.",
    )
    copy2(first_pdf, second_pdf)
    _write_minimal_index(first_directory, first_type, runbook_id)
    _write_minimal_index(second_directory, second_type, runbook_id)
    library = LocalPDFRunbookLibrary(
        tmp_path,
        min_score=0,
        min_confidence=0,
    )

    documents = await library.list()
    document = await library.get(runbook_id)
    second_type_alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": second_type,
            "alert_type": second_type,
        }
    )
    second_type_matches = await library.search(second_type_alert)

    assert [item.id for item in documents] == [runbook_id]
    assert documents[0].metadata["alert_types"] == [first_type, second_type]
    assert documents[0].metadata["alert_type"] == first_type
    assert document.id == runbook_id
    assert document.metadata["alert_types"] == [first_type, second_type]
    assert [item.runbook_id for item in second_type_matches] == [runbook_id]
    assert second_type_matches[0].metadata["alert_type"] == second_type
    assert second_type_matches[0].metadata["alert_types"] == [second_type]


@pytest.mark.asyncio
async def test_multi_alert_copy_uses_its_alert_type_profile(tmp_path: Path) -> None:
    first_type = "connection_failure"
    second_type = "replica_lag"
    runbook_id = "profiled-diagnosis"
    first_directory = tmp_path / first_type
    second_directory = tmp_path / second_type
    first_directory.mkdir()
    second_directory.mkdir()
    first_pdf = first_directory / f"{runbook_id}.pdf"
    _write_text_pdf(
        first_pdf,
        "Shared database troubleshooting guide with safe investigation steps.",
    )
    copy2(first_pdf, second_directory / first_pdf.name)
    annotation_fields = {
        "match": {
            "alert_names": ["Connection Failure", "Replica Lag"],
            "metric_names": ["connection_errors", "replica_delay_seconds"],
        },
        "alert_type_profiles": {
            first_type: {
                "alert_names": ["Connection Failure"],
                "metric_names": ["connection_errors"],
            },
            second_type: {
                "alert_names": ["Replica Lag"],
                "metric_names": ["replica_delay_seconds"],
            },
        },
    }
    _write_minimal_index(
        first_directory,
        first_type,
        runbook_id,
        annotation_fields=annotation_fields,
    )
    _write_minimal_index(
        second_directory,
        second_type,
        runbook_id,
        annotation_fields=annotation_fields,
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica Lag",
            "reason": "replica_delay_seconds",
            "alert_name": "Replica Lag",
            "metric_name": "replica_delay_seconds",
            "alert_type": second_type,
        }
    )

    matches = await LocalPDFRunbookLibrary(tmp_path).search(alert)

    assert [item.runbook_id for item in matches] == [runbook_id]
    assert matches[0].metadata["match"]["alert_names"] == ["Replica Lag"]
    assert matches[0].metadata["match"]["metric_names"] == [
        "replica_delay_seconds"
    ]


@pytest.mark.asyncio
async def test_conflicting_multi_alert_copies_are_rejected(
    tmp_path: Path,
) -> None:
    first_type = "connection_failure"
    second_type = "replica_lag"
    runbook_id = "conflicting-diagnosis"
    first_directory = tmp_path / first_type
    second_directory = tmp_path / second_type
    first_directory.mkdir()
    second_directory.mkdir()
    _write_text_pdf(
        first_directory / f"{runbook_id}.pdf",
        "Connection failure diagnosis guide with safe investigation steps.",
    )
    _write_text_pdf(
        second_directory / f"{runbook_id}.pdf",
        "Replica lag diagnosis guide with different investigation steps.",
    )
    _write_minimal_index(first_directory, first_type, runbook_id)
    _write_minimal_index(second_directory, second_type, runbook_id)
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Connection failure",
            "reason": first_type,
            "alert_type": first_type,
        }
    )

    with pytest.raises(RunbookError, match="Conflicting PDF runbook copies"):
        await library.list()
    with pytest.raises(RunbookError, match="Conflicting PDF runbook copies"):
        await library.get(runbook_id)
    with pytest.raises(RunbookError, match="Conflicting PDF runbook copies"):
        await library.search(alert)


@pytest.mark.asyncio
async def test_multi_alert_copies_with_conflicting_annotations_are_rejected(
    tmp_path: Path,
) -> None:
    first_type = "connection_failure"
    second_type = "replica_lag"
    runbook_id = "annotation-conflict"
    first_directory = tmp_path / first_type
    second_directory = tmp_path / second_type
    first_directory.mkdir()
    second_directory.mkdir()
    first_pdf = first_directory / f"{runbook_id}.pdf"
    _write_text_pdf(
        first_pdf,
        "Shared database diagnosis guide with safe investigation steps.",
    )
    copy2(first_pdf, second_directory / first_pdf.name)
    _write_minimal_index(first_directory, first_type, runbook_id)
    _write_minimal_index(
        second_directory,
        second_type,
        runbook_id,
        annotation_fields={"deprecated": True},
    )
    library = LocalPDFRunbookLibrary(tmp_path)
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Connection failure",
            "reason": first_type,
            "alert_type": first_type,
        }
    )

    with pytest.raises(
        RunbookError,
        match="different structured annotations",
    ):
        await library.list()
    with pytest.raises(
        RunbookError,
        match="different structured annotations",
    ):
        await library.get(runbook_id)
    with pytest.raises(
        RunbookError,
        match="different structured annotations",
    ):
        await library.search(alert)


@pytest.mark.asyncio
@requires_repository_annotations
async def test_repository_annotations_provide_sections_and_diagnosis_graph() -> None:
    library = LocalPDFRunbookLibrary(SOURCE_PDFS)
    documents = await library.list()
    template = next(item for item in documents if item.id == "SYNTHETIC-RUNBOOK-ID")
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "CRITICAL",
            "title": "Synthetic replica lag alert",
            "reason": "synthetic_replica_lag_high",
            "database": {"engine": "TiDB"},
            "labels": {"type": "unreachable"},
        }
    )

    matches = await library.search(alert)

    assert template.knowledge_type.value == "incomplete"
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
    assert "visual_review_complete" not in tikv.metadata


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
            "title": "Synthetic archive task failed",
            "alert_type": "Synthetic archive task failed",
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
            "alert_type": "synthetic_replica_lag_high",
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
async def test_database_scope_tolerates_present_target_with_unknown_engine(
    tmp_path: Path,
) -> None:
    library = _self_contained_library(
        tmp_path,
        scope={"database_engines": ["mysql"], "components": []},
    )
    alert = CanonicalAlertSourceAdapter().normalize(
        {
            "severity": "WARNING",
            "title": "Replica lag",
            "reason": "replica_lag",
            "alert_name": "ReplicaLag",
            "database": {"instance": "database-01"},
        }
    )

    assert [item.runbook_id for item in await library.search(alert)] == [
        "replica-lag-runbook"
    ]


@pytest.mark.asyncio
@requires_repository_annotations
async def test_runbook_without_visual_annotations_reports_incomplete_coverage(
    tmp_path: Path,
) -> None:
    pdf_dir = tmp_path / "pdfs"
    alert_type_dir = pdf_dir / "synthetic_replica_lag_high"
    alert_type_dir.mkdir(parents=True)
    copy2(TIKV_PDF, alert_type_dir / TIKV_PDF.name)
    annotation_path = alert_type_dir / "index.json"
    annotation_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "alert_type": "synthetic_replica_lag_high",
                "runbooks": [
                    {
                        "runbook_id": TIKV_PDF.stem,
                        "knowledge_type": "runbook",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    documents = await LocalPDFRunbookLibrary(pdf_dir).list()

    assert len(documents) == 1
    assert documents[0].metadata["unannotated_image_pages"]
    assert documents[0].metadata["visual_coverage_complete"] is False
