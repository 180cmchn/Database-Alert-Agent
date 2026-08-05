from types import SimpleNamespace

import pytest

from app.adapters import runbook_indexing
from app.adapters.runbook_indexing import (
    AutoIndexAction,
    AutoIndexAlertProfile,
    AutoIndexCause,
    AutoIndexSection,
    AutoRunbookIndexDraft,
    OpenAICompatibleRunbookIndexer,
    build_auto_annotation,
)
from app.domain.errors import RunbookError


def test_build_auto_annotation_merges_multiple_types_and_structured_content() -> None:
    first = AutoRunbookIndexDraft(
        alert_profiles=[
            AutoIndexAlertProfile(
                alert_type="MySQL/Crash",
                alert_names=["MySQL Crash"],
                aliases=["mysqld exited"],
                evidence_pages=[1],
            ),
            AutoIndexAlertProfile(
                alert_type="Connections High",
                metric_names=["threads_connected"],
                evidence_pages=[2],
            ),
        ],
        database_engines=["MySQL"],
        sections=[
            AutoIndexSection(
                title="Check service state",
                pages=[1, 2],
                match_terms=["mysqld", "threads_connected"],
            )
        ],
        causes=[
            AutoIndexCause(
                hypothesis="The database process exited unexpectedly.",
                pages=[1],
                supporting_evidence=["service is inactive"],
            )
        ],
        actions=[
            AutoIndexAction(
                action="Inspect the database service status.",
                pages=[1],
            ),
            AutoIndexAction(
                action="Restart the database service after approval.",
                pages=[1],
                execution_class="change",
            ),
        ],
    )
    second = AutoRunbookIndexDraft(
        alert_profiles=[
            AutoIndexAlertProfile(
                alert_type="mysql crash",
                keywords=["process exit"],
                evidence_pages=[2],
            )
        ]
    )

    annotation = build_auto_annotation(
        "shared-guide",
        [first, second],
        page_count=2,
        content_sha256="a" * 64,
        model="index-model",
    )

    assert annotation["alert_types"] == ["connections_high", "mysql_crash"]
    assert annotation["alert_type_profiles"]["mysql_crash"] == {
        "alert_names": ["MySQL Crash"],
        "metric_names": [],
        "aliases": ["mysqld exited"],
        "keywords": ["process exit"],
        "evidence_pages": [1, 2],
    }
    assert annotation["match"]["metric_names"] == ["threads_connected"]
    assert annotation["sections"][0]["pages"] == [1, 2]
    assert annotation["causes"][0]["section_ids"] == [
        annotation["sections"][0]["id"]
    ]
    assert annotation["actions"][0]["approval_required"] is False
    assert annotation["actions"][1]["approval_required"] is True
    assert annotation["metadata"]["auto_index"] == {
        "generator": "openai_compatible",
        "model": "index-model",
        "prompt_version": "runbook-auto-index-v1",
        "content_sha256": "a" * 64,
    }


def test_build_auto_annotation_rejects_out_of_range_pages() -> None:
    draft = AutoRunbookIndexDraft(
        alert_profiles=[
            AutoIndexAlertProfile(
                alert_type="replica_lag",
                evidence_pages=[2],
            )
        ]
    )

    with pytest.raises(RunbookError, match="invalid alert profile pages"):
        build_auto_annotation(
            "replica-guide",
            [draft],
            page_count=1,
            content_sha256="b" * 64,
            model="index-model",
        )


@pytest.mark.asyncio
async def test_openai_indexer_extracts_multiple_alert_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    closed = False

    class FakeCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            return SimpleNamespace(
                id="index-request-1",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=(
                                '{"alert_profiles":['
                                '{"alert_type":"replica_lag",'
                                '"alert_names":["Replica Lag"],'
                                '"evidence_pages":[1]},'
                                '{"alert_type":"connections_high",'
                                '"metric_names":["threads_connected"],'
                                '"evidence_pages":[1]}],'
                                '"database_engines":["mysql"],'
                                '"components":[],"sections":[],"causes":[],'
                                '"actions":[]}'
                            )
                        )
                    )
                ],
            )

    class FakeClient:
        def __init__(self) -> None:
            self.chat = SimpleNamespace(completions=FakeCompletions())

        async def close(self) -> None:
            nonlocal closed
            closed = True

    fake_client = FakeClient()
    monkeypatch.setattr(
        runbook_indexing,
        "AsyncOpenAI",
        lambda **_: fake_client,
    )
    monkeypatch.setattr(
        runbook_indexing,
        "_system_trust_http_client",
        lambda _: object(),
    )
    indexer = OpenAICompatibleRunbookIndexer(
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="index-model",
        max_tokens=4096,
        timeout_seconds=30,
        max_retries=1,
        json_mode=True,
    )

    annotation = await indexer.generate_annotation(
        "shared-guide",
        ["Replica Lag and connections high handling steps."],
    )
    await indexer.aclose()

    assert annotation["alert_types"] == ["connections_high", "replica_lag"]
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert calls[0]["temperature"] == 0
    assert closed is True
