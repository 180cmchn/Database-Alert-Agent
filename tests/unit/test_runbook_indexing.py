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
        provider="openai_compatible",
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
        "prompt_version": "runbook-auto-index-v2",
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
            provider="openai_compatible",
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
        provider="openai_compatible",
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
    assert len(calls) == 1
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert calls[0]["temperature"] == 0
    assert closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("use_output_text_helper", [True, False])
async def test_openai_responses_indexer_uses_responses_protocol_and_records_generator(
    monkeypatch: pytest.MonkeyPatch,
    use_output_text_helper: bool,
) -> None:
    calls: list[dict[str, object]] = []
    content = (
        '{"alert_profiles":[{'
        '"alert_type":"replica_lag",'
        '"alert_names":["Replica Lag"],'
        '"evidence_pages":[1]}]}'
    )

    class FakeResponses:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            if use_output_text_helper:
                return SimpleNamespace(
                    id="responses-index-request-1",
                    output_text=content,
                    output=[],
                )
            return SimpleNamespace(
                id="responses-index-request-1",
                output_text="",
                output=[
                    SimpleNamespace(type="reasoning", summary=[]),
                    SimpleNamespace(
                        type="message",
                        content=[
                            SimpleNamespace(type="output_text", text=content)
                        ],
                    ),
                ],
            )

    class UnexpectedCompletions:
        async def create(self, **kwargs: object) -> None:
            raise AssertionError(f"Chat Completions must not be called: {kwargs}")

    class FakeClient:
        def __init__(self) -> None:
            self.responses = FakeResponses()
            self.chat = SimpleNamespace(completions=UnexpectedCompletions())

        async def close(self) -> None:
            return None

    monkeypatch.setattr(runbook_indexing, "AsyncOpenAI", lambda **_: FakeClient())
    monkeypatch.setattr(
        runbook_indexing,
        "_system_trust_http_client",
        lambda _: object(),
    )
    indexer = OpenAICompatibleRunbookIndexer(
        provider="openai_responses",
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="index-model",
        max_tokens=4096,
        timeout_seconds=30,
        max_retries=1,
        json_mode=True,
    )

    annotation = await indexer.generate_annotation(
        "replica-guide",
        ["Replica Lag diagnostic and handling steps."],
    )
    await indexer.aclose()

    assert annotation["alert_types"] == ["replica_lag"]
    assert annotation["metadata"]["auto_index"]["generator"] == "openai_responses"
    assert len(calls) == 1
    request = calls[0]
    assert request["model"] == "index-model"
    assert request["max_output_tokens"] == 4096
    assert request["store"] is False
    assert request["text"] == {"format": {"type": "json_object"}}
    assert isinstance(request["input"], list)
    assert "temperature" not in request
    assert "messages" not in request
    assert "max_tokens" not in request
    assert "response_format" not in request


def _install_index_responses(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[str],
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    queued = list(responses)

    class FakeCompletions:
        async def create(self, **kwargs: object) -> SimpleNamespace:
            calls.append(kwargs)
            if not queued:
                raise AssertionError("Unexpected automatic index model call")
            return SimpleNamespace(
                id=f"index-request-{len(calls)}",
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content=queued.pop(0))
                    )
                ],
            )

    class FakeClient:
        def __init__(self) -> None:
            self.chat = SimpleNamespace(completions=FakeCompletions())

        async def close(self) -> None:
            return None

    monkeypatch.setattr(runbook_indexing, "AsyncOpenAI", lambda **_: FakeClient())
    monkeypatch.setattr(
        runbook_indexing,
        "_system_trust_http_client",
        lambda _: object(),
    )
    return calls


def _test_indexer() -> OpenAICompatibleRunbookIndexer:
    return OpenAICompatibleRunbookIndexer(
        provider="openai_compatible",
        api_key="test-key",
        base_url="https://models.example.test/v1",
        model="index-model",
        max_tokens=4096,
        timeout_seconds=30,
        max_retries=1,
        json_mode=True,
    )


@pytest.mark.asyncio
async def test_openai_indexer_retries_when_first_pass_has_no_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_index_responses(
        monkeypatch,
        [
            '{"alert_profiles":[]}',
            (
                '{"alert_profiles":[{'
                '"alert_type":"MySQL CPU 飙升",'
                '"alert_names":["MySQL CPU 飙升"],'
                '"evidence_pages":[1]}],'
                '"database_engines":["mysql"]}'
            ),
        ],
    )
    indexer = _test_indexer()

    annotation = await indexer.generate_annotation(
        "cpu-spike-guide",
        ['案件标题：“抽数 SQL 引发 MySQL CPU 飙升的应急处置”'],
    )
    await indexer.aclose()

    assert annotation["alert_types"] == ["mysql_cpu_飙升"]
    assert len(calls) == 2
    recovery_messages = calls[1]["messages"]
    assert isinstance(recovery_messages, list)
    assert "empty_profile_recovery" in recovery_messages[1]["content"]
    assert "症状" in recovery_messages[0]["content"]


@pytest.mark.asyncio
async def test_openai_indexer_uses_literal_incident_title_after_empty_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_index_responses(
        monkeypatch,
        ['{"alert_profiles":[]}', '{"alert_profiles":[]}'],
    )
    indexer = _test_indexer()

    annotation = await indexer.generate_annotation(
        "cpu-spike-guide",
        [
            "xxxx-xx-xx KB模板\n"
            "案件标题：“抽数SQL引发MySQLCPU飙升的应急处置”\n"
            "后续优化：\n"
            "脚本名称： auto_kill_long_transaction.sh\n"
            "触发条件：事务执行时间>300s"
        ],
    )
    await indexer.aclose()

    assert annotation["alert_types"] == ["mysqlcpu飙升"]
    profile = annotation["alert_type_profiles"]["mysqlcpu飙升"]
    assert profile["alert_names"] == ["MySQLCPU飙升"]
    assert profile["evidence_pages"] == [1]
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_openai_indexer_still_rejects_unidentifiable_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_index_responses(
        monkeypatch,
        ['{"alert_profiles":[]}', '{"alert_profiles":[]}'],
    )
    indexer = _test_indexer()

    with pytest.raises(RunbookError, match="found no handled alert types"):
        await indexer.generate_annotation(
            "blank-guide",
            ["This reference lists database product names without handling steps."],
        )
    await indexer.aclose()
