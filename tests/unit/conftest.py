from __future__ import annotations

import os

import pytest


# Some modules construct the ASGI app during test collection, before fixtures run.
os.environ["STREAM_MAIN_AGENT_REASONING"] = "false"


@pytest.fixture(autouse=True)
def _required_runtime_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the deployment baseline used by isolated unit tests."""

    monkeypatch.setenv("STREAM_MAIN_AGENT_REASONING", "false")