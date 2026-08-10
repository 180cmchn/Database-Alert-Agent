"""Create falsifiable investigation memory from trusted structured inputs."""

from __future__ import annotations

import hashlib

from app.domain.models import (
    InvestigationStrategy,
    NormalizedAlert,
    RunbookCause,
    RunbookExcerpt,
    ToolExecutionRequest,
)
from app.investigations.models import EvidenceNeed, Hypothesis, InvestigationMemory


def seed_investigation_memory(
    alert: NormalizedAlert,
    runbooks: list[RunbookExcerpt],
    strategy: InvestigationStrategy,
    *,
    available_tools: set[str],
) -> InvestigationMemory:
    """Build initial hypotheses without treating knowledge as incident truth."""

    requests_by_tool = _requests_by_tool(strategy.tool_plan)
    hypotheses: list[Hypothesis] = []
    seen_ids: set[str] = set()
    for runbook in runbooks:
        for cause in runbook.causes:
            hypothesis_id = _bounded_id(f"{runbook.runbook_id}:{cause.cause_id}")
            if hypothesis_id in seen_ids:
                continue
            seen_ids.add(hypothesis_id)
            hypotheses.append(
                _from_runbook_cause(
                    runbook,
                    cause,
                    hypothesis_id=hypothesis_id,
                    requests_by_tool=requests_by_tool,
                    available_tools=available_tools,
                )
            )

    if not hypotheses:
        hypotheses.append(
            _unresolved_hypothesis(
                strategy,
                available_tools=available_tools,
            )
        )

    target = alert.database
    target_ambiguous = target is None or not any(
        (target.instance, target.database, target.host, alert.cluster)
    )
    window_ambiguous = alert.occurred_at.tzinfo is None or alert.occurred_at.utcoffset() is None
    return InvestigationMemory(
        hypotheses=hypotheses,
        target_ambiguous=target_ambiguous,
        window_ambiguous=window_ambiguous,
    )


def _from_runbook_cause(
    runbook: RunbookExcerpt,
    cause: RunbookCause,
    *,
    hypothesis_id: str,
    requests_by_tool: dict[str, ToolExecutionRequest],
    available_tools: set[str],
) -> Hypothesis:
    expected = cause.supporting_evidence or [
        "Qualified live evidence from the affected system matches this mechanism."
    ]
    contradicting = cause.contradicting_evidence or [
        "Qualified live evidence conflicts with a necessary prediction of this mechanism."
    ]
    read_only_probe = next((probe for probe in cause.probes if probe.read_only), None)
    if read_only_probe is None:
        next_probe = EvidenceNeed(
            need_id=_bounded_id(f"{hypothesis_id}:missing-probe"),
            objective="Find a read-only probe that can discriminate this mechanism.",
            expected_observation=expected[0],
            contradicting_observation=contradicting[0],
            available=False,
            unavailable_reason=(
                "The matched knowledge cause does not define an approved read-only probe."
            ),
        )
    else:
        template = requests_by_tool.get(read_only_probe.tool_name)
        available = read_only_probe.tool_name in available_tools
        next_probe = EvidenceNeed(
            need_id=_bounded_id(f"{hypothesis_id}:{read_only_probe.tool_name}"),
            objective=read_only_probe.objective,
            expected_observation=expected[0],
            contradicting_observation=contradicting[0],
            tool_name=read_only_probe.tool_name,
            parameters=dict(template.parameters) if template is not None else {},
            available=available,
            unavailable_reason=(
                None
                if available
                else "The runbook probe is not available in the current tool catalog."
            ),
        )
    return Hypothesis(
        hypothesis_id=hypothesis_id,
        mechanism=cause.hypothesis,
        expected_observations=list(expected),
        contradicting_observations=list(contradicting),
        next_probe=next_probe,
        priority=max(1, min(100, round(runbook.match_confidence * 100))),
    )


def _unresolved_hypothesis(
    strategy: InvestigationStrategy,
    *,
    available_tools: set[str],
) -> Hypothesis:
    request = next(
        (
            item
            for item in strategy.tool_plan
            if item.tool_name != "alert_context" and item.tool_name in available_tools
        ),
        None,
    )
    if request is None:
        probe = EvidenceNeed(
            need_id="unresolved-cause:missing-probe",
            objective="Identify a safe read-only probe for the affected database target.",
            expected_observation="Live evidence identifies a causal mechanism.",
            contradicting_observation="Live evidence contradicts the candidate mechanism.",
            available=False,
            unavailable_reason="No discriminating read-only provider is available.",
        )
    else:
        probe = EvidenceNeed(
            need_id=_bounded_id(f"unresolved-cause:{request.tool_name}"),
            objective=(
                str(request.parameters.get("objective") or "Collect discriminating live evidence.")
            ),
            expected_observation="Live evidence identifies a causal mechanism.",
            contradicting_observation="Live evidence contradicts the candidate mechanism.",
            tool_name=request.tool_name,
            parameters=dict(request.parameters),
        )
    return Hypothesis(
        hypothesis_id="unresolved-cause",
        mechanism="合格实时证据尚未确定本次告警的因果机制。",
        causal_candidate=False,
        expected_observations=["A read-only live observation distinguishes a causal mechanism."],
        contradicting_observations=[
            "The observation conflicts with the necessary prediction of a candidate mechanism."
        ],
        next_probe=probe,
        priority=1,
    )


def _requests_by_tool(
    requests: list[ToolExecutionRequest],
) -> dict[str, ToolExecutionRequest]:
    return {request.tool_name: request for request in requests}


def _bounded_id(value: str) -> str:
    if len(value) <= 200:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{value[:183]}:{digest}"
