from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain.alert_preprocessing import (
    has_management_platform_sql_filter_note,
    is_management_platform_collection_sql_cause,
)
from app.domain.models import (
    AnalysisBasisSource,
    EvidenceRecord,
    ExternalKnowledgeReference,
    InvestigationRun,
    NormalizedAlert,
    Recommendation,
    RootCauseAssessment,
    RootCauseStatus,
    RunbookExcerpt,
    RunbookReference,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)
from app.investigations.models import (
    EvidenceRelation,
    Hypothesis,
    InvestigationMemory,
)

_DANGEROUS_ACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DROP", re.compile(r"(?<![A-Z0-9_])DROP(?![A-Z0-9_])", re.IGNORECASE)),
    ("TRUNCATE", re.compile(r"(?<![A-Z0-9_])TRUNCATE(?![A-Z0-9_])", re.IGNORECASE)),
    ("DELETE", re.compile(r"(?<![A-Z0-9_])DELETE(?![A-Z0-9_])", re.IGNORECASE)),
    ("UPDATE", re.compile(r"(?<![A-Z0-9_])UPDATE(?![A-Z0-9_])", re.IGNORECASE)),
    ("INSERT", re.compile(r"(?<![A-Z0-9_])INSERT(?![A-Z0-9_])", re.IGNORECASE)),
    ("ALTER", re.compile(r"(?<![A-Z0-9_])ALTER(?![A-Z0-9_])", re.IGNORECASE)),
    ("RESTART/REBOOT", re.compile(r"\b(?:RESTART|REBOOT)\b", re.IGNORECASE)),
    (
        "KILL/TERMINATE SESSION",
        re.compile(
            r"\b(?:KILL|TERMINATE)\s+(?:SESSION|CONNECTION|QUERY|PROCESS)\b",
            re.IGNORECASE,
        ),
    ),
    ("SHUTDOWN", re.compile(r"\bSHUTDOWN\b", re.IGNORECASE)),
    ("重启", re.compile(r"重启")),
    ("终止会话/连接", re.compile(r"终止.{0,8}(?:会话|连接|查询|进程)")),
    ("杀会话/连接", re.compile(r"(?:杀掉?|强杀).{0,8}(?:会话|连接|查询|进程)")),
)


@dataclass(frozen=True)
class _HypothesisBinding:
    hypothesis: Hypothesis
    status: RootCauseStatus
    supporting_refs: tuple[str, ...]
    contradicting_refs: tuple[str, ...]
    inconclusive_refs: frozenset[str]


def _build_hypothesis_bindings(
    memory: InvestigationMemory,
    evidence: list[EvidenceRecord],
) -> dict[str, _HypothesisBinding]:
    """Derive causal state from Host-owned assessments and eligible evidence."""

    evidence_by_id = {str(item.id): item for item in evidence}
    memory_evidence_by_id = memory.evidence_by_id()
    relation_by_key = {
        (assessment.hypothesis_id, assessment.evidence_id): assessment.relation
        for assessment in memory.assessments
    }

    def is_same_qualified_record(evidence_id: str) -> bool:
        record = evidence_by_id.get(evidence_id)
        memory_record = memory_evidence_by_id.get(evidence_id)
        return (
            record is not None
            and memory_record == record
            and record.is_root_cause_support_eligible()
        )

    bindings: dict[str, _HypothesisBinding] = {}
    for hypothesis in memory.hypotheses:
        hypothesis_id = hypothesis.hypothesis_id
        supporting_refs = tuple(
            evidence_id
            for evidence_id in hypothesis.supporting_evidence_ids
            if hypothesis.causal_candidate
            and relation_by_key.get((hypothesis_id, evidence_id)) == EvidenceRelation.SUPPORTS
            and is_same_qualified_record(evidence_id)
        )
        contradicting_refs = tuple(
            evidence_id
            for evidence_id in hypothesis.contradicting_evidence_ids
            if hypothesis.causal_candidate
            and relation_by_key.get((hypothesis_id, evidence_id)) == EvidenceRelation.CONTRADICTS
            and is_same_qualified_record(evidence_id)
        )
        inconclusive_refs = frozenset(
            assessment.evidence_id
            for assessment in memory.assessments
            if assessment.hypothesis_id == hypothesis_id
            and assessment.relation == EvidenceRelation.INCONCLUSIVE
            and memory_evidence_by_id.get(assessment.evidence_id)
            == evidence_by_id.get(assessment.evidence_id)
            and assessment.evidence_id in evidence_by_id
        )
        status = (
            RootCauseStatus.CONTRADICTED
            if contradicting_refs
            else RootCauseStatus.SUPPORTED
            if supporting_refs
            else RootCauseStatus.UNKNOWN
        )
        bindings[hypothesis_id] = _HypothesisBinding(
            hypothesis=hypothesis,
            status=status,
            supporting_refs=supporting_refs,
            contradicting_refs=contradicting_refs,
            inconclusive_refs=inconclusive_refs,
        )
    return bindings


def _bind_root_causes_to_memory(
    root_causes: list[RootCauseAssessment],
    memory: InvestigationMemory,
    evidence: list[EvidenceRecord],
) -> tuple[list[RootCauseAssessment], bool]:
    """Canonicalize model output to one Host-verifiable hypothesis per cause."""

    bindings = _build_hypothesis_bindings(memory, evidence)
    bound_causes: list[RootCauseAssessment] = []
    seen_hypothesis_ids: set[str] = set()
    invalid_binding = False

    for root_cause in root_causes:
        hypothesis_id = root_cause.hypothesis_id
        binding = bindings.get(hypothesis_id or "")
        if hypothesis_id is None or binding is None or hypothesis_id in seen_hypothesis_ids:
            invalid_binding = True
            continue
        seen_hypothesis_ids.add(hypothesis_id)

        # Contradicted hypotheses are never user-visible final causes.
        if binding.status == RootCauseStatus.CONTRADICTED:
            continue

        submitted_refs = tuple(dict.fromkeys(root_cause.evidence_refs))
        allowed_refs = (
            frozenset(binding.supporting_refs)
            if binding.status == RootCauseStatus.SUPPORTED
            else binding.inconclusive_refs
        )
        if (
            len(submitted_refs) != len(root_cause.evidence_refs)
            or any(evidence_id not in allowed_refs for evidence_id in submitted_refs)
            or (binding.status == RootCauseStatus.SUPPORTED and not submitted_refs)
        ):
            invalid_binding = True

        expected_verified = binding.status == RootCauseStatus.SUPPORTED
        if (
            root_cause.cause.strip() != binding.hypothesis.mechanism.strip()
            or root_cause.status != binding.status
            or root_cause.verified != expected_verified
            or binding.hypothesis.status != binding.status
        ):
            invalid_binding = True

        if binding.status == RootCauseStatus.SUPPORTED:
            canonical_refs = list(binding.supporting_refs)
            next_probe = None
            confidence = root_cause.confidence
        else:
            canonical_refs = [
                evidence_id
                for evidence_id in submitted_refs
                if evidence_id in binding.inconclusive_refs
            ]
            next_probe = (
                binding.hypothesis.next_probe.objective
                if binding.hypothesis.next_probe is not None
                else root_cause.next_probe or "补充可验证该原因必要预测的实时只读证据。"
            )
            confidence = min(root_cause.confidence, 0.45)

        bound_causes.append(
            root_cause.model_copy(
                update={
                    "cause": binding.hypothesis.mechanism,
                    "status": binding.status,
                    "evidence_refs": canonical_refs,
                    "confidence": confidence,
                    "verified": expected_verified,
                    "next_probe": next_probe,
                }
            )
        )

    return bound_causes, invalid_binding


def _root_cause_binding_issues(
    recommendation: Recommendation,
    memory: InvestigationMemory,
    evidence: list[EvidenceRecord],
) -> list[str]:
    """Validate the final object independently of the normalization path."""

    bindings = _build_hypothesis_bindings(memory, evidence)
    issues: list[str] = []
    seen_hypothesis_ids: set[str] = set()
    for index, root_cause in enumerate(recommendation.root_causes, start=1):
        hypothesis_id = root_cause.hypothesis_id
        if hypothesis_id is None:
            issues.append(f"根因 #{index} 缺少 hypothesis_id，无法绑定调查假设")
            continue
        binding = bindings.get(hypothesis_id)
        if binding is None:
            issues.append(f"根因 #{index} 引用了不存在的调查假设：{hypothesis_id}")
            continue
        if hypothesis_id in seen_hypothesis_ids:
            issues.append(f"根因 #{index} 重复引用调查假设：{hypothesis_id}")
            continue
        seen_hypothesis_ids.add(hypothesis_id)

        if root_cause.cause.strip() != binding.hypothesis.mechanism.strip():
            issues.append(
                f"根因 #{index}（{root_cause.cause.strip() or '未命名根因'}）与调查假设"
                f" {hypothesis_id} 的 mechanism 不一致"
            )
        if root_cause.status != binding.status:
            issues.append(
                f"根因 #{index} 的状态与调查假设 {hypothesis_id} 的 Host 评估不一致："
                f"{root_cause.status.value} != {binding.status.value}"
            )
        if binding.hypothesis.status != binding.status:
            issues.append(f"调查假设 {hypothesis_id} 的状态与其有效 evidence assessments 不一致")

        evidence_refs = tuple(root_cause.evidence_refs)
        if len(evidence_refs) != len(set(evidence_refs)):
            issues.append(f"根因 #{index} 包含重复 evidence_refs")
        if binding.status == RootCauseStatus.SUPPORTED:
            if evidence_refs != binding.supporting_refs:
                issues.append(
                    f"根因 #{index} 的 evidence_refs 未完整绑定调查假设 "
                    f"{hypothesis_id} 的 SUPPORTS assessments"
                )
            if not root_cause.verified:
                issues.append(f"根因 #{index} 与 SUPPORTED 调查假设绑定时必须 verified=true")
        elif binding.status == RootCauseStatus.UNKNOWN:
            invalid_refs = [
                evidence_id
                for evidence_id in evidence_refs
                if evidence_id not in binding.inconclusive_refs
            ]
            if invalid_refs:
                issues.append(
                    f"根因 #{index} 引用了不属于调查假设 {hypothesis_id} 的 "
                    f"INCONCLUSIVE assessments：{', '.join(invalid_refs)}"
                )
            if root_cause.verified:
                issues.append(f"根因 #{index} 与 UNKNOWN 调查假设绑定时必须 verified=false")

    return issues


def enforce_post_evidence_root_cause_policy(
    recommendation: Recommendation,
    evidence: list[EvidenceRecord],
    alert: NormalizedAlert | None = None,
    investigation_memory: InvestigationMemory | None = None,
) -> Recommendation:
    """Enforce causal evidence eligibility on the final recommendation.

    ``CONTRADICTED`` is retained in the enum so historical recommendations remain
    readable. New recommendations contain only causes that remain plausible after
    all collected evidence has been considered, and unsupported decisive states
    are downgraded to ``UNKNOWN`` for human review.
    """

    evidence_by_id = {str(item.id): item for item in evidence}
    plausible_causes: list[RootCauseAssessment] = []
    root_causes = recommendation.root_causes
    invalid_causal_assessment = False
    if investigation_memory is not None:
        root_causes, invalid_causal_assessment = _bind_root_causes_to_memory(
            root_causes,
            investigation_memory,
            evidence,
        )
    filtered_metric_cause = False
    management_sql_already_filtered = bool(
        alert and has_management_platform_sql_filter_note(alert.raw_payload)
    )

    for root_cause in root_causes:
        if management_sql_already_filtered and is_management_platform_collection_sql_cause(
            root_cause.cause
        ):
            filtered_metric_cause = True
            continue
        if root_cause.status == RootCauseStatus.UNKNOWN:
            plausible_causes.append(root_cause)
            continue

        has_qualified_live_evidence = any(
            (record := evidence_by_id.get(evidence_ref)) is not None
            and record.is_root_cause_support_eligible()
            for evidence_ref in dict.fromkeys(root_cause.evidence_refs)
        )
        if root_cause.status == RootCauseStatus.CONTRADICTED and has_qualified_live_evidence:
            continue
        if root_cause.status == RootCauseStatus.SUPPORTED and has_qualified_live_evidence:
            plausible_causes.append(root_cause)
            continue

        invalid_causal_assessment = True
        plausible_causes.append(
            root_cause.model_copy(
                update={
                    "status": RootCauseStatus.UNKNOWN,
                    "evidence_refs": [],
                    "confidence": min(root_cause.confidence, 0.45),
                    "verified": False,
                    "next_probe": root_cause.next_probe
                    or "补充可验证该原因必要预测的实时只读证据。",
                }
            )
        )

    return recommendation.model_copy(
        update={
            "root_causes": plausible_causes,
            "likely_causes": [item.cause for item in plausible_causes],
            "requires_human": (
                recommendation.requires_human
                or not plausible_causes
                or invalid_causal_assessment
                or filtered_metric_cause
                or any(item.status == RootCauseStatus.UNKNOWN for item in plausible_causes)
            ),
        }
    )


class RuleConclusionValidator:
    """Validate a recommendation using deterministic safety and provenance rules."""

    async def validate(
        self,
        run: InvestigationRun,
        alert: NormalizedAlert,
        recommendation: Recommendation,
        evidence: list[EvidenceRecord],
        runbooks: list[RunbookExcerpt],
        investigation_memory: InvestigationMemory | None = None,
    ) -> ValidationRecord:
        issues: list[str] = []
        binding_issues: list[str] = []
        if investigation_memory is not None:
            binding_issues = _root_cause_binding_issues(
                recommendation,
                investigation_memory,
                evidence,
            )
            issues.extend(binding_issues)
        evidence_by_id = {str(item.id): item for item in evidence}
        has_supported_cause = False
        all_causes_decisive = bool(recommendation.root_causes)

        for index, root_cause in enumerate(recommendation.root_causes, start=1):
            cause_label = root_cause.cause.strip() or "未命名根因"
            live_successful_refs: set[str] = set()

            for evidence_ref in dict.fromkeys(root_cause.evidence_refs):
                record = evidence_by_id.get(evidence_ref)
                if record is None:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了不存在的证据：{evidence_ref}"
                    )
                    continue
                if record.status != ToolStatus.SUCCESS:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用的证据不是 SUCCESS："
                        f"{evidence_ref}（{record.status.value}）"
                    )
                    continue
                if record.is_root_cause_support_eligible():
                    live_successful_refs.add(evidence_ref)
                elif (
                    root_cause.status != RootCauseStatus.UNKNOWN
                    and record.structured_data.get("partial") is True
                ):
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了 partial=true 的部分证据："
                        f"{evidence_ref}；部分结果只能作为描述性上下文"
                    )
                elif (
                    root_cause.status != RootCauseStatus.UNKNOWN
                    and record.structured_data.get("root_cause_eligible") is False
                ):
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了明确标记为不能支持"
                        f"根因的证据：{evidence_ref}"
                    )

            if root_cause.verified and not live_successful_refs:
                issues.append(
                    f"已验证根因 #{index}（{cause_label}）必须至少引用一条 SUCCESS 证据"
                    "（且来自实时系统）"
                )
            if root_cause.status == RootCauseStatus.SUPPORTED and not live_successful_refs:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）缺少实时 SUCCESS 证据")
                all_causes_decisive = False
            if root_cause.status == RootCauseStatus.SUPPORTED:
                has_supported_cause = True
                if not root_cause.verified:
                    issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）必须标记 verified=true")
            elif root_cause.status == RootCauseStatus.CONTRADICTED:
                issues.append(
                    f"根因 #{index}（{cause_label}）已被实时证据反驳，必须在最终结果生成前直接移除"
                )
                all_causes_decisive = False
            else:
                all_causes_decisive = False
                if not (root_cause.next_probe or "").strip():
                    issues.append(f"UNKNOWN 根因 #{index}（{cause_label}）必须提供具体 next_probe")
            if root_cause.status != RootCauseStatus.SUPPORTED and root_cause.verified:
                issues.append(f"根因 #{index}（{cause_label}）只有 SUPPORTED 状态才能标记已验证")

        evidence_sufficient = (
            has_supported_cause
            and all_causes_decisive
            and bool(recommendation.root_causes)
            and not binding_issues
        )
        if not evidence_sufficient and not recommendation.requires_human:
            issues.append("实时证据不足时 recommendation.requires_human 必须为 true")

        manual_matched = recommendation.manual_matched
        sources = [item.source for item in recommendation.analysis_bases]
        valid_runbook_refs = {(excerpt.runbook_id, excerpt.section) for excerpt in runbooks}
        if AnalysisBasisSource.AI not in sources:
            issues.append("判断依据必须至少包含一条 AI 分析依据")
        if manual_matched:
            if AnalysisBasisSource.RUNBOOK not in sources:
                issues.append("命中手册时必须提供至少一条手册依据")
            for index, basis in enumerate(recommendation.analysis_bases, start=1):
                if basis.source != AnalysisBasisSource.RUNBOOK:
                    continue
                if not isinstance(basis.source_ref, RunbookReference):
                    issues.append(f"手册依据 #{index} 缺少 source_ref")
                    continue
                ref_key = (basis.source_ref.runbook_id, basis.source_ref.section)
                if ref_key not in valid_runbook_refs:
                    issues.append(
                        f"手册依据 #{index} 引用了无效章节："
                        f"{basis.source_ref.runbook_id}/{basis.source_ref.section}"
                    )
            known_cause_ids = {cause.cause_id for excerpt in runbooks for cause in excerpt.causes}
            for index, root_cause in enumerate(recommendation.root_causes, start=1):
                if root_cause.cause_id and root_cause.cause_id not in known_cause_ids:
                    issues.append(
                        f"根因 #{index} 引用了手册中不存在的 cause_id：{root_cause.cause_id}"
                    )
        elif recommendation.runbook_references or any(
            basis.source == AnalysisBasisSource.RUNBOOK for basis in recommendation.analysis_bases
        ):
            issues.append("未命中本地 PDF 时不得声称存在手册依据")

        external_matches = recommendation.external_knowledge_matches
        valid_external_refs = {
            item.knowledge_id: (item.title, item.source_uri) for item in external_matches
        }
        external_bases = [
            basis
            for basis in recommendation.analysis_bases
            if basis.source == AnalysisBasisSource.EXTERNAL_KNOWLEDGE
        ]
        if external_matches and not external_bases:
            issues.append("命中外部知识时必须提供至少一条外部知识依据")
        if not external_matches and external_bases:
            issues.append("未命中外部知识时不得声称存在外部知识依据")
        for index, basis in enumerate(recommendation.analysis_bases, start=1):
            if basis.source != AnalysisBasisSource.EXTERNAL_KNOWLEDGE:
                continue
            if not isinstance(basis.source_ref, ExternalKnowledgeReference):
                issues.append(f"外部知识依据 #{index} 缺少合法 source_ref")
                continue
            expected = valid_external_refs.get(basis.source_ref.knowledge_id)
            if expected is None:
                issues.append(
                    f"外部知识依据 #{index} 引用了未知条目：{basis.source_ref.knowledge_id}"
                )
            elif (basis.source_ref.title, basis.source_ref.source_uri) != expected:
                issues.append(f"外部知识依据 #{index} 的标题或来源与检索结果不一致")

        knowledge_matched = manual_matched or bool(external_matches)
        for index, step in enumerate(recommendation.steps, start=1):
            source_ref = step.source_ref
            if not knowledge_matched:
                if source_ref is not None:
                    issues.append(f"未命中知识时处理步骤 #{index} 不得提供 source_ref")
                continue
            if source_ref is None:
                issues.append(f"命中知识时处理步骤 #{index} 必须提供 source_ref")
            elif isinstance(source_ref, RunbookReference):
                ref_key = (source_ref.runbook_id, source_ref.section)
                if not manual_matched or ref_key not in valid_runbook_refs:
                    issues.append(
                        f"处理步骤 #{index} 引用了无效的手册章节："
                        f"{source_ref.runbook_id}/{source_ref.section}"
                    )
            elif isinstance(source_ref, ExternalKnowledgeReference):
                expected = valid_external_refs.get(source_ref.knowledge_id)
                if expected is None:
                    issues.append(
                        f"处理步骤 #{index} 引用了未知外部知识：{source_ref.knowledge_id}"
                    )
                elif (source_ref.title, source_ref.source_uri) != expected:
                    issues.append(f"处理步骤 #{index} 的外部知识标题或来源不一致")

        source_rank = {
            AnalysisBasisSource.RUNBOOK: 0,
            AnalysisBasisSource.EXTERNAL_KNOWLEDGE: 0,
            AnalysisBasisSource.AI: 1,
        }
        ranks = [source_rank[source] for source in sources]
        if ranks != sorted(ranks):
            issues.append("判断依据顺序错误：所有知识依据必须排在 AI 依据之前")

        for index, step in enumerate(recommendation.steps, start=1):
            matches = [
                label
                for label, pattern in _DANGEROUS_ACTION_PATTERNS
                if pattern.search(step.action)
            ]
            if matches:
                issues.append(f"处理步骤 #{index} 包含禁止的危险动作：{', '.join(matches)}")

        return ValidationRecord(
            run_id=run.id,
            kind=ValidationKind.RULE,
            passed=not issues,
            evidence_sufficient=evidence_sufficient,
            issues=issues,
            metadata={
                "validator": type(self).__name__,
                "alert_id": str(alert.id),
                "checked_root_causes": len(recommendation.root_causes),
                "checked_steps": len(recommendation.steps),
                "evidence_count": len(evidence),
                "runbook_count": len(runbooks),
                "external_knowledge_count": len(external_matches),
                "investigation_memory_bound": investigation_memory is not None,
            },
        )
