from __future__ import annotations

from app.domain.alert_preprocessing import (
    has_management_platform_sql_filter_note,
    is_management_platform_collection_sql_cause,
)
from app.domain.models import (
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
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


def enforce_post_evidence_root_cause_policy(
    recommendation: Recommendation,
    evidence: list[EvidenceRecord],
    alert: NormalizedAlert | None = None,
) -> Recommendation:
    """Validate evidence references in the main Agent's completed conclusion.

    This deterministic check never infers causality. Historical status values remain
    deserializable, but they are never accepted as output from the strict
    post-collection analysis phase.
    """

    evidence_by_id = {str(item.id): item for item in evidence}
    supported_causes: list[RootCauseAssessment] = []
    management_sql_already_filtered = bool(
        alert and has_management_platform_sql_filter_note(alert.raw_payload)
    )

    alert_reason = alert.reason.strip().casefold() if alert else ""
    for root_cause in recommendation.root_causes:
        if management_sql_already_filtered and is_management_platform_collection_sql_cause(
            root_cause.cause
        ):
            continue
        if not root_cause.cause.strip() or root_cause.status != RootCauseStatus.SUPPORTED:
            continue
        if alert_reason and root_cause.cause.strip().casefold() == alert_reason:
            continue
        qualified_refs = [
            evidence_ref
            for evidence_ref in dict.fromkeys(root_cause.evidence_refs)
            if (record := evidence_by_id.get(evidence_ref)) is not None
            and record.is_root_cause_support_eligible()
        ]
        if not qualified_refs:
            continue
        supported_causes.append(
            root_cause.model_copy(
                update={
                    "hypothesis_id": None,
                    "status": RootCauseStatus.SUPPORTED,
                    "evidence_refs": qualified_refs,
                    "verified": True,
                    "next_probe": None,
                }
            )
        )

    if not supported_causes:
        return recommendation.model_copy(
            update={
                "summary": INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
                "likely_causes": [],
                "root_causes": [],
                "confidence": 0,
            }
        )

    return recommendation.model_copy(
        update={
            "root_causes": supported_causes,
            "likely_causes": [item.cause for item in supported_causes],
        }
    )


class RuleConclusionValidator:
    """Validate output shape and provenance without reassessing causal reasoning."""

    async def validate(
        self,
        run: InvestigationRun,
        alert: NormalizedAlert,
        recommendation: Recommendation,
        evidence: list[EvidenceRecord],
        runbooks: list[RunbookExcerpt],
    ) -> ValidationRecord:
        issues: list[str] = []
        evidence_by_id = {str(item.id): item for item in evidence}
        has_supported_cause = bool(recommendation.root_causes)

        if not recommendation.root_causes:
            if recommendation.summary != INCONCLUSIVE_ROOT_CAUSE_SUMMARY:
                issues.append(
                    "无法得出根因时 summary 必须固定为“现有结果无法得出根因”"
                )
            if recommendation.likely_causes:
                issues.append("无法得出根因时 likely_causes 必须为空")

        for index, root_cause in enumerate(recommendation.root_causes, start=1):
            cause_label = root_cause.cause.strip() or "未命名根因"
            live_successful_refs: set[str] = set()
            if root_cause.status != RootCauseStatus.SUPPORTED:
                issues.append(
                    f"根因 #{index}（{cause_label}）状态必须为 SUPPORTED，"
                    f"不能使用历史状态 {root_cause.status.value}"
                )
                has_supported_cause = False
            if not root_cause.cause.strip():
                issues.append(f"根因 #{index} 必须填写因果机制")
            if root_cause.hypothesis_id is not None:
                issues.append(f"根因 #{index}（{cause_label}）不得绑定采证前假设")

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
                elif record.structured_data.get("partial") is True:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了 partial=true 的部分证据："
                        f"{evidence_ref}；部分结果只能作为描述性上下文"
                    )
                elif record.structured_data.get("root_cause_eligible") is False:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了没有可用、可追溯程序事实投影的"
                        f"证据：{evidence_ref}"
                    )

            if not live_successful_refs:
                issues.append(
                    f"SUPPORTED 根因 #{index}（{cause_label}）缺少合格实时 SUCCESS 证据"
                )
                has_supported_cause = False
            if not root_cause.verified:
                issues.append(
                    f"SUPPORTED 根因 #{index}（{cause_label}）必须标记 verified=true"
                )
                has_supported_cause = False
            if root_cause.next_probe is not None:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）不得提供 next_probe")

        # This mirrors whether the main Agent returned a structurally valid supported
        # result. It does not independently infer whether the cited facts prove causality.
        evidence_sufficient = has_supported_cause and bool(recommendation.root_causes)
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
            },
        )
