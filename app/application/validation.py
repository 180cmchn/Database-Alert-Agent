from __future__ import annotations

from app.domain.alert_preprocessing import (
    has_management_platform_sql_filter_note,
    is_management_platform_collection_sql_cause,
)
from app.domain.models import (
    EVIDENCE_RECORD_V2,
    INCONCLUSIVE_ROOT_CAUSE_SUMMARY,
    AnalysisBasisSource,
    EvidenceRecord,
    EvidenceUnit,
    EvidenceUnitStatus,
    InvestigationRun,
    NormalizedAlert,
    Recommendation,
    RootCauseAssessment,
    RootCauseStatus,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
)


def _evidence_units_by_id(
    evidence: list[EvidenceRecord],
) -> dict[str, tuple[EvidenceRecord, EvidenceUnit]]:
    return {str(unit.id): (record, unit) for record in evidence for unit in record.evidence_units}


def _unit_contains_sql_sample(unit: EvidenceUnit) -> bool:
    if unit.stage.casefold() != "history":
        return False
    rows = unit.data.get("rows")
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, value in row.items():
            if str(key).casefold() == "sample" and isinstance(value, str) and value.strip():
                return True
    return False


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
    evidence_units_by_id = _evidence_units_by_id(evidence)
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
        qualified_refs: list[str] = []
        for evidence_ref in dict.fromkeys(root_cause.evidence_refs):
            unit_entry = evidence_units_by_id.get(evidence_ref)
            if unit_entry is not None:
                parent, unit = unit_entry
                if parent.is_evidence_unit_root_cause_support_eligible(unit):
                    qualified_refs.append(evidence_ref)
                    continue
            record = evidence_by_id.get(evidence_ref)
            if (
                record is not None
                and record.contract_version != EVIDENCE_RECORD_V2
                and record.is_root_cause_support_eligible()
            ):
                qualified_refs.append(evidence_ref)
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
                "steps": [],
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
    ) -> ValidationRecord:
        issues: list[str] = []
        knowledge_warnings: list[str] = []
        evidence_by_id = {str(item.id): item for item in evidence}
        evidence_units_by_id = _evidence_units_by_id(evidence)
        successful_explain_refs_by_parent = {
            str(record.id): {
                str(unit.id)
                for unit in record.evidence_units
                if unit.stage.casefold() == "explain"
                and record.is_evidence_unit_root_cause_support_eligible(unit)
            }
            for record in evidence
        }
        has_supported_cause = bool(recommendation.root_causes)

        if not recommendation.root_causes:
            if recommendation.summary != INCONCLUSIVE_ROOT_CAUSE_SUMMARY:
                issues.append("无法得出根因时 summary 必须固定为“现有结果无法得出根因”")
            if recommendation.likely_causes:
                issues.append("无法得出根因时 likely_causes 必须为空")
            if recommendation.steps:
                issues.append("无法得出根因时 steps 必须为空")
        elif not recommendation.steps:
            issues.append("SUPPORTED 根因必须至少提供一项实际处置步骤")

        for index, root_cause in enumerate(recommendation.root_causes, start=1):
            cause_label = root_cause.cause.strip() or "未命名根因"
            live_successful_refs: set[str] = set()
            referenced_history_parent_ids: set[str] = set()
            has_sql_sample = False
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
                unit_entry = evidence_units_by_id.get(evidence_ref)
                if unit_entry is not None:
                    parent, unit = unit_entry
                    if unit.status != EvidenceUnitStatus.SUCCESS:
                        issues.append(
                            f"根因 #{index}（{cause_label}）引用的证据单元不是 SUCCESS："
                            f"{evidence_ref}（{unit.status.value}）"
                        )
                        continue
                    if parent.is_evidence_unit_root_cause_support_eligible(unit):
                        live_successful_refs.add(evidence_ref)
                        if unit.stage.casefold() == "history":
                            referenced_history_parent_ids.add(str(parent.id))
                            has_sql_sample = has_sql_sample or _unit_contains_sql_sample(unit)
                    else:
                        issues.append(
                            f"根因 #{index}（{cause_label}）引用了不具备根因资格的"
                            f"证据单元：{evidence_ref}"
                        )
                    continue
                record = evidence_by_id.get(evidence_ref)
                if record is None:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了不存在的证据：{evidence_ref}"
                    )
                    continue
                if record.contract_version == EVIDENCE_RECORD_V2:
                    issues.append(
                        f"根因 #{index}（{cause_label}）引用了 v2 父证据：{evidence_ref}；"
                        "必须引用其合格 SUCCESS 子证据单元"
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

            if not root_cause.analysis_process:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）必须给出分析过程与依据")
                has_supported_cause = False
            for step_index, step in enumerate(root_cause.analysis_process, start=1):
                unqualified_refs = [
                    evidence_ref
                    for evidence_ref in dict.fromkeys(step.evidence_refs)
                    if evidence_ref not in live_successful_refs
                ]
                if unqualified_refs:
                    issues.append(
                        f"根因 #{index} 分析步骤 #{step_index} 引用了未在该根因中验证的证据："
                        + "、".join(unqualified_refs)
                    )
                    has_supported_cause = False

            if has_sql_sample and root_cause.problem_sql is None:
                issues.append(
                    f"SUPPORTED 根因 #{index}（{cause_label}）引用了问题 SQL sample，"
                    "必须展示具体 SQL、SQL 结构或 sample ID"
                )
                has_supported_cause = False
            if (
                root_cause.problem_sql is not None
                and root_cause.problem_sql.evidence_ref not in live_successful_refs
            ):
                issues.append(
                    f"根因 #{index} 的问题 SQL 引用了未在该根因中验证的证据："
                    f"{root_cause.problem_sql.evidence_ref}"
                )
                has_supported_cause = False

            available_explain_refs = {
                evidence_ref
                for parent_id in referenced_history_parent_ids
                for evidence_ref in successful_explain_refs_by_parent.get(parent_id, set())
            }
            if available_explain_refs and root_cause.explain_result is None:
                issues.append(
                    f"SUPPORTED 根因 #{index}（{cause_label}）存在成功 EXPLAIN，"
                    "必须展示执行计划结果及解读"
                )
                has_supported_cause = False
            if root_cause.explain_result is not None:
                explain_ref = root_cause.explain_result.evidence_ref
                if explain_ref not in live_successful_refs:
                    issues.append(
                        f"根因 #{index} 的 EXPLAIN 结果引用了未在该根因中验证的证据：{explain_ref}"
                    )
                    has_supported_cause = False
                else:
                    explain_entry = evidence_units_by_id.get(explain_ref)
                    if explain_entry is None or explain_entry[1].stage.casefold() != "explain":
                        issues.append(f"根因 #{index} 的 EXPLAIN 结果必须引用 explain 证据单元")
                        has_supported_cause = False
                    elif available_explain_refs and explain_ref not in available_explain_refs:
                        issues.append(
                            f"根因 #{index} 的 EXPLAIN 结果未引用问题 SQL 对应的成功计划证据"
                        )
                        has_supported_cause = False

            if not live_successful_refs:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）缺少合格实时 SUCCESS 证据")
                has_supported_cause = False
            if not root_cause.verified:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）必须标记 verified=true")
                has_supported_cause = False
            if root_cause.next_probe is not None:
                issues.append(f"SUPPORTED 根因 #{index}（{cause_label}）不得提供 next_probe")

        # This mirrors whether the main Agent returned a structurally valid supported
        # result. It does not independently infer whether the cited facts prove causality.
        evidence_sufficient = has_supported_cause and bool(recommendation.root_causes)
        sources = [item.source for item in recommendation.analysis_bases]
        if AnalysisBasisSource.AI not in sources:
            issues.append("判断依据必须至少包含一条 AI 分析依据")
        knowledge_matches = recommendation.knowledge_matches
        valid_knowledge_refs = {
            (item.source, item.knowledge_id): (item.title, item.source_uri)
            for item in knowledge_matches
        }
        knowledge_bases = [
            basis
            for basis in recommendation.analysis_bases
            if basis.source == AnalysisBasisSource.KNOWLEDGE
        ]
        if knowledge_matches and not knowledge_bases:
            knowledge_warnings.append("命中知识时未提供知识依据")
        if not knowledge_matches and knowledge_bases:
            knowledge_warnings.append("未命中知识时声称存在知识依据")
        for index, basis in enumerate(recommendation.analysis_bases, start=1):
            if basis.source != AnalysisBasisSource.KNOWLEDGE:
                continue
            if basis.source_ref is None:
                knowledge_warnings.append(f"知识依据 #{index} 缺少合法 source_ref")
                continue
            expected = valid_knowledge_refs.get(
                (basis.source_ref.source, basis.source_ref.knowledge_id)
            )
            if expected is None:
                knowledge_warnings.append(
                    f"知识依据 #{index} 引用了未知条目："
                    f"{basis.source_ref.source}/{basis.source_ref.knowledge_id}"
                )
            elif (basis.source_ref.title, basis.source_ref.source_uri) != expected:
                knowledge_warnings.append(f"知识依据 #{index} 的标题或来源与检索结果不一致")

        knowledge_matched = bool(knowledge_matches)
        for index, step in enumerate(recommendation.steps, start=1):
            source_ref = step.source_ref
            if not knowledge_matched:
                if source_ref is not None:
                    knowledge_warnings.append(f"未命中知识时处理步骤 #{index} 提供了 source_ref")
                continue
            if source_ref is not None:
                expected = valid_knowledge_refs.get((source_ref.source, source_ref.knowledge_id))
                if expected is None:
                    knowledge_warnings.append(
                        f"处理步骤 #{index} 引用了未知知识："
                        f"{source_ref.source}/{source_ref.knowledge_id}"
                    )
                elif (source_ref.title, source_ref.source_uri) != expected:
                    knowledge_warnings.append(f"处理步骤 #{index} 的知识标题或来源不一致")

        source_rank = {
            AnalysisBasisSource.KNOWLEDGE: 0,
            AnalysisBasisSource.AI: 1,
        }
        ranks = [source_rank[source] for source in sources]
        if ranks != sorted(ranks):
            knowledge_warnings.append("判断依据顺序提示：建议将知识依据排在 AI 依据之前")

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
                "evidence_unit_count": len(evidence_units_by_id),
                "knowledge_count": len(knowledge_matches),
                "knowledge_warnings": knowledge_warnings,
            },
        )
