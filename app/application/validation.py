from __future__ import annotations

import re

from app.domain.models import (
    AnalysisBasisSource,
    EvidenceRecord,
    ExternalKnowledgeReference,
    InvestigationRun,
    NormalizedAlert,
    Recommendation,
    RootCauseStatus,
    RunbookExcerpt,
    RunbookReference,
    ToolStatus,
    ValidationKind,
    ValidationRecord,
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


class RuleConclusionValidator:
    """Validate a recommendation using deterministic safety and provenance rules."""

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
        has_supported_cause = False
        all_causes_decisive = bool(recommendation.root_causes)
        if not recommendation.root_causes:
            issues.append("根因判断必须至少包含一个 SUPPORTED、CONTRADICTED 或 UNKNOWN 候选")

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
                issues.append(
                    f"SUPPORTED 根因 #{index}（{cause_label}）缺少实时 SUCCESS 证据"
                )
                all_causes_decisive = False
            if root_cause.status == RootCauseStatus.SUPPORTED:
                has_supported_cause = True
                if not root_cause.verified:
                    issues.append(
                        f"SUPPORTED 根因 #{index}（{cause_label}）必须标记 verified=true"
                    )
            elif root_cause.status == RootCauseStatus.CONTRADICTED:
                if not live_successful_refs:
                    issues.append(
                        f"CONTRADICTED 根因 #{index}（{cause_label}）缺少实时 SUCCESS 反证"
                    )
                    all_causes_decisive = False
            else:
                all_causes_decisive = False
                if not (root_cause.next_probe or "").strip():
                    issues.append(
                        f"UNKNOWN 根因 #{index}（{cause_label}）必须提供具体 next_probe"
                    )
            if root_cause.status != RootCauseStatus.SUPPORTED and root_cause.verified:
                issues.append(
                    f"根因 #{index}（{cause_label}）只有 SUPPORTED 状态才能标记已验证"
                )

        evidence_sufficient = (
            has_supported_cause
            and all_causes_decisive
            and bool(recommendation.root_causes)
        )
        if not evidence_sufficient and not recommendation.requires_human:
            issues.append("实时证据不足时 recommendation.requires_human 必须为 true")

        manual_matched = recommendation.manual_matched
        sources = [item.source for item in recommendation.analysis_bases]
        valid_runbook_refs = {
            (excerpt.runbook_id, excerpt.section) for excerpt in runbooks
        }
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
            known_cause_ids = {
                cause.cause_id for excerpt in runbooks for cause in excerpt.causes
            }
            for index, root_cause in enumerate(recommendation.root_causes, start=1):
                if root_cause.cause_id and root_cause.cause_id not in known_cause_ids:
                    issues.append(
                        f"根因 #{index} 引用了手册中不存在的 cause_id："
                        f"{root_cause.cause_id}"
                    )
        elif recommendation.runbook_references or any(
            basis.source == AnalysisBasisSource.RUNBOOK
            for basis in recommendation.analysis_bases
        ):
            issues.append("未命中本地 PDF 时不得声称存在手册依据")

        external_matches = recommendation.external_knowledge_matches
        valid_external_refs = {
            item.knowledge_id: (item.title, item.source_uri)
            for item in external_matches
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
                    f"外部知识依据 #{index} 引用了未知条目："
                    f"{basis.source_ref.knowledge_id}"
                )
            elif (basis.source_ref.title, basis.source_ref.source_uri) != expected:
                issues.append(
                    f"外部知识依据 #{index} 的标题或来源与检索结果不一致"
                )

        knowledge_matched = manual_matched or bool(external_matches)
        for index, step in enumerate(recommendation.steps, start=1):
            source_ref = step.source_ref
            if not knowledge_matched:
                if source_ref is not None:
                    issues.append(
                        f"未命中知识时处理步骤 #{index} 不得提供 source_ref"
                    )
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
                        f"处理步骤 #{index} 引用了未知外部知识："
                        f"{source_ref.knowledge_id}"
                    )
                elif (source_ref.title, source_ref.source_uri) != expected:
                    issues.append(
                        f"处理步骤 #{index} 的外部知识标题或来源不一致"
                    )

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
                issues.append(
                    f"处理步骤 #{index} 包含禁止的危险动作：{', '.join(matches)}"
                )

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
