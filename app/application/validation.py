from __future__ import annotations

import re

from app.domain.models import (
    AnalysisBasisSource,
    EvidenceRecord,
    InvestigationRun,
    NormalizedAlert,
    Recommendation,
    RunbookExcerpt,
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

        for index, root_cause in enumerate(recommendation.root_causes, start=1):
            cause_label = root_cause.cause.strip() or "未命名根因"
            successful_refs: set[str] = set()

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
                successful_refs.add(evidence_ref)

            if root_cause.verified and not successful_refs:
                issues.append(
                    f"已验证根因 #{index}（{cause_label}）必须至少引用一条 SUCCESS 证据"
                )

        manual_matched = recommendation.manual_matched or bool(runbooks)
        sources = [item.source for item in recommendation.analysis_bases]
        if AnalysisBasisSource.AI not in sources:
            issues.append("判断依据必须至少包含一条 AI 分析依据")
        if manual_matched:
            valid_runbook_refs = {
                (excerpt.runbook_id, excerpt.section) for excerpt in runbooks
            }
            if AnalysisBasisSource.RUNBOOK not in sources:
                issues.append("命中手册时必须提供至少一条手册依据")
            if AnalysisBasisSource.AI in sources:
                first_ai = sources.index(AnalysisBasisSource.AI)
                if any(
                    source == AnalysisBasisSource.RUNBOOK
                    for source in sources[first_ai:]
                ):
                    issues.append("判断依据顺序错误：手册依据必须全部排在 AI 依据之前")
            for index, basis in enumerate(recommendation.analysis_bases, start=1):
                if basis.source != AnalysisBasisSource.RUNBOOK:
                    continue
                if basis.source_ref is None:
                    issues.append(f"手册依据 #{index} 缺少 source_ref")
                    continue
                ref_key = (basis.source_ref.runbook_id, basis.source_ref.section)
                if ref_key not in valid_runbook_refs:
                    issues.append(
                        f"手册依据 #{index} 引用了无效章节："
                        f"{basis.source_ref.runbook_id}/{basis.source_ref.section}"
                    )
            for index, step in enumerate(recommendation.steps, start=1):
                source_ref = step.source_ref
                if source_ref is None:
                    issues.append(f"命中手册时处理步骤 #{index} 必须提供 source_ref")
                    continue
                ref_key = (source_ref.runbook_id, source_ref.section)
                if ref_key not in valid_runbook_refs:
                    issues.append(
                        f"处理步骤 #{index} 引用了无效的手册章节："
                        f"{source_ref.runbook_id}/{source_ref.section}"
                    )

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
            issues=issues,
            metadata={
                "validator": type(self).__name__,
                "alert_id": str(alert.id),
                "checked_root_causes": len(recommendation.root_causes),
                "checked_steps": len(recommendation.steps),
                "evidence_count": len(evidence),
                "runbook_count": len(runbooks),
            },
        )
