import { CheckCircle2, CircleAlert, ExternalLink } from "lucide-react";
import { buildRecommendationGroups } from "../lib/recommendationModel";
import type { KnowledgeReference, Recommendation, RecommendationStep } from "../types/api";

interface RecommendationGroupsProps {
  recommendation: Recommendation;
  legacySteps?: RecommendationStep[];
  compact?: boolean;
}

function knowledgeReference(reference: KnowledgeReference): string {
  return `${reference.title} · ${reference.source}`;
}

function StepList({ steps, compact }: { steps: RecommendationStep[]; compact: boolean }) {
  return (
    <ol className={compact ? "wecom-advice-list" : "action-steps"}>
      {steps.map((step) => (
        <li key={step.order}>
          <span className={compact ? undefined : "step-number"}>
            {String(step.order).padStart(2, "0")}
          </span>
          <div>
            {compact ? <h3>{step.action}</h3> : <strong>{step.action}</strong>}
            {step.expected_result && (
              <p><CheckCircle2 size={14} /> 预期：{step.expected_result}</p>
            )}
            {step.caution && (
              <p className={compact ? "wecom-caution" : "caution"}>
                <CircleAlert size={14} /> 注意：{step.caution}
              </p>
            )}
            {!compact && step.source_ref && (
              <span className="source-ref">
                <ExternalLink size={13} /> {knowledgeReference(step.source_ref)}
              </span>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function RecommendationGroups({
  recommendation,
  legacySteps = [],
  compact = false,
}: RecommendationGroupsProps) {
  if (legacySteps.length > 0) {
    return (
      <div className="recommendation-groups">
        <section className="recommendation-group recommendation-group-legacy">
          <header>
            <h3>历史建议</h3>
            <p>该结果生成于建议分类上线前，无法可靠划分为临时解决和长期优化。</p>
          </header>
          <StepList steps={legacySteps} compact={compact} />
        </section>
      </div>
    );
  }

  const groups = buildRecommendationGroups(recommendation);

  return (
    <div className={`recommendation-groups${compact ? " compact" : ""}`}>
      {groups.map((group) => (
        <section className={`recommendation-group recommendation-group-${group.key}`} key={group.key}>
          <header>
            <h3>{group.title}</h3>
            <p>{group.description}</p>
          </header>
          {group.steps.length > 0 ? (
            <StepList steps={group.steps} compact={compact} />
          ) : (
            <p className={compact ? "wecom-summary" : "muted-copy"}>本类暂无可展示建议。</p>
          )}
        </section>
      ))}
    </div>
  );
}
