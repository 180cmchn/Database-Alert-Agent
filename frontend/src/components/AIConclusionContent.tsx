import { Check, ChevronDown, CircleAlert } from "lucide-react";
import { compactId, formatPercent } from "../lib/format";
import type { RootCauseAssessment } from "../types/api";
import { EmptyState } from "./ui";

function RootCauseContent({ rootCause, collapsibleAnalysisProcess }: { rootCause: RootCauseAssessment; collapsibleAnalysisProcess: boolean }) {
  const analysisProcess = rootCause.analysis_process || [];
  const problemSql = rootCause.problem_sql;
  const explainResult = rootCause.explain_result;
  const analysisProcessList = analysisProcess.length > 0 ? (
    <ol className="root-analysis-process">
      {analysisProcess.map((step, index) => (
        <li key={`${step.observation}-${index}`}>
          <span>{index + 1}</span>
          <div>
            <p><b>观察：</b>{step.observation}</p>
            <p><b>推导：</b>{step.inference}</p>
            <small>证据：{step.evidence_refs.map((id) => compactId(id, 6)).join("、")}</small>
          </div>
        </li>
      ))}
    </ol>
  ) : null;

  return (
    <div className="root-cause-content">
      <strong className="root-cause-title">{rootCause.cause}</strong>

      {problemSql && (
        <div className="root-detail-block">
          <span className="root-detail-label">问题 SQL</span>
          {problemSql.statement && <pre className="root-sql"><code>{problemSql.statement}</code></pre>}
          {problemSql.sample_id && <p><b>SQL sample ID：</b>{problemSql.sample_id}</p>}
          {problemSql.structure && <p><b>SQL 结构：</b>{problemSql.structure}</p>}
          <small>来源证据：{compactId(problemSql.evidence_ref, 6)}</small>
        </div>
      )}

      {explainResult && (
        <div className="root-detail-block">
          <span className="root-detail-label">EXPLAIN 结果</span>
          <pre className="root-explain-result">{explainResult.result}</pre>
          <p><b>计划解读：</b>{explainResult.interpretation}</p>
          <small>来源证据：{compactId(explainResult.evidence_ref, 6)}</small>
        </div>
      )}

      {analysisProcessList && (collapsibleAnalysisProcess ? (
        <details className="json-details root-analysis-details">
          <summary><ChevronDown size={14} aria-hidden="true" />查看分析过程与依据</summary>
          <div className="root-detail-block">{analysisProcessList}</div>
        </details>
      ) : (
        <div className="root-detail-block">
          <span className="root-detail-label">分析过程与依据</span>
          {analysisProcessList}
        </div>
      ))}

      <p className="root-evidence-summary">{rootCause.evidence_refs.length ? `关联证据：${rootCause.evidence_refs.map((id) => compactId(id, 6)).join("、")}` : "暂未关联可验证证据"}</p>
      {rootCause.next_probe && <p>下一步：{rootCause.next_probe}</p>}
    </div>
  );
}

export function AIConclusionContent({ rootCauses, collapsibleAnalysisProcess = false }: { rootCauses: RootCauseAssessment[]; collapsibleAnalysisProcess?: boolean }) {
  if (rootCauses.length === 0) {
    return <EmptyState title="现有结果无法得出根因" description="" />;
  }

  return (
    <div className="root-causes">
      {rootCauses.map((rootCause, index) => (
        <article key={`${rootCause.cause}-${index}`} className={rootCause.verified ? "verified" : "unverified"}>
          <span className="root-index">{String(index + 1).padStart(2, "0")}</span>
          <RootCauseContent rootCause={rootCause} collapsibleAnalysisProcess={collapsibleAnalysisProcess} />
          <span className="root-confidence">{formatPercent(rootCause.confidence)}</span>
          <span className="verified-label">{rootCause.verified ? <><Check size={13} /> 已验证</> : <><CircleAlert size={13} /> {rootCause.status}</>}</span>
        </article>
      ))}
    </div>
  );
}
