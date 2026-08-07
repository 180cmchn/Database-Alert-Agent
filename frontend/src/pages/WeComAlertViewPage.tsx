import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  CircleHelp,
  Database,
  Server,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../lib/api";
import { compactId, formatDateTime, formatPercent } from "../lib/format";
import type { StoredAlert } from "../types/api";

type WeComView = "overview" | "root-cause" | "recovery-advice";

const rootCauseLabels = {
  SUPPORTED: "已有实时证据支持",
  CONTRADICTED: "历史结果：已被实时证据反驳",
  UNKNOWN: "证据不足",
} as const;

export function WeComAlertViewPage({ view }: { view: WeComView }) {
  const { alertId = "" } = useParams();
  const [record, setRecord] = useState<StoredAlert | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    api.getAlert(alertId)
      .then((result) => {
        if (active) setRecord(result);
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(requestError instanceof Error ? requestError.message : "内容加载失败");
        }
      });
    return () => { active = false; };
  }, [alertId]);

  if (error) {
    return (
      <main className="wecom-page wecom-state-page">
        <AlertTriangle size={30} />
        <h1>告警内容暂时无法打开</h1>
        <p>{error}</p>
      </main>
    );
  }
  if (!record) {
    return (
      <main className="wecom-page wecom-state-page">
        <span className="wecom-loading" />
        <p>正在读取告警分析结果…</p>
      </main>
    );
  }

  const { alert, recommendation } = record;
  const host = alert.database?.host || alert.database?.instance || "未提供";

  return (
    <main className={`wecom-page severity-${alert.severity.toLowerCase()}`}>
      <header className="wecom-alert-header">
        <div className="wecom-source"><Database size={15} /> 数据库告警 Agent</div>
        <h1>{alert.title}</h1>
        <p>{alert.reason}</p>
        <div className="wecom-meta-row">
          <span className="wecom-severity">{alert.severity}</span>
          <span>{record.status}</span>
          <time dateTime={alert.occurred_at}>{formatDateTime(alert.occurred_at)}</time>
        </div>
      </header>

      <section className="wecom-facts" aria-label="告警基本信息">
        <div><Server size={15} /><span>告警主机</span><strong>{host}</strong></div>
        <div><Database size={15} /><span>数据库</span><strong>{[alert.database?.engine, alert.database?.database].filter(Boolean).join(" / ") || "未提供"}</strong></div>
        <div><span>环境</span><strong>{alert.environment}</strong></div>
        <div><span>服务</span><strong>{alert.service_name}</strong></div>
      </section>

      {!recommendation ? (
        <section className="wecom-content-card wecom-empty-content">
          <CircleHelp size={28} />
          <h2>分析结果尚未生成</h2>
          <p>请稍后从企微卡片重新进入。</p>
        </section>
      ) : view === "root-cause" ? (
        <RootCauseContent record={record} />
      ) : view === "recovery-advice" ? (
        <RecoveryAdviceContent record={record} />
      ) : (
        <OverviewContent record={record} />
      )}

      <footer className="wecom-page-footer">
        历史案例与知识资料仅作为线索；本次根因结论以当前事件的实时证据为准。
      </footer>
    </main>
  );
}

function OverviewContent({ record }: { record: StoredAlert }) {
  const recommendation = record.recommendation!;
  return (
    <section className="wecom-content-card">
      <div className="wecom-section-title"><BrainCircuit size={20} /><h2>AI 分析摘要</h2></div>
      <p className="wecom-summary">{recommendation.summary}</p>
      <div className="wecom-confidence">
        <span>分析置信度</span><strong>{formatPercent(recommendation.confidence)}</strong>
      </div>
    </section>
  );
}

function RootCauseContent({ record }: { record: StoredAlert }) {
  const recommendation = record.recommendation!;
  return (
    <div className="wecom-content-stack">
      <section className="wecom-content-card">
        <div className="wecom-section-title"><BrainCircuit size={20} /><h2>告警根因分析</h2></div>
        <p className="wecom-summary">{recommendation.summary}</p>
        <div className="wecom-confidence">
          <span>分析置信度</span><strong>{formatPercent(recommendation.confidence)}</strong>
        </div>
      </section>

      {recommendation.root_causes.length > 0 ? (
        recommendation.root_causes.map((rootCause, index) => (
          <article className={`wecom-content-card wecom-root-cause root-${rootCause.status.toLowerCase()}`} key={`${rootCause.cause}-${index}`}>
            <header>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <div><h3>{rootCause.cause}</h3><small>{rootCauseLabels[rootCause.status]}</small></div>
              <strong>{formatPercent(rootCause.confidence)}</strong>
            </header>
            {rootCause.evidence_refs.length > 0 && (
              <p>关联证据：{rootCause.evidence_refs.map((id) => compactId(id, 8)).join("、")}</p>
            )}
          </article>
        ))
      ) : recommendation.likely_causes.length > 0 ? (
        <section className="wecom-content-card">
          <div className="wecom-section-title"><CircleHelp size={20} /><h2>待验证的可能原因</h2></div>
          <ol className="wecom-simple-list">
            {recommendation.likely_causes.map((cause) => <li key={cause}>{cause}</li>)}
          </ol>
        </section>
      ) : (
        <section className="wecom-content-card wecom-empty-content"><CircleHelp size={26} /><p>本次没有形成可展示的根因候选。</p></section>
      )}

      {recommendation.excluded_causes.length > 0 && (
        <section className="wecom-content-card">
          <div className="wecom-section-title"><ShieldAlert size={20} /><h2>实时证据已排除</h2></div>
          <ol className="wecom-simple-list">
            {recommendation.excluded_causes.map((excludedCause, index) => (
              <li key={`${excludedCause.cause}-${index}`}>
                <strong>{excludedCause.cause}</strong> · {excludedCause.reason}
                {excludedCause.evidence_refs.length > 0 && <small>反证：{excludedCause.evidence_refs.map((id) => compactId(id, 8)).join("、")}</small>}
              </li>
            ))}
          </ol>
        </section>
      )}

      {recommendation.analysis_bases.length > 0 && (
        <section className="wecom-content-card">
          <div className="wecom-section-title"><CheckCircle2 size={20} /><h2>判断依据</h2></div>
          <ol className="wecom-simple-list">
            {recommendation.analysis_bases.map((basis, index) => (
              <li key={`${basis.source}-${index}`}><strong>{basis.source}</strong> · {basis.statement}</li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}

function RecoveryAdviceContent({ record }: { record: StoredAlert }) {
  const recommendation = record.recommendation!;
  return (
    <div className="wecom-content-stack">
      <section className="wecom-content-card">
        <div className="wecom-section-title"><Wrench size={20} /><h2>告警恢复建议</h2></div>
        <p className="wecom-summary">以下为 Agent 已封装的核查与恢复建议，请结合现场证据执行。</p>
      </section>

      <section className="wecom-content-card">
        <ol className="wecom-advice-list">
          {recommendation.steps.map((step) => (
            <li key={step.order}>
              <span>{String(step.order).padStart(2, "0")}</span>
              <div>
                <h3>{step.action}</h3>
                {step.expected_result && <p><CheckCircle2 size={14} /> 预期：{step.expected_result}</p>}
                {step.caution && <p className="wecom-caution"><ShieldAlert size={14} /> 注意：{step.caution}</p>}
              </div>
            </li>
          ))}
        </ol>
      </section>

      {recommendation.risks.length > 0 && (
        <section className="wecom-content-card wecom-risk-card">
          <div className="wecom-section-title"><ShieldAlert size={20} /><h2>风险与审批提示</h2></div>
          <ul className="wecom-simple-list">
            {recommendation.risks.map((risk) => <li key={risk}>{risk}</li>)}
          </ul>
        </section>
      )}
    </div>
  );
}
