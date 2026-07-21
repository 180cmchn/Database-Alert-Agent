import {
  AlertOctagon,
  ArrowLeft,
  BookCheck,
  Bot,
  BrainCircuit,
  Check,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Database,
  ExternalLink,
  FileCheck2,
  Gauge,
  History,
  Radio,
  RefreshCw,
  ShieldCheck,
  Siren,
  TerminalSquare,
  UserRoundCheck,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { StageTimeline } from "../components/StageTimeline";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  SectionCard,
  SeverityBadge,
  StatusBadge,
  ToolStatusBadge,
} from "../components/ui";
import { api } from "../lib/api";
import { compactId, formatDateTime, formatJson, formatPercent } from "../lib/format";
import type { AlertStatus, StoredAlert } from "../types/api";

const activeStatuses: AlertStatus[] = ["RECEIVED", "QUEUED", "ANALYZING"];
const terminalStages = ["COMPLETED", "REVIEW_REQUIRED", "FAILED"];

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const [record, setRecord] = useState<StoredAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    try {
      const result = await api.getAlert(alertId);
      setRecord(result);
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "告警详情加载失败");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [alertId]);

  useEffect(() => { void load(); }, [load]);

  const currentStage = useMemo(
    () => record?.latest_run?.current_stage || record?.progress.at(-1)?.stage || null,
    [record],
  );
  const isTracking = Boolean(
    (record && (
      activeStatuses.includes(record.status)
      || (record.latest_run && (!currentStage || !terminalStages.includes(currentStage)))
    )),
  );

  useEffect(() => {
    if (!record || !isTracking) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 2_500);
    return () => window.clearInterval(timer);
  }, [isTracking, load, record]);
  const runbookSearchFinished = useMemo(
    () => Boolean(record?.progress.some((item) => [
      "INVESTIGATING",
      "ADVISING",
      "VALIDATING",
      "REPORTING",
      "COMPLETED",
      "REVIEW_REQUIRED",
      "FAILED",
    ].includes(item.stage))),
    [record],
  );

  if (loading && !record) return <LoadingState label="正在读取完整排查链路…" />;
  if (error && !record) return <ErrorState message={error} onRetry={() => void load()} />;
  if (!record) return <EmptyState title="告警不存在" description="该记录可能已被删除，或链接中的 ID 不正确。" />;

  const { alert, recommendation } = record;
  const isActive = isTracking;

  return (
    <div className="page-stack detail-page">
      <div className="detail-back-row">
        <Link to="/alerts" className="back-link"><ArrowLeft size={15} /> 返回告警中心</Link>
        <span className="detail-refresh">
          {isActive && <><Radio size={14} className="pulse" /> 每 2.5 秒自动跟踪</>}
          <button type="button" onClick={() => void load(true)} aria-label="刷新详情" disabled={refreshing}>
            <RefreshCw size={15} className={refreshing ? "spin" : ""} />
          </button>
        </span>
      </div>

      <PageHeader
        eyebrow={`ALERT · ${alert.external_id}`}
        title={alert.title}
        description={alert.description || "该告警未提供补充描述。"}
        actions={<><SeverityBadge severity={alert.severity} /><StatusBadge status={record.status} /></>}
      />

      {error && <ErrorState compact message={`刷新失败：${error}`} onRetry={() => void load(true)} />}
      {record.error && (
        <div className="analysis-error"><AlertOctagon size={18} /><div><strong>分析过程报告异常</strong><span>{record.error}</span></div></div>
      )}

      <section className="incident-facts">
        <div><span><CircleAlert size={15} /> 告警原因</span><strong>{alert.reason}</strong></div>
        <div><span><Database size={15} /> 数据库目标</span><strong>{[alert.database?.engine, alert.database?.instance].filter(Boolean).join(" · ") || "未提供"}</strong></div>
        <div><span><Gauge size={15} /> 环境 / 服务</span><strong>{alert.environment} · {alert.service_name}</strong></div>
        <div><span><Clock3 size={15} /> 发生时间</span><strong>{formatDateTime(alert.occurred_at)}</strong></div>
      </section>

      <section className="detail-grid workflow-grid">
        <SectionCard
          eyebrow="LIVE WORKFLOW"
          title="Agent 排查轨迹"
          description={`第 ${record.latest_run?.attempt || 1} 次执行 · ${record.latest_run?.strategy_id || "等待选择策略"}`}
        >
          <StageTimeline currentStage={currentStage} progress={record.progress} />
        </SectionCard>

        <SectionCard
          eyebrow="RUNBOOK FIRST"
          title="手册匹配"
          description="手册是建议生成的首要依据"
          action={record.manual_matches.length ? <span className="match-score"><BookCheck size={14} /> 命中 {record.manual_matches.length} 条</span> : undefined}
        >
          {record.manual_matches.length ? (
            <div className="runbook-evidence-list">
              {record.manual_matches.map((match) => (
                <details key={`${match.runbook_id}-${match.section}`} className="runbook-evidence" open={record.manual_matches.length === 1}>
                  <summary>
                    <div><strong>{match.title}</strong><span>{match.runbook_id} / {match.section}</span></div>
                    <span className="score-chip">相关度 {match.score.toFixed(1)}</span>
                  </summary>
                  <div className="runbook-content">{match.content}</div>
                </details>
              ))}
            </div>
          ) : isActive && !runbookSearchFinished ? (
            <div className="waiting-panel"><BookCheck size={24} /><strong>正在检索处置手册</strong><span>结果会在匹配阶段完成后显示</span></div>
          ) : (
            <EmptyState kind="runbook" title="未命中处置手册" description="Agent 的通用建议应降低置信度，并明确要求人工复核。" />
          )}
        </SectionCard>

      </section>

      {record.knowledge_matches.length > 0 && (
        <SectionCard
          eyebrow="CONFIRMED KNOWLEDGE"
          title="同类已确认案例"
          description="历史案例只作为调查线索，本次告警仍需使用实时证据重新校验。"
        >
          <div className="knowledge-case-grid">
            {record.knowledge_matches.map((knowledgeCase) => (
              <article key={knowledgeCase.id}>
                <span><History size={16} /> 人工确认</span>
                <strong>{knowledgeCase.final_root_cause}</strong>
                <p>{knowledgeCase.actual_resolution}</p>
                <small>{knowledgeCase.confirmed_by} · {formatDateTime(knowledgeCase.confirmed_at)}</small>
              </article>
            ))}
          </div>
        </SectionCard>
      )}

      <SectionCard
        eyebrow="FIELD EVIDENCE"
        title="现场证据"
        description="工具输出相互隔离，只有采集成功的证据才能用于验证根因。"
        action={<span className="evidence-count">{record.evidence_records.length} 项采集结果</span>}
      >
        {record.evidence_records.length ? (
          <div className="evidence-grid">
            {record.evidence_records.map((evidence) => (
              <article className={`evidence-card evidence-${evidence.status.toLowerCase()}`} key={evidence.id}>
                <div className="evidence-head">
                  <span className="tool-icon"><TerminalSquare size={18} /></span>
                  <div><strong>{evidence.tool_name}</strong><span>{evidence.source_system} · {evidence.duration_ms} ms</span></div>
                  <ToolStatusBadge status={evidence.status} />
                </div>
                <p>{evidence.summary}</p>
                {evidence.error && <div className="tool-error">{evidence.error}</div>}
                {(Object.keys(evidence.structured_data).length > 0 || Object.keys(evidence.request).length > 0) && (
                  <details className="json-details">
                    <summary>查看请求与结构化数据</summary>
                    <pre>{formatJson({ request: evidence.request, data: evidence.structured_data })}</pre>
                  </details>
                )}
                <span className="evidence-id">证据 ID · {compactId(evidence.id)}</span>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title={isActive ? "等待采集现场证据" : "没有可用的现场证据"} description={isActive ? "排查策略执行后，日志、指标和数据库诊断结果会出现在这里。" : "本次分析未记录工具调用结果。"} />
        )}
      </SectionCard>

      {recommendation ? (
        <section className="recommendation-stack">
          <div className="recommendation-hero">
            <div className="recommendation-mark"><BrainCircuit size={27} /></div>
            <div className="recommendation-copy">
              <div className="recommendation-kicker"><span>AI 处理建议</span>{recommendation.manual_matched && <span className="manual-proof"><BookCheck size={13} /> 手册约束</span>}</div>
              <h2>{recommendation.summary}</h2>
              <div className="recommendation-meta">
                <span><Gauge size={15} /> 置信度 <strong>{formatPercent(recommendation.confidence)}</strong></span>
                <span>{recommendation.requires_human ? <UserRoundCheck size={15} /> : <ShieldCheck size={15} />} {recommendation.requires_human ? "需要人工介入" : "可按建议核查"}</span>
                {record.advisor_metadata && <span><Bot size={15} /> {record.advisor_metadata.model}</span>}
              </div>
            </div>
          </div>

          {recommendation.root_causes.length > 0 && (
            <SectionCard eyebrow="ROOT CAUSE" title="根因判断">
              <div className="root-causes">
                {recommendation.root_causes.map((rootCause, index) => (
                  <article key={`${rootCause.cause}-${index}`} className={rootCause.verified ? "verified" : "unverified"}>
                    <span className="root-index">{String(index + 1).padStart(2, "0")}</span>
                    <div><strong>{rootCause.cause}</strong><p>{rootCause.evidence_refs.length ? `关联证据：${rootCause.evidence_refs.map((id) => compactId(id, 6)).join("、")}` : "暂未关联可验证证据"}</p></div>
                    <span className="root-confidence">{formatPercent(rootCause.confidence)}</span>
                    <span className="verified-label">{rootCause.verified ? <><Check size={13} /> 已验证</> : <><CircleAlert size={13} /> 待验证</>}</span>
                  </article>
                ))}
              </div>
            </SectionCard>
          )}

          <section className="advice-grid">
            <SectionCard eyebrow="ACTION PLAN" title="建议处置步骤">
              <ol className="action-steps">
                {recommendation.steps.map((step) => (
                  <li key={step.order}>
                    <span className="step-number">{String(step.order).padStart(2, "0")}</span>
                    <div>
                      <strong>{step.action}</strong>
                      {step.expected_result && <p><CheckCircle2 size={14} /> 预期：{step.expected_result}</p>}
                      {step.caution && <p className="caution"><CircleAlert size={14} /> 注意：{step.caution}</p>}
                      {step.source_ref && <span className="source-ref"><BookCheck size={13} /> {step.source_ref.runbook_id} / {step.source_ref.section}</span>}
                    </div>
                  </li>
                ))}
              </ol>
            </SectionCard>

            <div className="advice-side">
              {recommendation.likely_causes.length > 0 && (
                <SectionCard eyebrow="HYPOTHESES" title="可能原因">
                  <ol className="likely-causes">
                    {recommendation.likely_causes.map((cause, index) => (
                      <li key={`${cause}-${index}`}><span>{index + 1}</span>{cause}</li>
                    ))}
                  </ol>
                </SectionCard>
              )}
              <SectionCard eyebrow="BASIS" title="判断依据" description="顺序固定为手册依据优先、AI 分析依据其次">
                {recommendation.analysis_bases.length ? <ol className="likely-causes">{recommendation.analysis_bases.map((basis, index) => <li key={`${basis.source}-${basis.statement}-${index}`}><span>{index + 1}</span><div><strong>{basis.source === "RUNBOOK" ? "手册" : "AI"}</strong> · {basis.statement}{basis.source_ref && <small className="source-ref"><BookCheck size={13} /> {basis.source_ref.runbook_id} / {basis.source_ref.section}</small>}</div></li>)}</ol> : <p className="muted-copy">本次结果没有可用判断依据。</p>}
              </SectionCard>
              <SectionCard eyebrow="RISK GUARD" title="风险提示" className="risk-card">
                {recommendation.risks.length ? <ul className="risk-points">{recommendation.risks.map((risk) => <li key={risk}><Siren size={14} /> {risk}</li>)}</ul> : <p className="muted-copy">没有额外风险提示。</p>}
              </SectionCard>
            </div>
          </section>
        </section>
      ) : (
        <SectionCard eyebrow="AI ADVICE" title="处理建议">
          <div className="waiting-panel large"><Bot size={29} /><strong>{isActive ? "Agent 正在形成处理建议" : "本次分析未生成建议"}</strong><span>{isActive ? "建议将在证据采集与独立校验结束后显示。" : "请查看上方错误和校验记录，并安排人工介入。"}</span></div>
        </SectionCard>
      )}

      <section className="detail-grid audit-grid">
        <SectionCard eyebrow="VALIDATION" title="独立校验" description="规则与独立模型共同约束最终结论">
          {record.validations.length ? (
            <div className="validation-list">
              {record.validations.map((validation) => (
                <article key={validation.id} className={validation.passed ? "passed" : "rejected"}>
                  <span>{validation.passed ? <FileCheck2 size={18} /> : <XCircle size={18} />}</span>
                  <div><strong>{validation.kind === "RULE" ? "确定性规则校验" : "独立 Agent 校验"}</strong><p>{validation.passed ? "未发现阻断问题" : validation.issues.join("；") || "校验未通过"}</p></div>
                  <b>{validation.passed ? "PASS" : "REJECT"}</b>
                </article>
              ))}
            </div>
          ) : <EmptyState title="暂无校验记录" description="建议生成后，校验结果会记录在审计链路中。" />}
        </SectionCard>

      </section>

      <SectionCard eyebrow="TRACEABILITY" title="事件标识与审计信息">
        <dl className="traceability-grid">
          <div><dt>告警 ID</dt><dd>{alert.id}</dd></div>
          <div><dt>事件指纹</dt><dd>{alert.incident_fingerprint || "尚未生成"}</dd></div>
          <div><dt>来源适配器</dt><dd>{alert.source}</dd></div>
          <div><dt>最后更新</dt><dd>{formatDateTime(record.updated_at)}</dd></div>
          {record.advisor_metadata?.request_id && <div><dt>模型请求 ID</dt><dd>{record.advisor_metadata.request_id}</dd></div>}
          {record.knowledge_matches.length > 0 && <div><dt>历史经验命中</dt><dd><History size={14} /> {record.knowledge_matches.length} 条已确认案例</dd></div>}
        </dl>
        <details className="json-details raw-alert"><summary><ExternalLink size={14} /> 查看脱敏后的原始告警</summary><pre>{formatJson(alert.raw_payload)}</pre></details>
      </SectionCard>
    </div>
  );
}
