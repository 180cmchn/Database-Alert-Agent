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
  Eye,
  ExternalLink,
  FileCheck2,
  Gauge,
  History,
  KeyRound,
  LockKeyhole,
  MessageSquareCheck,
  Radio,
  RefreshCw,
  Send,
  ShieldCheck,
  Siren,
  TerminalSquare,
  UserRoundCheck,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
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
import { useAdminAuth } from "../context/AdminAuthContext";
import { api, ApiError } from "../lib/api";
import { compactId, formatDateTime, formatJson, formatPercent } from "../lib/format";
import type {
  AlertStatus,
  FeedbackRequest,
  FeedbackVerdict,
  RunbookMatchVerdict,
  StoredAlert,
} from "../types/api";

const activeStatuses: AlertStatus[] = ["RECEIVED", "QUEUED", "ANALYZING"];
const terminalStages = ["COMPLETED", "REVIEW_REQUIRED", "FAILED"];
const feedbackStatuses: AlertStatus[] = ["COMPLETED", "REVIEW_REQUIRED"];

const feedbackVerdictLabel: Record<FeedbackVerdict, string> = {
  CONFIRMED: "确认结论",
  CORRECTED: "修正结论",
  REJECTED: "否定结论",
};

const runbookVerdictLabel: Record<RunbookMatchVerdict, string> = {
  CORRECT: "手册命中正确",
  INCORRECT: "命中了错误手册",
  MISSED: "漏掉了正确手册",
  NOT_APPLICABLE: "本次不适用手册",
  UNKNOWN: "暂不评价",
};

function textList(value: FormDataEntryValue | null): string[] {
  return String(value || "")
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .filter((item, index, items) => items.indexOf(item) === index);
}

function lineList(value: FormDataEntryValue | null): string[] {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
    .filter((item, index, items) => items.indexOf(item) === index);
}

function optionalText(value: FormDataEntryValue | null): string | undefined {
  return String(value || "").trim() || undefined;
}

function newFeedbackKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `feedback-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const { token, unlocked, unlock, lock } = useAdminAuth();
  const [record, setRecord] = useState<StoredAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [feedbackVerdict, setFeedbackVerdict] = useState<FeedbackVerdict>("CONFIRMED");
  const [runbookFeedbackVerdict, setRunbookFeedbackVerdict] =
    useState<RunbookMatchVerdict>("UNKNOWN");
  const [feedbackKey, setFeedbackKey] = useState(newFeedbackKey);
  const [feedbackSaving, setFeedbackSaving] = useState(false);
  const [feedbackError, setFeedbackError] = useState("");
  const [feedbackNotice, setFeedbackNotice] = useState("");
  const [unlockToken, setUnlockToken] = useState("");

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
  useEffect(() => {
    setFeedbackVerdict("CONFIRMED");
    setRunbookFeedbackVerdict("UNKNOWN");
    setFeedbackKey(newFeedbackKey());
    setFeedbackError("");
    setFeedbackNotice("");
  }, [alertId]);

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

  function unlockFeedback(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextToken = unlockToken.trim();
    if (!nextToken) return;
    unlock(nextToken);
    setUnlockToken("");
    setFeedbackError("");
  }

  async function submitFeedback(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    if (!record || !feedbackStatuses.includes(record.status)) {
      setFeedbackError("只有已完成或待人工复核的调查可以提交反馈。");
      return;
    }
    if (
      record.latest_run
      && record.feedback.some((item) => item.run_id === record.latest_run?.id)
    ) {
      setFeedbackError("本次调查的人工审核已经提交，审核意见不可重复修改。");
      return;
    }
    if (!token) {
      setFeedbackError("请先解锁管理员会话。");
      return;
    }

    setFeedbackSaving(true);
    setFeedbackError("");
    setFeedbackNotice("");
    try {
      const form = new FormData(formElement);
      const finalRootCause = optionalText(form.get("final_root_cause"));
      const actualResolution = optionalText(form.get("actual_resolution"));
      const correctRunbookId = optionalText(form.get("correct_runbook_id"));
      const correctRunbookSection = optionalText(form.get("correct_runbook_section"));
      const missedRunbookIds = textList(form.get("missed_runbook_ids"));
      const wrongAgentClaims = lineList(form.get("wrong_agent_claims"));
      const supportingEvidenceIds = form.getAll("supporting_evidence_ids").map(String);
      const acceptedStepOrders = form.getAll("accepted_step_orders").map(Number);
      const recoveredValue = String(form.get("recovered") || "");

      if (
        ["CONFIRMED", "CORRECTED"].includes(feedbackVerdict)
        && (!finalRootCause || !actualResolution)
      ) {
        throw new Error("确认或修正结论时，必须填写最终根因和实际恢复动作。");
      }

      const requiresCorrectRunbook = ["CORRECT", "INCORRECT", "MISSED"].includes(
        runbookFeedbackVerdict,
      );
      if (requiresCorrectRunbook && !correctRunbookId) {
        throw new Error("当前手册评价需要填写正确手册 ID。");
      }
      if (correctRunbookSection && !correctRunbookId) {
        throw new Error("填写手册章节前，请先填写正确手册 ID。");
      }

      const retrievedRunbookIds = new Set(record.manual_matches.map((item) => item.runbook_id));
      if (
        runbookFeedbackVerdict === "CORRECT"
        && correctRunbookId
        && !retrievedRunbookIds.has(correctRunbookId)
      ) {
        throw new Error("“命中正确”只能引用本次实际命中的手册。");
      }
      if (
        runbookFeedbackVerdict === "MISSED"
        && correctRunbookId
        && retrievedRunbookIds.has(correctRunbookId)
      ) {
        throw new Error("“漏掉手册”必须填写本次未命中的手册 ID。");
      }
      if (
        runbookFeedbackVerdict === "NOT_APPLICABLE"
        && (correctRunbookId || correctRunbookSection)
      ) {
        throw new Error("手册不适用时不能填写正确手册或章节。");
      }

      if (missedRunbookIds.length > 20) {
        throw new Error("漏召回手册最多填写 20 个。");
      }
      if (supportingEvidenceIds.length > 50) {
        throw new Error("支持证据最多选择 50 项。");
      }
      if (wrongAgentClaims.length > 20) {
        throw new Error("错误声明最多填写 20 条。");
      }
      if (
        acceptedStepOrders.length > 50
        || acceptedStepOrders.some((order) => !Number.isInteger(order))
      ) {
        throw new Error("采纳步骤选择不正确。");
      }

      const successfulEvidenceIds = new Set(
        record.evidence_records
          .filter((item) => item.status === "SUCCESS")
          .map((item) => item.id),
      );
      if (supportingEvidenceIds.some((id) => !successfulEvidenceIds.has(id))) {
        throw new Error("只能引用本次调查中采集成功的证据。");
      }

      const validStepOrders = new Set(record.recommendation?.steps.map((step) => step.order) || []);
      if (acceptedStepOrders.some((order) => !validStepOrders.has(order))) {
        throw new Error("只能采纳本次建议中存在的步骤。");
      }

      const payload: FeedbackRequest = {
        idempotency_key: feedbackKey,
        verdict: feedbackVerdict,
        runbook_match_verdict: runbookFeedbackVerdict,
        missed_runbook_ids: missedRunbookIds,
        supporting_evidence_ids: supportingEvidenceIds,
        wrong_agent_claims: wrongAgentClaims,
        accepted_step_orders: acceptedStepOrders,
      };
      if (finalRootCause) payload.final_root_cause = finalRootCause;
      if (actualResolution) payload.actual_resolution = actualResolution;
      if (correctRunbookId) payload.correct_runbook_id = correctRunbookId;
      if (correctRunbookSection) payload.correct_runbook_section = correctRunbookSection;
      if (recoveredValue === "true") payload.recovered = true;
      if (recoveredValue === "false") payload.recovered = false;

      const saved = await api.submitFeedback(alertId, payload, token);
      setRecord((current) => {
        if (!current) return current;
        const exists = current.feedback.some((item) => item.id === saved.id);
        return {
          ...current,
          status: "COMPLETED",
          feedback: exists
            ? current.feedback.map((item) => (item.id === saved.id ? saved : item))
            : [...current.feedback, saved],
        };
      });
      setFeedbackNotice("人工反馈已保存，并写入本次调查的审计记录。");
      setFeedbackKey(newFeedbackKey());
      setFeedbackVerdict("CONFIRMED");
      setRunbookFeedbackVerdict("UNKNOWN");
      formElement.reset();
    } catch (submitError) {
      if (
        submitError instanceof ApiError
        && submitError.status === 409
        && submitError.problem?.code === "FEEDBACK_ALREADY_SUBMITTED"
      ) {
        setFeedbackError("本次调查的人工审核已经提交，正在载入已固定的审核意见。");
        void load(true);
      } else if (submitError instanceof ApiError && [401, 403].includes(submitError.status)) {
        setFeedbackError("管理员令牌无效或已过期，请锁定后重新输入。");
      } else {
        setFeedbackError(
          submitError instanceof Error ? submitError.message : "人工反馈提交失败",
        );
      }
    } finally {
      setFeedbackSaving(false);
    }
  }

  if (loading && !record) return <LoadingState label="正在读取完整排查链路…" />;
  if (error && !record) return <ErrorState message={error} onRetry={() => void load()} />;
  if (!record) return <EmptyState title="告警不存在" description="该记录可能已被删除，或链接中的 ID 不正确。" />;

  const { alert, recommendation } = record;
  const isActive = isTracking;
  const currentFeedback = record.latest_run
    ? record.feedback.find((item) => item.run_id === record.latest_run?.id)
    : undefined;
  const feedbackStatusAllowed = feedbackStatuses.includes(record.status);
  const singleManualMatch = record.manual_matches.length === 1 ? record.manual_matches[0] : null;
  const successfulEvidence = record.evidence_records.filter(
    (evidence) => evidence.status === "SUCCESS",
  );

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
                    <span className="score-chip">置信度 {formatPercent(match.match_confidence)}</span>
                  </summary>
                  <div className="runbook-content">
                    <p>页码：{match.page_refs.join("、") || "未标注"} · 质量：{match.quality_status} · {match.match_reasons.join("；")}</p>
                    {match.content}
                  </div>
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
              <div className="recommendation-kicker"><span>AI 处理建议</span>{recommendation.analysis_mode === "shadow" && <span className="manual-proof"><Eye size={13} /> 影子分析</span>}{recommendation.manual_matched && <span className="manual-proof"><BookCheck size={13} /> 手册约束</span>}</div>
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
                    <div><strong>{rootCause.cause}</strong><p>{rootCause.evidence_refs.length ? `关联证据：${rootCause.evidence_refs.map((id) => compactId(id, 6)).join("、")}` : "暂未关联可验证证据"}</p>{rootCause.next_probe && <p>下一步：{rootCause.next_probe}</p>}</div>
                    <span className="root-confidence">{formatPercent(rootCause.confidence)}</span>
                    <span className="verified-label">{rootCause.verified ? <><Check size={13} /> 已验证</> : <><CircleAlert size={13} /> {rootCause.status}</>}</span>
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

      <SectionCard
        eyebrow="EXPERT REVIEW"
        title="人工反馈与训练记录"
        description="反馈由管理员提交并写入审计链路；确认或修正且已恢复的记录可形成同类历史案例。"
        action={<span className="evidence-count">{record.feedback.length} 条反馈</span>}
      >
        {record.feedback.length > 0 ? (
          <div className="feedback-history">
            {record.feedback.map((feedback) => (
              <article
                key={feedback.id}
                className={`feedback-record feedback-${feedback.verdict.toLowerCase()}`}
              >
                <header>
                  <span>
                    <MessageSquareCheck size={16} />
                    {feedbackVerdictLabel[feedback.verdict]}
                  </span>
                  <time dateTime={feedback.created_at}>
                    {feedback.reviewer} · {formatDateTime(feedback.created_at)}
                  </time>
                </header>
                <dl>
                  <div>
                    <dt>恢复状态</dt>
                    <dd>
                      {feedback.recovered == null
                        ? "未记录"
                        : feedback.recovered ? "已恢复" : "尚未恢复"}
                    </dd>
                  </div>
                  <div>
                    <dt>手册评价</dt>
                    <dd>{runbookVerdictLabel[feedback.runbook_match_verdict]}</dd>
                  </div>
                  {feedback.final_root_cause && (
                    <div className="span-2">
                      <dt>最终根因</dt>
                      <dd>{feedback.final_root_cause}</dd>
                    </div>
                  )}
                  {feedback.actual_resolution && (
                    <div className="span-2">
                      <dt>实际恢复动作</dt>
                      <dd>{feedback.actual_resolution}</dd>
                    </div>
                  )}
                  {feedback.correct_runbook_id && (
                    <div className="span-2">
                      <dt>正确手册</dt>
                      <dd>
                        {feedback.correct_runbook_id}
                        {feedback.correct_runbook_section
                          ? ` / ${feedback.correct_runbook_section}`
                          : ""}
                      </dd>
                    </div>
                  )}
                </dl>
                {(feedback.supporting_evidence_ids.length > 0
                  || feedback.accepted_step_orders.length > 0
                  || feedback.missed_runbook_ids.length > 0) && (
                  <div className="feedback-reference-groups">
                    {feedback.supporting_evidence_ids.length > 0 && (
                      <p>
                        <span>支持证据</span>
                        {feedback.supporting_evidence_ids.map((id) => (
                          <code key={id}>{compactId(id, 6)}</code>
                        ))}
                      </p>
                    )}
                    {feedback.accepted_step_orders.length > 0 && (
                      <p>
                        <span>采纳步骤</span>
                        {feedback.accepted_step_orders.map((order) => (
                          <code key={order}>#{order}</code>
                        ))}
                      </p>
                    )}
                    {feedback.missed_runbook_ids.length > 0 && (
                      <p>
                        <span>漏召回手册</span>
                        {feedback.missed_runbook_ids.map((id) => (
                          <code key={id}>{id}</code>
                        ))}
                      </p>
                    )}
                  </div>
                )}
                {feedback.wrong_agent_claims.length > 0 && (
                  <details className="feedback-wrong-claims">
                    <summary>查看 Agent 错误声明</summary>
                    <ul>
                      {feedback.wrong_agent_claims.map((claim, index) => (
                        <li key={`${claim}-${index}`}>{claim}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </article>
            ))}
          </div>
        ) : (
          <div className="feedback-empty">
            <UserRoundCheck size={20} />
            <span>尚未提交人工反馈</span>
          </div>
        )}

        <div className="feedback-divider" />

        {currentFeedback ? (
          <div className="feedback-locked">
            <LockKeyhole size={17} />
            <span>
              本次调查的人工审核已完成，审核意见已经固定，不能再次提交或覆盖。
            </span>
          </div>
        ) : !feedbackStatusAllowed ? (
          <div className="feedback-not-ready">
            <CircleAlert size={17} />
            <span>调查完成或进入人工复核后，管理员才能提交反馈。</span>
          </div>
        ) : unlocked ? (
          <form className="feedback-form" onSubmit={submitFeedback}>
            <div className="feedback-form-heading">
              <div>
                <strong>提交本次调查反馈</strong>
                <span>管理员身份由当前 Bearer Token 确认，页面不会提交 reviewer 字段。</span>
              </div>
              <button
                type="button"
                className="button secondary small"
                onClick={() => {
                  lock();
                  setFeedbackError("");
                  setFeedbackNotice("");
                }}
                disabled={feedbackSaving}
              >
                <KeyRound size={14} /> 锁定
              </button>
            </div>

            <div className="form-grid two-cols">
              <label className="field">
                <span>结论评价 <b>*</b></span>
                <select
                  name="verdict"
                  value={feedbackVerdict}
                  onChange={(event) =>
                    setFeedbackVerdict(event.target.value as FeedbackVerdict)}
                >
                  <option value="CONFIRMED">确认：结论准确</option>
                  <option value="CORRECTED">修正：需要更正结论</option>
                  <option value="REJECTED">否定：结论不可采纳</option>
                </select>
              </label>
              <label className="field">
                <span>故障是否恢复</span>
                <select name="recovered" defaultValue="">
                  <option value="">未确认</option>
                  <option value="true">已恢复</option>
                  <option value="false">尚未恢复</option>
                </select>
              </label>
              <label className="field span-2">
                <span>
                  最终根因 {feedbackVerdict !== "REJECTED" && <b>*</b>}
                </span>
                <textarea
                  name="final_root_cause"
                  rows={3}
                  required={feedbackVerdict !== "REJECTED"}
                  placeholder="由值班人员确认的最终根因"
                />
              </label>
              <label className="field span-2">
                <span>
                  实际恢复动作 {feedbackVerdict !== "REJECTED" && <b>*</b>}
                </span>
                <textarea
                  name="actual_resolution"
                  rows={3}
                  required={feedbackVerdict !== "REJECTED"}
                  placeholder="实际执行并验证有效的恢复动作"
                />
              </label>
              <label className="field">
                <span>手册匹配评价</span>
                <select
                  name="runbook_match_verdict"
                  value={runbookFeedbackVerdict}
                  onChange={(event) =>
                    setRunbookFeedbackVerdict(event.target.value as RunbookMatchVerdict)}
                >
                  <option value="UNKNOWN">暂不评价</option>
                  <option value="CORRECT">命中正确</option>
                  <option value="INCORRECT">命中错误</option>
                  <option value="MISSED">漏召回</option>
                  <option value="NOT_APPLICABLE">不适用手册</option>
                </select>
              </label>

              {!["UNKNOWN", "NOT_APPLICABLE"].includes(runbookFeedbackVerdict) && (
                <label className="field">
                  <span>正确手册 ID <b>*</b></span>
                  <input
                    key={`runbook-${runbookFeedbackVerdict}`}
                    name="correct_runbook_id"
                    list="matched-runbook-ids"
                    required
                    maxLength={128}
                    defaultValue={
                      runbookFeedbackVerdict === "CORRECT"
                        ? singleManualMatch?.runbook_id || ""
                        : ""
                    }
                    placeholder={
                      runbookFeedbackVerdict === "MISSED"
                        ? "填写本次未命中的手册 ID"
                        : "填写正确手册 ID"
                    }
                  />
                  <datalist id="matched-runbook-ids">
                    {record.manual_matches.map((match) => (
                      <option
                        value={match.runbook_id}
                        key={`${match.runbook_id}-${match.section}`}
                      >
                        {match.title}
                      </option>
                    ))}
                  </datalist>
                </label>
              )}

              {!["UNKNOWN", "NOT_APPLICABLE"].includes(runbookFeedbackVerdict) && (
                <label className="field">
                  <span>正确手册章节</span>
                  <input
                    key={`section-${runbookFeedbackVerdict}`}
                    name="correct_runbook_section"
                    maxLength={200}
                    defaultValue={
                      runbookFeedbackVerdict === "CORRECT"
                        ? singleManualMatch?.section || ""
                        : ""
                    }
                    placeholder="可选，例如 diagnosis"
                  />
                </label>
              )}

              {!["UNKNOWN", "NOT_APPLICABLE"].includes(runbookFeedbackVerdict) && (
                <label className="field span-2">
                  <span>其他漏召回手册 ID</span>
                  <textarea
                    name="missed_runbook_ids"
                    rows={2}
                    placeholder="可选；每行或逗号分隔，最多 20 个"
                  />
                </label>
              )}

              <label className="field span-2">
                <span>Agent 错误声明</span>
                <textarea
                  name="wrong_agent_claims"
                  rows={3}
                  placeholder="可选；每行填写一条需要纠正的声明，最多 20 条"
                />
              </label>
            </div>

            <div className="feedback-selection-grid">
              <fieldset className="feedback-options">
                <legend>支持最终根因的成功证据</legend>
                {successfulEvidence.length > 0 ? (
                  successfulEvidence.map((evidence) => (
                    <label key={evidence.id}>
                      <input
                        type="checkbox"
                        name="supporting_evidence_ids"
                        value={evidence.id}
                      />
                      <span>
                        <strong>{evidence.tool_name}</strong>
                        <small>{evidence.summary}</small>
                      </span>
                    </label>
                  ))
                ) : (
                  <p>本次调查没有可引用的成功证据。</p>
                )}
              </fieldset>

              <fieldset className="feedback-options">
                <legend>已采纳的建议步骤</legend>
                {recommendation?.steps.length ? (
                  recommendation.steps.map((step) => (
                    <label key={step.order}>
                      <input
                        type="checkbox"
                        name="accepted_step_orders"
                        value={step.order}
                      />
                      <span>
                        <strong>步骤 {step.order}</strong>
                        <small>{step.action}</small>
                      </span>
                    </label>
                  ))
                ) : (
                  <p>本次调查没有可标记的建议步骤。</p>
                )}
              </fieldset>
            </div>

            {feedbackError && <div className="form-error" role="alert">{feedbackError}</div>}
            {feedbackNotice && <div className="form-success"><Check size={16} /> {feedbackNotice}</div>}
            <div className="feedback-submit">
              <span>提交后记录不可在控制台删除，请只引用本次调查中的证据和步骤。</span>
              <button className="button primary" type="submit" disabled={feedbackSaving}>
                {feedbackSaving
                  ? "正在保存…"
                  : <><Send size={15} /> 提交反馈</>}
              </button>
            </div>
          </form>
        ) : (
          <div className="feedback-unlock">
            <span className="feedback-unlock-icon"><LockKeyhole size={21} /></span>
            <div>
              <strong>管理员会话未解锁</strong>
              <p>提交反馈会影响训练闭环和历史案例，需使用管理员 Bearer Token。</p>
            </div>
            <form onSubmit={unlockFeedback}>
              <label className="sr-only" htmlFor="feedback-admin-token">
                管理员访问令牌
              </label>
              <input
                id="feedback-admin-token"
                type="password"
                autoComplete="current-password"
                value={unlockToken}
                onChange={(event) => setUnlockToken(event.target.value)}
                placeholder="输入管理员 Bearer Token"
                required
              />
              <button
                className="button primary"
                type="submit"
                disabled={!unlockToken.trim()}
              >
                解锁并填写
              </button>
            </form>
          </div>
        )}
      </SectionCard>

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
