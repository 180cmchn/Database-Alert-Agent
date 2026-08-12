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
  Lightbulb,
  LockKeyhole,
  Radio,
  RefreshCw,
  Siren,
  TerminalSquare,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
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
  AnalysisBasis,
  AlertStatus,
  InvestigationRun,
  StoredAlert,
} from "../types/api";

const activeStatuses: AlertStatus[] = ["RECEIVED", "QUEUED", "ANALYZING"];
const terminalStages = ["COMPLETED", "INCONCLUSIVE", "FAILED"];
const runStatusLabel: Record<InvestigationRun["status"], string> = {
  RUNNING: "运行中",
  COMPLETED: "已完成",
  INCONCLUSIVE: "结论不充分",
  FAILED: "失败",
};

function basisLabel(source: AnalysisBasis["source"]): string {
  if (source === "RUNBOOK") return "本地 PDF";
  if (source === "EXTERNAL_KNOWLEDGE") return "外部知识";
  return "AI";
}

function knowledgeReference(reference: AnalysisBasis["source_ref"]): string | null {
  if (!reference) return null;
  if ("runbook_id" in reference) {
    return `${reference.runbook_id} / ${reference.section}`;
  }
  return reference.title;
}

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedRunId = searchParams.get("run_id");
  const { token, unlocked, unlock, lock } = useAdminAuth();
  const [record, setRecord] = useState<StoredAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [unlockToken, setUnlockToken] = useState("");
  const [reanalyzing, setReanalyzing] = useState(false);
  const [reanalyzeError, setReanalyzeError] = useState("");

  const load = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    try {
      const result = await api.getAlert(alertId, selectedRunId);
      setRecord(result);
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "告警详情加载失败");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [alertId, selectedRunId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!record || !window.location.hash) return;
    const targetId = decodeURIComponent(window.location.hash.slice(1));
    window.requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [record]);
  const selectedRun = useMemo(
    () => record?.selected_run || record?.latest_run || null,
    [record],
  );
  const isViewingLatest = Boolean(
    selectedRun && record?.latest_run && selectedRun.id === record.latest_run.id,
  );
  const currentStage = useMemo(
    () => selectedRun?.current_stage || record?.progress.at(-1)?.stage || null,
    [record, selectedRun],
  );
  const isTracking = Boolean(
    record
    && selectedRun
    && selectedRun.status === "RUNNING"
    && (activeStatuses.includes(record.status)
      || !currentStage
      || !terminalStages.includes(currentStage)),
  );
  const latestRunIsActive = record?.latest_run?.status === "RUNNING";

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
      "INCONCLUSIVE",
      "FAILED",
    ].includes(item.stage))),
    [record],
  );

  function unlockReanalysis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextToken = unlockToken.trim();
    if (!nextToken) return;
    unlock(nextToken);
    setUnlockToken("");
  }

  async function handleReanalyze(force: boolean) {
    if (!token) {
      setReanalyzeError("请先解锁管理员会话。");
      return;
    }
    setReanalyzing(true);
    setReanalyzeError("");
    try {
      const started = await api.reanalyzeAlert(alertId, { force }, token);
      const nextSearchParams = new URLSearchParams(searchParams);
      nextSearchParams.set("run_id", started.run_id);
      setSearchParams(nextSearchParams);
    } catch (reanalyzeErr) {
      if (reanalyzeErr instanceof ApiError && [401, 403].includes(reanalyzeErr.status)) {
        setReanalyzeError("管理员令牌无效或已过期，请锁定后重新输入。");
      } else {
        setReanalyzeError(
          reanalyzeErr instanceof Error ? reanalyzeErr.message : "重新分析失败",
        );
      }
    } finally {
      setReanalyzing(false);
    }
  }

  function showRun(runId: string) {
    const nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams.set("run_id", runId);
    setSearchParams(nextSearchParams);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  if (loading && !record) return <LoadingState label="正在读取完整排查链路…" />;
  if (error && !record) return <ErrorState message={error} onRetry={() => void load()} />;
  if (!record) return <EmptyState title="告警不存在" description="该记录可能已被删除，或链接中的 ID 不正确。" />;

  const { alert, recommendation } = record;
  const visibleRootCauses = recommendation?.root_causes || [];
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

      {!isViewingLatest && selectedRun && (
        <div className="historical-run-banner">
          <History size={18} />
          <div>
            <strong>正在查看第 {selectedRun.attempt} 次运行</strong>
            <span>页面中的排查轨迹、PDF 命中、MCP 请求 JSON、AI 建议和校验均属于这一次运行。</span>
          </div>
          {record.latest_run && (
            <button type="button" className="button secondary small" onClick={() => showRun(record.latest_run!.id)}>
              查看最新运行
            </button>
          )}
        </div>
      )}

      {selectedRun
        && selectedRun.status !== "RUNNING"
        && !record.selected_run_result_available && (
          <div className="historical-result-warning">
            <CircleAlert size={17} />
            <span>该运行早于运行级结果存储功能，原有进度、MCP 证据和校验仍可查看，但当时的 PDF 命中与 AI 建议已无法恢复。</span>
          </div>
        )}

      <section className="detail-grid workflow-grid">
        <SectionCard
          eyebrow="LIVE WORKFLOW"
          title="Agent 排查轨迹"
          description={`第 ${selectedRun?.attempt || 1} 次执行 · ${selectedRun?.strategy_id || "等待选择策略"}`}
        >
          <StageTimeline currentStage={currentStage} progress={record.progress} />
        </SectionCard>

        <SectionCard
          eyebrow="LOCAL PDF"
          title="本地 PDF 匹配"
          description="启用本地来源时展示达到匹配阈值的手册"
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
                    <p>页码：{match.page_refs.join("、") || "未标注"} · {match.match_reasons.join("；")}</p>
                    {match.content}
                  </div>
                </details>
              ))}
            </div>
          ) : selectedRun?.status !== "RUNNING" && !record.selected_run_result_available ? (
            <EmptyState title="历史 PDF 结果不可恢复" description="该次运行只保留了进度和现场证据，未保存独立的 PDF 匹配结果。" />
          ) : isActive && !runbookSearchFinished ? (
            <div className="waiting-panel"><BookCheck size={24} /><strong>正在检索处置手册</strong><span>结果会在匹配阶段完成后显示</span></div>
          ) : (
            <EmptyState kind="runbook" title="未命中处置手册" description="Agent 的通用建议应降低置信度，并明确标记尚需补充的证据。" />
          )}
        </SectionCard>

      </section>

      {recommendation?.external_knowledge_matches.length ? (
        <SectionCard
          eyebrow="EXTERNAL KNOWLEDGE"
          title="外部知识库匹配"
          description="外部知识与本地 PDF 同级作为知识依据，但均不能单独证明本次事故根因。"
          action={<span className="match-score"><ExternalLink size={14} /> 命中 {recommendation.external_knowledge_matches.length} 条</span>}
        >
          <div className="runbook-evidence-list">
            {recommendation.external_knowledge_matches.map((match) => (
              <details key={match.knowledge_id} className="runbook-evidence" open={recommendation.external_knowledge_matches.length === 1}>
                <summary>
                  <div><strong>{match.title}</strong><span>{match.knowledge_id}</span></div>
                  <span className="score-chip">相关度 {formatPercent(match.score)}</span>
                </summary>
                <div className="runbook-content">
                  <p>来源：{match.source_uri}</p>
                  {match.content}
                </div>
              </details>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {recommendation?.knowledge_match_summary && (
        <div className="knowledge-match-summary">
          <CircleAlert size={18} />
          <div>
            <strong>知识匹配说明</strong>
            <span>{recommendation.knowledge_match_summary}</span>
          </div>
        </div>
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
              <div className="recommendation-kicker"><span>AI 处理建议</span>{recommendation.analysis_mode === "shadow" && <span className="manual-proof"><Eye size={13} /> 影子分析</span>}{recommendation.manual_matched && <span className="manual-proof"><BookCheck size={13} /> 本地 PDF 命中</span>}{recommendation.external_knowledge_matches.length > 0 && <span className="manual-proof"><ExternalLink size={13} /> 外部知识命中</span>}</div>
              <h2>{recommendation.summary}</h2>
              <div className="recommendation-meta">
                <span><Gauge size={15} /> 置信度 <strong>{formatPercent(recommendation.confidence)}</strong></span>
                {record.advisor_metadata && <span><Bot size={15} /> {record.advisor_metadata.model}</span>}
              </div>
            </div>
          </div>

          <SectionCard eyebrow="ROOT CAUSE" title="采证后根因判断">
            {visibleRootCauses.length > 0 ? (
              <div className="root-causes">
                {visibleRootCauses.map((rootCause, index) => (
                  <article key={`${rootCause.cause}-${index}`} className={rootCause.verified ? "verified" : "unverified"}>
                    <span className="root-index">{String(index + 1).padStart(2, "0")}</span>
                    <div><strong>{rootCause.cause}</strong><p>{rootCause.evidence_refs.length ? `关联证据：${rootCause.evidence_refs.map((id) => compactId(id, 6)).join("、")}` : "暂未关联可验证证据"}</p>{rootCause.next_probe && <p>下一步：{rootCause.next_probe}</p>}</div>
                    <span className="root-confidence">{formatPercent(rootCause.confidence)}</span>
                    <span className="verified-label">{rootCause.verified ? <><Check size={13} /> 已验证</> : <><CircleAlert size={13} /> {rootCause.status}</>}</span>
                  </article>
                ))}
              </div>
            ) : (
              <EmptyState title="现有结果无法得出根因" description="" />
            )}
          </SectionCard>

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
                      {step.source_ref && <span className="source-ref">{"knowledge_id" in step.source_ref ? <ExternalLink size={13} /> : <BookCheck size={13} />} {knowledgeReference(step.source_ref)}</span>}
                    </div>
                  </li>
                ))}
              </ol>
            </SectionCard>

            <div className="advice-side">
              <SectionCard eyebrow="BASIS" title="判断依据" description="所选知识来源的依据同级展示，AI 分析列在其后">
                {recommendation.analysis_bases.length ? <ol className="likely-causes">{recommendation.analysis_bases.map((basis, index) => { const reference = knowledgeReference(basis.source_ref); return <li key={`${basis.source}-${basis.statement}-${index}`}><span>{index + 1}</span><div><strong>{basisLabel(basis.source)}</strong> · {basis.statement}{reference && <small className="source-ref">{basis.source === "EXTERNAL_KNOWLEDGE" ? <ExternalLink size={13} /> : <BookCheck size={13} />} {reference}</small>}</div></li>; })}</ol> : <p className="muted-copy">本次结果没有可用判断依据。</p>}
              </SectionCard>
              <SectionCard eyebrow="RISK GUARD" title="风险提示" className="risk-card">
                {recommendation.risks.length ? <ul className="risk-points">{recommendation.risks.map((risk) => <li key={risk}><Siren size={14} /> {risk}</li>)}</ul> : <p className="muted-copy">没有额外风险提示。</p>}
              </SectionCard>
            </div>
          </section>
        </section>
      ) : (
        <SectionCard eyebrow="AI ADVICE" title="处理建议">
          <div className="waiting-panel large">
            <Bot size={29} />
            <strong>{isActive ? "Agent 正在形成处理建议" : !record.selected_run_result_available ? "历史 AI 建议不可恢复" : "本次分析未生成建议"}</strong>
            <span>{isActive ? "建议将在证据采集与独立校验结束后显示。" : !record.selected_run_result_available ? "该次运行发生在运行级结果开始保存之前。" : "请查看上方错误和校验记录；本次未形成可采纳结论。"}</span>
          </div>
        </SectionCard>
      )}

      <section className="detail-grid audit-grid">
        <SectionCard eyebrow="VALIDATION" title="独立校验" description="规则与 Agent 验收分别判断分析契约和实时证据是否充分">
          {record.validations.length ? (
            <div className="validation-list">
              {record.validations.map((validation) => {
                const state = !validation.passed
                  ? "rejected"
                  : validation.evidence_sufficient
                    ? "passed"
                    : "needs-evidence";
                const detail = !validation.passed
                  ? validation.issues.join("；") || "分析契约未通过"
                  : validation.evidence_sufficient
                    ? "分析契约通过，实时证据充分"
                    : "分析契约通过，但实时证据不足，结论不充分";
                return (
                  <article key={validation.id} className={state}>
                    <span>{state === "rejected" ? <XCircle size={18} /> : state === "needs-evidence" ? <CircleAlert size={18} /> : <FileCheck2 size={18} />}</span>
                    <div><strong>{validation.kind === "RULE" ? "确定性规则校验" : "独立 Agent 校验"}</strong><p>{detail}</p></div>
                    <b>{state === "rejected" ? "REJECT" : state === "needs-evidence" ? "PASS · INCONCLUSIVE" : "PASS · EVIDENCE"}</b>
                  </article>
                );
              })}
            </div>
          ) : <EmptyState title="暂无校验记录" description="建议生成后，校验结果会记录在审计链路中。" />}
        </SectionCard>

      </section>

      <SectionCard
        eyebrow="DEBUG TOOLS"
        title="重新分析告警"
        description="使用当前的 runtime-settings.json 配置重新分析此告警，用于调试和对比不同配置的分析结果。"
        action={unlocked ? (
          <button
            type="button"
            className="button secondary small"
            onClick={() => {
              lock();
              setReanalyzeError("");
            }}
          >
            <KeyRound size={14} /> 锁定
          </button>
        ) : undefined}
      >
        {unlocked ? (
          <>
            {reanalyzeError && (
              <div className="form-error" role="alert" style={{ marginBottom: "1rem" }}>
                {reanalyzeError}
              </div>
            )}
            <div className="reanalyze-panel">
              <div className="reanalyze-info">
                <Lightbulb size={20} />
                <div>
                  <strong>当前配置将被记录</strong>
                  <p>
                    重新分析会使用当前 runtime-settings.json 中的配置（知识来源、模型、参数等），
                    并将配置快照保存到新的运行记录中，方便对比不同配置的分析结果。
                  </p>
                </div>
              </div>
              <div className="reanalyze-actions">
                <button
                  className="button primary"
                  type="button"
                  onClick={() => handleReanalyze(false)}
                  disabled={reanalyzing || latestRunIsActive}
                  title={latestRunIsActive ? "当前有分析正在运行，请使用强制重新分析" : "使用当前配置重新分析"}
                >
                  {reanalyzing ? (
                    "正在启动..."
                  ) : (
                    <><RefreshCw size={15} /> 重新分析</>
                  )}
                </button>
                {latestRunIsActive && (
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => handleReanalyze(true)}
                    disabled={reanalyzing}
                    title="强制终止当前运行并重新分析"
                  >
                    {reanalyzing ? (
                      "正在启动..."
                    ) : (
                      <><RefreshCw size={15} /> 强制重新分析</>
                    )}
                  </button>
                )}
              </div>
            </div>
          </>
        ) : (
          <div className="reanalyze-unlock">
            <span className="reanalyze-unlock-icon"><LockKeyhole size={21} /></span>
            <div>
              <strong>管理员会话未解锁</strong>
              <p>重新分析会创建新的运行记录，需使用管理员 Bearer Token。</p>
            </div>
            <form onSubmit={unlockReanalysis}>
              <label className="sr-only" htmlFor="reanalyze-admin-token">
                管理员访问令牌
              </label>
              <input
                id="reanalyze-admin-token"
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
                解锁重新分析
              </button>
            </form>
          </div>
        )}
      </SectionCard>

      {/* Analysis History Section */}
      {record.all_runs.length > 1 && (
        <SectionCard
          eyebrow="ANALYSIS HISTORY"
          title="分析历史记录"
          description="点击任意运行即可切换到当时的完整告警分析页；URL 可直接分享和回看。"
          action={<span className="evidence-count">{record.all_runs.length} 次运行</span>}
        >
          <div className="analysis-history-list">
            {record.all_runs.map((run) => (
              <article
                key={run.id}
                className={`analysis-history-item ${run.id === record.latest_run?.id ? "current" : ""} ${run.id === selectedRun?.id ? "selected" : ""}`}
              >
                <header>
                  <div className="run-header-main">
                    <button type="button" className="run-attempt" onClick={() => showRun(run.id)}>
                      第 {run.attempt} 次运行
                    </button>
                    <span className={`run-status-badge run-status-${run.status.toLowerCase()}`}>
                      {runStatusLabel[run.status]}
                    </span>
                    {run.id === record.latest_run?.id && (
                      <span className="current-badge">最新</span>
                    )}
                    {run.id === selectedRun?.id && (
                      <span className="selected-badge">正在查看</span>
                    )}
                  </div>
                  <div className="run-history-actions">
                    <time dateTime={run.created_at}>{formatDateTime(run.created_at)}</time>
                    <button type="button" className="run-open-button" onClick={() => showRun(run.id)}>
                      <Eye size={13} /> 打开本次分析
                    </button>
                  </div>
                </header>
                {run.error && (
                  <div className="run-error">
                    <CircleAlert size={14} />
                    {run.error}
                  </div>
                )}
                {run.config_snapshot && (
                  <details className="config-snapshot-details">
                    <summary>查看配置快照</summary>
                    <dl className="config-snapshot-grid">
                      <div>
                        <dt>知识来源</dt>
                        <dd>{run.config_snapshot.knowledge_sources.join(", ") || "默认"}</dd>
                      </div>
                      <div>
                        <dt>外部知识库</dt>
                        <dd>
                          {run.config_snapshot.external_knowledge_enabled
                            ? run.config_snapshot.external_knowledge_base_url || "已启用"
                            : "未启用"}
                        </dd>
                      </div>
                      <div>
                        <dt>手册上限</dt>
                        <dd>{run.config_snapshot.runbook_limit}</dd>
                      </div>
                      <div>
                        <dt>PDF 最低置信度</dt>
                        <dd>{formatPercent(run.config_snapshot.runbook_match_min_confidence)}</dd>
                      </div>
                      <div>
                        <dt>外部知识最低相关度</dt>
                        <dd>{formatPercent(run.config_snapshot.external_knowledge_min_relevance)}</dd>
                      </div>
                      <div>
                        <dt>历史动态规划配置</dt>
                        <dd>
                          {run.config_snapshot.react_enabled
                            ? `旧值启用（最多 ${run.config_snapshot.react_max_dynamic_turns} 轮）`
                            : "旧值禁用"}
                          ，当前流程不使用
                        </dd>
                      </div>
                      <div>
                        <dt>校验</dt>
                        <dd>{run.config_snapshot.validation_enabled ? "启用" : "禁用"}</dd>
                      </div>
                      <div>
                        <dt>影子模式</dt>
                        <dd>{run.config_snapshot.shadow_enabled ? "启用" : "禁用"}</dd>
                      </div>
                      <div>
                        <dt>AI Fallback</dt>
                        <dd>{run.config_snapshot.ai_fallback_enabled ? "启用" : "禁用"}</dd>
                      </div>
                      <div>
                        <dt>AI 模型</dt>
                        <dd>
                          {run.config_snapshot.ai_provider}
                          {run.config_snapshot.ai_model && ` / ${run.config_snapshot.ai_model}`}
                        </dd>
                      </div>
                    </dl>
                  </details>
                )}
                <div className="run-meta">
                  <span>Run ID: {compactId(run.id)}</span>
                  {run.strategy_id && <span>策略: {run.strategy_id}</span>}
                </div>
              </article>
            ))}
          </div>
        </SectionCard>
      )}

      <SectionCard eyebrow="TRACEABILITY" title="事件标识与审计信息">
        <dl className="traceability-grid">
          <div><dt>告警 ID</dt><dd>{alert.id}</dd></div>
          <div><dt>事件指纹</dt><dd>{alert.incident_fingerprint || "尚未生成"}</dd></div>
          <div><dt>来源适配器</dt><dd>{alert.source}</dd></div>
          <div><dt>最后更新</dt><dd>{formatDateTime(record.updated_at)}</dd></div>
          {record.advisor_metadata?.request_id && <div><dt>模型请求 ID</dt><dd>{record.advisor_metadata.request_id}</dd></div>}
        </dl>
        <details className="json-details raw-alert"><summary><ExternalLink size={14} /> 查看脱敏后的原始告警</summary><pre>{formatJson(alert.raw_payload)}</pre></details>
      </SectionCard>
    </div>
  );
}
