import {
  AlertOctagon,
  ArrowLeft,
  Ban,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
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
  TerminalSquare,
  Users,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { StageTimeline } from "../components/StageTimeline";
import { AgentTrace } from "../components/AgentTrace";
import { AIConclusionContent } from "../components/AIConclusionContent";
import {
  EmptyState,
  ErrorState,
  FlashDutyProgressBadge,
  InlineLoading,
  LoadingState,
  PageHeader,
  SectionCard,
  SeverityBadge,
  StatusBadge,
  ToolStatusBadge,
} from "../components/ui";
import { useAdminAuth } from "../context/AdminAuthContext";
import { api, ApiError } from "../lib/api";
import { compactId, formatDateTime, formatJson, formatPercent, stageLabel } from "../lib/format";
import {
  canRequestRunCancellation,
  isRunCancellationPending,
  shouldPollAlertDetail,
} from "../lib/investigationRun";
import { buildKnowledgeCardModel } from "../lib/knowledgeMatchModel";
import type {
  AnalysisBasis,
  AlertStatus,
  EvidenceUnit,
  FlashDutyHandlingResponse,
  InvestigationRun,
  StoredAlert,
} from "../types/api";

const activeStatuses: AlertStatus[] = ["RECEIVED", "QUEUED", "ANALYZING"];
const terminalStages = ["COMPLETED", "INCONCLUSIVE", "FAILED", "CANCELLED"];
const runStatusLabel: Record<InvestigationRun["status"], string> = {
  RUNNING: "运行中",
  COMPLETED: "已完成",
  INCONCLUSIVE: "结论不充分",
  FAILED: "失败",
  CANCELLED: "已取消",
};

function basisLabel(source: AnalysisBasis["source"]): string {
  return source === "KNOWLEDGE" ? "知识来源" : "AI";
}

function knowledgeReference(reference: AnalysisBasis["source_ref"]): string | null {
  if (!reference) return null;
  return `${reference.title} · ${reference.source}`;
}


function FlashDutyHandlingCard({
  handling,
  loading,
  refreshing,
  error,
  onRetry,
}: {
  handling: FlashDutyHandlingResponse | null;
  loading: boolean;
  refreshing: boolean;
  error: string;
  onRetry: () => void;
}) {
  const action = handling?.progress || refreshing
    ? (
      <div className="flashduty-handling-actions">
        {handling?.progress && <FlashDutyProgressBadge progress={handling.progress} />}
        {refreshing && <InlineLoading label="刷新中" />}
      </div>
    )
    : undefined;

  return (
    <SectionCard
      eyebrow="FLASHDUTY"
      title="当前处理状态"
      description="来自 FlashDuty 关联故障的当前只读快照，不随所选分析运行回放。"
      action={action}
      className="flashduty-handling-card"
    >
      {loading && !handling ? (
        <div className="flashduty-handling-loading"><InlineLoading label="正在读取处理状态" /></div>
      ) : error && !handling ? (
        <ErrorState compact message={error} onRetry={onRetry} />
      ) : handling && !handling.linked_incident ? (
        <div className="flashduty-handling-empty">
          <CircleAlert size={19} />
          <div>
            <strong>暂未关联故障</strong>
            <span>FlashDuty 当前未返回关联 incident，无法推断处理状态。</span>
          </div>
          <div className="flashduty-handling-footer">
            <span>刷新于 {formatDateTime(handling.refreshed_at)}</span>
            <button className="button secondary small" type="button" onClick={onRetry} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "spin" : ""} /> 刷新
            </button>
          </div>
        </div>
      ) : handling ? (
        <div className="flashduty-handling-body">
          <div className="flashduty-handling-meta">
            <span>关联故障</span>
            <strong title={handling.incident_id || undefined}>{handling.incident_id || "—"}</strong>
          </div>
          <div className="flashduty-handler-section">
            <div className="flashduty-handler-heading">
              <Users size={16} />
              <strong>{handling.progress === "Closed" ? "参与处理人" : "当前处理人"}</strong>
            </div>
            {!handling.handlers_complete ? (
              <div className="flashduty-handling-warning" role="status">
                处理人暂时无法完整读取，请稍后重试。
              </div>
            ) : handling.handlers.length > 0 ? (
              <div className="flashduty-handler-list">
                {handling.handlers.map((handler) => (
                  <div className="flashduty-handler" key={`${handler.person_id}-${handler.acknowledged_at}`}>
                    <strong>{handler.person_name || `成员 #${handler.person_id}`}</strong>
                    <span>
                      {handler.assigned_at && `分派于 ${formatDateTime(handler.assigned_at)} · `}
                      认领于 {formatDateTime(handler.acknowledged_at)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <span className="flashduty-handler-empty">
                {handling.progress === "Processing"
                  ? "FlashDuty 未返回已认领人员"
                  : handling.progress === "Closed"
                    ? "未记录参与处理人"
                    : "暂无认领人"}
              </span>
            )}
          </div>
          {error && (
            <div className="flashduty-handling-warning" role="status">
              刷新失败，当前显示上次成功读取的结果：{error}
            </div>
          )}
          <div className="flashduty-handling-footer">
            <span>刷新于 {formatDateTime(handling.refreshed_at)}</span>
            <button className="button secondary small" type="button" onClick={onRetry} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "spin" : ""} /> 刷新
            </button>
          </div>
        </div>
      ) : null}
    </SectionCard>
  );
}

function evidenceUnitQualification(
  unit: Pick<EvidenceUnit, "root_cause_eligible" | "status">,
): string {
  if (unit.root_cause_eligible) return "根因可用";
  if (unit.status === "PARTIAL") return "覆盖不完整";
  if (unit.status === "FAILED") return "不可用";
  if (unit.status === "NO_DATA") return "无数据";
  if (unit.status === "RECOVERED") return "已恢复";
  if (unit.status === "UNAVAILABLE") return "前置条件不可用";
  if (unit.status === "NOT_APPLICABLE") return "不适用";
  return "根因不可用";
}

function historySampleCoverage(unit: EvidenceUnit): string | null {
  if (unit.kind !== "HISTORY") return null;
  const rows = Array.isArray(unit.data.rows) ? unit.data.rows : [];
  const recordedRowCount = unit.data.row_count;
  const rowCount = typeof recordedRowCount === "number" && Number.isInteger(recordedRowCount)
    ? Math.max(recordedRowCount, 0)
    : rows.length;
  if (rowCount === 0) return null;

  let fullCount = 0;
  let structuredCount = 0;
  let prefixCount = 0;
  rows.forEach((row) => {
    if (typeof row !== "object" || row === null || Array.isArray(row)) return;
    const values = row as Record<string, unknown>;
    if (values.sample_representation === "full") fullCount += 1;
    else if (values.sample_representation === "structured") structuredCount += 1;
    else if (typeof values.sample === "string") prefixCount += 1;
  });

  const missingCount = Math.max(
    rowCount - fullCount - structuredCount - prefixCount,
    0,
  );
  const parts = [`Sample：${fullCount} / ${rowCount} 完整`];
  if (structuredCount > 0) parts.push(`${structuredCount} 条结构化摘要`);
  if (prefixCount > 0) parts.push(`${prefixCount} 条前缀`);
  if (missingCount > 0) parts.push(`${missingCount} 条未恢复`);
  return parts.join(" · ");
}

function EvidenceUnitDetails({ units }: { units: EvidenceUnit[] }) {
  const eligibleCount = units.filter((unit) => unit.root_cause_eligible).length;
  const ineligibleCount = units.length - eligibleCount;

  return (
    <details className="evidence-unit-details">
      <summary aria-label={`显示或隐藏 ${units.length} 项工具内部状态`}>
        <span className="evidence-unit-summary-copy">
          <strong>工具内部状态</strong>
          <span>{units.length} 项</span>
          {eligibleCount > 0 && (
            <span className="evidence-unit-eligible">根因可用 {eligibleCount}</span>
          )}
          {ineligibleCount > 0 && <span>不参与根因 {ineligibleCount}</span>}
        </span>
        <span className="evidence-unit-toggle" aria-hidden="true">
          <span className="evidence-unit-show-label">显示更多</span>
          <span className="evidence-unit-hide-label">收起</span>
          <ChevronDown size={14} />
        </span>
      </summary>
      <div className="evidence-unit-list">
        {units.map((unit) => (
          <div className="evidence-unit-row" key={unit.id}>
            <div>
              <strong>
                {unit.kind === "HISTORY" && unit.status === "SUCCESS"
                  ? `History 行集完整 · ${evidenceUnitQualification(unit)}`
                  : unit.kind === "HISTORY" ? "History" : unit.stage}
              </strong>
              <span>{historySampleCoverage(unit) ?? unit.summary}</span>
            </div>
            {!(unit.kind === "HISTORY" && unit.status === "SUCCESS") && (
              <span className={`evidence-unit-status unit-${unit.status.toLowerCase()}`}>
                {unit.status} · {evidenceUnitQualification(unit)}
              </span>
            )}
            <small>单元 {compactId(unit.id)} · 父证据 {compactId(unit.parent_evidence_id)}</small>
          </div>
        ))}
      </div>
    </details>
  );
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
  const [cancelling, setCancelling] = useState(false);
  const [cancelNotice, setCancelNotice] = useState("");
  const [handling, setHandling] = useState<FlashDutyHandlingResponse | null>(null);
  const [handlingLoading, setHandlingLoading] = useState(false);
  const [handlingRefreshing, setHandlingRefreshing] = useState(false);
  const [handlingError, setHandlingError] = useState("");
  const handlingRequestSequence = useRef(0);

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

  const loadFlashDutyHandling = useCallback(async (silent = false) => {
    const requestSequence = ++handlingRequestSequence.current;
    if (silent) setHandlingRefreshing(true);
    else setHandlingLoading(true);
    setHandlingError("");
    try {
      const result = await api.getFlashDutyHandling(alertId);
      if (requestSequence !== handlingRequestSequence.current) return;
      setHandling(result);
    } catch (requestError) {
      if (requestSequence !== handlingRequestSequence.current) return;
      setHandlingError(
        requestError instanceof Error ? requestError.message : "FlashDuty 处理状态加载失败",
      );
    } finally {
      if (requestSequence === handlingRequestSequence.current) {
        setHandlingLoading(false);
        setHandlingRefreshing(false);
      }
    }
  }, [alertId]);

  const isFlashDutyAlert = Boolean(
    record
    && record.alert.id === alertId
    && record.alert.source.toLowerCase() === "flashduty",
  );

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    handlingRequestSequence.current += 1;
    setHandling(null);
    setHandlingError("");
    setHandlingLoading(false);
    setHandlingRefreshing(false);
    if (isFlashDutyAlert) void loadFlashDutyHandling();
  }, [alertId, isFlashDutyAlert, loadFlashDutyHandling]);
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
  const latestRunCancellationPending = isRunCancellationPending(record?.latest_run);
  const shouldPollDetail = shouldPollAlertDetail(selectedRun, record?.latest_run);

  useEffect(() => {
    if (!latestRunIsActive) setCancelNotice("");
  }, [latestRunIsActive]);

  useEffect(() => {
    if (!shouldPollDetail) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 2_500);
    return () => window.clearInterval(timer);
  }, [load, shouldPollDetail]);

  function refreshDetail() {
    void load(true);
    if (isFlashDutyAlert) void loadFlashDutyHandling(true);
  }
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

  async function handleCancelLatestRun() {
    const latestRun = record?.latest_run;
    if (!token || !latestRun || !canRequestRunCancellation(latestRun)) return;
    setCancelling(true);
    setReanalyzeError("");
    setCancelNotice("");
    try {
      await api.cancelRun(alertId, latestRun.id, token);
      setCancelNotice("取消请求已接受，正在等待当前分析安全结束。");
      await load(true);
    } catch (cancelError) {
      if (cancelError instanceof ApiError && [401, 403].includes(cancelError.status)) {
        setReanalyzeError("管理员令牌无效或已过期，请锁定后重新输入。");
      } else {
        setReanalyzeError(cancelError instanceof Error ? cancelError.message : "取消分析失败");
      }
    } finally {
      setCancelling(false);
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
  const isFilteredWithoutRun = record.status === "FILTERED" && !selectedRun;
  const knowledgeCard = buildKnowledgeCardModel({
    run: selectedRun,
    recommendation,
    progress: record.progress,
    resultAvailable: record.selected_run_result_available,
  });

  return (
    <div className="page-stack detail-page">
      <div className="detail-back-row">
        <Link to="/alerts" className="back-link"><ArrowLeft size={15} /> 返回告警中心</Link>
        <span className="detail-refresh">
          {isActive && <><Radio size={14} className="pulse" /> 每 2.5 秒自动跟踪</>}
          <button
            type="button"
            onClick={refreshDetail}
            aria-label="刷新详情与处理状态"
            disabled={refreshing || handlingLoading || handlingRefreshing}
          >
            <RefreshCw size={15} className={refreshing || handlingRefreshing ? "spin" : ""} />
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
        <div><span><CircleAlert size={15} /> 告警项</span><strong>{alert.reason}</strong></div>
        <div><span><Database size={15} /> 数据库目标</span><strong>{[alert.database?.engine, alert.database?.instance].filter(Boolean).join(" · ") || "未提供"}</strong></div>
        <div><span><Gauge size={15} /> 环境 / 服务</span><strong>{alert.environment} · {alert.service_name}</strong></div>
        <div><span><Clock3 size={15} /> 发生时间</span><strong>{formatDateTime(alert.occurred_at)}</strong></div>
      </section>

      {isFlashDutyAlert && (
        <FlashDutyHandlingCard
          handling={handling}
          loading={handlingLoading}
          refreshing={handlingRefreshing}
          error={handlingError}
          onRetry={() => void loadFlashDutyHandling(true)}
        />
      )}

      {!isViewingLatest && selectedRun && (
        <div className="historical-run-banner">
          <History size={18} />
          <div>
            <strong>正在查看第 {selectedRun.attempt} 次运行</strong>
            <span>页面中的排查轨迹、知识匹配、MCP 请求 JSON、AI 建议和校验均属于这一次运行。</span>
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
            <span>该运行早于运行级结果存储功能，原有进度、MCP 证据和校验仍可查看，但当时的知识匹配与 AI 建议已无法恢复。</span>
          </div>
        )}

      {isFilteredWithoutRun ? (
        <SectionCard
          eyebrow="ANALYSIS ADMISSION"
          title="自动分析未启动"
          description="该告警已完成标准化和持久化，但未进入主 Agent 调查流程。"
        >
          <div className="waiting-panel large">
            <CircleAlert size={29} />
            <strong>该告警按等级过滤策略仅入库</strong>
            <span>系统未创建分析运行，也不会发送企微通知；管理员仍可在下方显式发起重新分析。</span>
          </div>
        </SectionCard>
      ) : (
        <>
      <SectionCard className="workflow-strip">
        <details className="workflow-disclosure" key={`${alertId}:${selectedRun?.id || ""}`}>
          <summary>
            <h2 className="workflow-strip-summary">
              <span className="workflow-strip-copy">
                <span className="workflow-strip-title">Agent 排查轨迹</span>
                <span className="workflow-strip-meta">第 {selectedRun?.attempt || 1} 次执行 · 主 Agent ReAct</span>
                <span className="workflow-strip-stage" data-stage={currentStage || undefined}>
                  {isActive && <Radio size={13} className="pulse" aria-hidden="true" />}
                  {currentStage ? stageLabel[currentStage] : "等待执行"}
                </span>
              </span>
              <span className="workflow-strip-toggle">
                <span className="workflow-strip-show-label">查看轨迹</span>
                <span className="workflow-strip-hide-label">收起轨迹</span>
                <ChevronDown size={16} aria-hidden="true" />
              </span>
            </h2>
          </summary>
          <div className="workflow-strip-body">
            <StageTimeline currentStage={currentStage} progress={record.progress} />
          </div>
        </details>
      </SectionCard>

      <section className="detail-grid analysis-results-grid">
        <SectionCard eyebrow="AI CONCLUSION" title="AI 分析结论" className="ai-conclusion-card">
          {recommendation ? (
            <AIConclusionContent
              key={`${alertId}:${selectedRun?.id || ""}`}
              rootCauses={visibleRootCauses}
              collapsibleAnalysisProcess
            />
          ) : (
            <div className="waiting-panel large">
              <Bot size={29} />
              <strong>{isActive ? "Agent 正在形成分析结论" : !record.selected_run_result_available ? "历史 AI 分析结论不可恢复" : "本次分析未生成结论"}</strong>
              <span>{isActive ? "结论将在证据采集与确定性契约校验结束后显示。" : !record.selected_run_result_available ? "该次运行发生在运行级结果开始保存之前。" : "请查看上方错误和校验记录；本次未形成可采纳结论。"}</span>
            </div>
          )}
        </SectionCard>
        <SectionCard
          eyebrow="ACTION PLAN"
          title="建议处理结果"
          description="基于已验证根因给出实际恢复动作；涉及变更时请遵循风险、审批和回滚要求"
        >
          {recommendation ? (
            recommendation.steps.length > 0 ? (
              <ol className="action-steps">
                {recommendation.steps.map((step) => (
                  <li key={step.order}>
                    <span className="step-number">{String(step.order).padStart(2, "0")}</span>
                    <div>
                      <strong>{step.action}</strong>
                      {step.expected_result && <p><CheckCircle2 size={14} /> 预期：{step.expected_result}</p>}
                      {step.caution && <p className="caution"><CircleAlert size={14} /> 注意：{step.caution}</p>}
                      {step.source_ref && <span className="source-ref"><ExternalLink size={13} /> {knowledgeReference(step.source_ref)}</span>}
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted-copy">现有结果未建立根因，因此未生成猜测性处置步骤。</p>
            )
          ) : (
            <div className="waiting-panel">
              <Bot size={29} />
              <strong>
                {isActive
                  ? "Agent 正在生成建议处理结果"
                  : !record.selected_run_result_available
                    ? "历史建议处理结果不可恢复"
                    : "本次分析未生成建议处理结果"}
              </strong>
              <span>
                {isActive
                  ? "建议将在根因确认和结果校验完成后显示。"
                  : !record.selected_run_result_available
                    ? "该次运行发生在运行级结果开始保存之前。"
                    : "请查看页面中的错误与校验记录；本次没有可展示的建议。"}
              </span>
            </div>
          )}
        </SectionCard>
      </section>
        <SectionCard
          eyebrow="KNOWLEDGE"
          title="知识匹配"
          description="展示本次运行的知识来源配置、匹配进度与结果。"
          className="knowledge-match-card"
          action={knowledgeCard.state === "matched"
            ? <span className="match-score"><ExternalLink size={14} /> 命中 {knowledgeCard.matchCount} 条</span>
            : <span className={`knowledge-status knowledge-status-${knowledgeCard.state}`}>{knowledgeCard.state === "matching" && <Radio size={13} className="pulse" />}{knowledgeCard.headline}</span>}
        >
          <div className={`knowledge-card-body knowledge-state-${knowledgeCard.state}`}>
            <div className="knowledge-state-message">
              <span className="knowledge-state-icon">
                {knowledgeCard.state === "matched" ? <CheckCircle2 size={20} />
                  : knowledgeCard.state === "matching" ? <Radio size={20} className="pulse" />
                    : knowledgeCard.state === "unavailable_history" ? <History size={20} />
                      : <CircleAlert size={20} />}
              </span>
              <div>
                <strong>{knowledgeCard.headline}</strong>
                <span>{knowledgeCard.description}</span>
              </div>
            </div>

            {knowledgeCard.sources.length > 0 && (
              <div className="knowledge-source-list">
                <span>本次来源</span>
                {knowledgeCard.sourceOutcomes.length > 0 ? (
                  <div className="knowledge-source-outcomes">
                    {knowledgeCard.sourceOutcomes.map((outcome) => (
                      <article key={outcome.source} className={`knowledge-source-outcome source-${outcome.status}`}>
                        <span>{outcome.status === "matched" ? <CheckCircle2 size={15} /> : <CircleAlert size={15} />}</span>
                        <div>
                          <code>{outcome.source}</code>
                          <small>{outcome.status === "matched"
                            ? `命中 ${outcome.matchCount} 条可用知识`
                            : outcome.status === "unavailable"
                              ? `本次不可用${outcome.error ? ` · ${outcome.error}` : ""}`
                              : "已查询，未匹配到可用知识"}</small>
                        </div>
                        {outcome.durationMs !== null && <b>{outcome.durationMs} ms</b>}
                      </article>
                    ))}
                  </div>
                ) : <div>{knowledgeCard.sources.map((source) => <code key={source}>{source}</code>)}</div>}
              </div>
            )}

            {knowledgeCard.matches.length > 0 && (
              <div className="knowledge-evidence-list">
                {knowledgeCard.matches.map((match) => (
                  <details key={`${match.source}-${match.knowledge_id}`} className="knowledge-evidence" open={knowledgeCard.matches.length === 1}>
                    <summary>
                      <div><strong>{match.title}</strong><span>{match.source} · {match.knowledge_id}</span></div>
                      <span className="score-chip">相关度 {formatPercent(match.score)}</span>
                    </summary>
                    <div className="knowledge-content">
                      <p>来源：{match.source_uri}</p>
                      {match.content}
                    </div>
                  </details>
                ))}
              </div>
            )}

            {knowledgeCard.summary && (
              <div className="knowledge-match-summary">
                <CircleAlert size={18} />
                <div><strong>知识匹配说明</strong><span>{knowledgeCard.summary}</span></div>
              </div>
            )}
          </div>
        </SectionCard>

      {selectedRun && (
        <AgentTrace
          key={`${alertId}:${selectedRun.id}`}
          alertId={alertId}
          runId={selectedRun.id}
          active={isActive}
        />
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
                {evidence.evidence_units.length > 0 && (
                  <EvidenceUnitDetails units={evidence.evidence_units} />
                )}
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

      {recommendation && (
        <SectionCard eyebrow="BASIS" title="判断依据" description="所选知识来源的依据同级展示，AI 分析列在其后">
          {recommendation.analysis_bases.length ? <ol className="likely-causes">{recommendation.analysis_bases.map((basis, index) => { const reference = knowledgeReference(basis.source_ref); return <li key={`${basis.source}-${basis.statement}-${index}`}><span>{index + 1}</span><div><strong>{basisLabel(basis.source)}</strong> · {basis.statement}{reference && <small className="source-ref"><ExternalLink size={13} /> {reference}</small>}</div></li>; })}</ol> : <p className="muted-copy">本次结果没有可用判断依据。</p>}
        </SectionCard>
      )}

        <SectionCard eyebrow="VALIDATION" title="结果契约校验" description="程序只核对结构、引用与来源资格，不重新判断根因">
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
                    <div><strong>{validation.kind === "RULE" ? "确定性契约校验" : "历史 Agent 校验"}</strong><p>{detail}</p></div>
                    <b>{state === "rejected" ? "REJECT" : state === "needs-evidence" ? "PASS · INCONCLUSIVE" : "PASS · EVIDENCE"}</b>
                  </article>
                );
              })}
            </div>
          ) : <EmptyState title="暂无校验记录" description="建议生成后，校验结果会记录在审计链路中。" />}
        </SectionCard>
        </>
      )}


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
            {(cancelNotice || latestRunCancellationPending) && (
              <div className="form-success">
                <Check size={16} /> {cancelNotice || "取消请求已接受，正在等待当前分析安全结束。"}
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
                  <>
                    <button
                      className="button danger"
                      type="button"
                      onClick={() => void handleCancelLatestRun()}
                      disabled={reanalyzing || cancelling || latestRunCancellationPending}
                    >
                      <Ban size={15} /> {
                        cancelling
                          ? "正在请求取消..."
                          : latestRunCancellationPending
                            ? "正在等待分析结束"
                            : "取消当前分析"
                      }
                    </button>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => handleReanalyze(true)}
                      disabled={reanalyzing || cancelling || latestRunCancellationPending}
                      title="创建新的分析运行"
                    >
                      {reanalyzing ? (
                        "正在启动..."
                      ) : (
                        <><RefreshCw size={15} /> 强制重新分析</>
                      )}
                    </button>
                  </>
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
                        <dt>外部知识最低相关度</dt>
                        <dd>{formatPercent(run.config_snapshot.external_knowledge_min_relevance)}</dd>
                      </div>
                      <div>
                        <dt>ReAct 最大轮次</dt>
                        <dd>{run.config_snapshot.react_max_rounds}</dd>
                      </div>
                      <div>
                        <dt>整次分析超时</dt>
                        <dd>{run.config_snapshot.analysis_timeout_seconds} 秒</dd>
                      </div>
                      <div>
                        <dt>AI Fallback</dt>
                        <dd>{run.config_snapshot.ai_fallback_enabled ? "启用" : "禁用"}</dd>
                      </div>
                      <div>
                        <dt>Reasoning 实时展示</dt>
                        <dd>{run.config_snapshot.stream_main_agent_reasoning ? "启用" : "禁用"}</dd>
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
