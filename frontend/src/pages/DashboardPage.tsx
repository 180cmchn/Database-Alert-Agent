import {
  Activity,
  ArrowRight,
  BellRing,
  Bot,
  CheckCircle2,
  CirclePlus,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorState, LoadingState, PageHeader, SectionCard } from "../components/ui";
import { api } from "../lib/api";
import { severityLabel, statusLabel } from "../lib/format";
import type { AlertStatus, DashboardSummary, Severity } from "../types/api";

const statusOrder: AlertStatus[] = [
  "ANALYZING",
  "QUEUED",
  "REVIEW_REQUIRED",
  "COMPLETED",
  "FAILED",
  "RECEIVED",
];
const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
      setError("");
      setLastUpdated(new Date());
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "总览加载失败");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [load]);

  if (loading && !summary) return <LoadingState label="正在汇总告警态势…" />;
  if (error && !summary) return <ErrorState message={error} onRetry={() => void load()} />;

  const statusMax = Math.max(1, ...statusOrder.map((status) => summary?.by_status[status] || 0));
  const severityTotal = severityOrder.reduce(
    (total, severity) => total + (summary?.by_severity[severity] || 0),
    0,
  );

  return (
    <div className="page-stack dashboard-page">
      <PageHeader
        eyebrow="OPERATIONS PULSE"
        title="数据库告警态势"
        description="从告警接入到证据校验，实时观察 Agent 的每一次排查决策。"
        actions={
          <>
            <span className="refresh-meta">
              <span className={refreshing ? "live-dot pulse" : "live-dot"} />
              {lastUpdated ? `${lastUpdated.toLocaleTimeString("zh-CN", { hour12: false })} 更新` : "等待更新"}
            </span>
            <button className="button secondary" type="button" onClick={() => void load(true)} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? "spin" : ""} /> 刷新
            </button>
            <Link className="button primary" to="/alerts/new"><CirclePlus size={17} /> 发起测试</Link>
          </>
        }
      />

      {error && <ErrorState compact message={`自动刷新失败：${error}`} onRetry={() => void load(true)} />}

      <section className="metrics-grid" aria-label="告警关键指标">
        <article className="metric-card total-card">
          <span className="metric-icon"><BellRing size={20} /></span>
          <div><p>累计告警</p><strong>{summary?.total ?? 0}</strong></div>
          <span className="metric-foot">全部已入库事件</span>
        </article>
        <article className="metric-card active-card">
          <span className="metric-icon"><Activity size={20} /></span>
          <div><p>正在处置</p><strong>{summary?.active ?? 0}</strong></div>
          <span className="metric-foot">排队或分析进行中</span>
        </article>
        <article className="metric-card critical-card">
          <span className="metric-icon"><ShieldAlert size={20} /></span>
          <div><p>待处理紧急告警</p><strong>{summary?.critical_open ?? 0}</strong></div>
          <span className="metric-foot">未完成分析或需要人工复核</span>
        </article>
        <article className="metric-card completed-card">
          <span className="metric-icon"><CheckCircle2 size={20} /></span>
          <div><p>已生成建议</p><strong>{summary?.by_status.COMPLETED ?? 0}</strong></div>
          <span className="metric-foot">结论已通过校验</span>
        </article>
      </section>

      <section className="dashboard-split">
        <SectionCard
          eyebrow="AGENT PIPELINE"
          title="排查流水"
          description="不同阶段的告警数量与当前积压"
        >
          <div className="pipeline-bars">
            {statusOrder.map((status) => {
              const count = summary?.by_status[status] || 0;
              return (
                <div className="pipeline-row" key={status}>
                  <span>{statusLabel[status]}</span>
                  <div className="pipeline-track">
                    <span
                      className={`pipeline-fill fill-${status.toLowerCase()}`}
                      style={{ width: `${count ? Math.max(8, (count / statusMax) * 100) : 0}%` }}
                    />
                  </div>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="SEVERITY MIX"
          title="等级分布"
          description="当前数据库告警等级构成"
        >
          <div
            className="severity-ring"
            style={{
              background: severityTotal
                ? `conic-gradient(
                    #ff5964 0 ${(summary?.by_severity.CRITICAL || 0) / severityTotal * 100}%,
                    #ff9b62 0 ${((summary?.by_severity.CRITICAL || 0) + (summary?.by_severity.HIGH || 0)) / severityTotal * 100}%,
                    #f6c85f 0 ${((summary?.by_severity.CRITICAL || 0) + (summary?.by_severity.HIGH || 0) + (summary?.by_severity.MEDIUM || 0)) / severityTotal * 100}%,
                    #43d6a4 0 ${((summary?.by_severity.CRITICAL || 0) + (summary?.by_severity.HIGH || 0) + (summary?.by_severity.MEDIUM || 0) + (summary?.by_severity.LOW || 0)) / severityTotal * 100}%,
                    #63788e 0 100%)`
                : undefined,
            }}
          >
            <div><strong>{severityTotal}</strong><span>条告警</span></div>
          </div>
          <div className="severity-legend">
            {severityOrder.map((severity) => (
              <div key={severity}>
                <span className={`legend-dot severity-${severity.toLowerCase()}`} />
                <span>{severityLabel[severity]}</span>
                <strong>{summary?.by_severity[severity] || 0}</strong>
              </div>
            ))}
          </div>
        </SectionCard>
      </section>

      <SectionCard
        eyebrow="LATEST SIGNALS"
        title="最新告警"
        action={<Link className="text-link" to="/alerts">查看全部 <ArrowRight size={15} /></Link>}
      >
        {summary?.recent_alerts.length ? (
          <AlertTable alerts={summary.recent_alerts} compact />
        ) : (
          <EmptyState
            title="目前没有告警"
            description="新告警进入系统后，会在这里展示 Agent 的分析进度。"
            action={<Link className="button secondary" to="/alerts/new"><Bot size={16} /> 发起测试告警</Link>}
          />
        )}
      </SectionCard>
    </div>
  );
}
