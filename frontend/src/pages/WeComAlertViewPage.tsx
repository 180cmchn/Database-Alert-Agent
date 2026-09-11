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
import { useParams, useSearchParams } from "react-router-dom";
import { AIConclusionContent } from "../components/AIConclusionContent";
import { api } from "../lib/api";
import { formatDateTime, formatPercent, statusLabel } from "../lib/format";
import type { StoredAlert } from "../types/api";

type WeComView = "overview" | "root-cause" | "recovery-advice";


export function WeComAlertViewPage({ view }: { view: WeComView }) {
  const { alertId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get("run_id");
  const [record, setRecord] = useState<StoredAlert | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    api.getAlert(alertId, runId)
      .then((result) => {
        if (active) setRecord(result);
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(requestError instanceof Error ? requestError.message : "内容加载失败");
        }
      });
    return () => { active = false; };
  }, [alertId, runId]);

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
  const selectedStatus = record.selected_run?.status ?? record.status;

  return (
    <main className={`wecom-page severity-${alert.severity.toLowerCase()}`}>
      <header className="wecom-alert-header">
        <div className="wecom-source"><Database size={15} /> 数据库告警 Agent</div>
        <h1>{alert.title}</h1>
        <p>{alert.reason}</p>
        <div className="wecom-meta-row">
          <span className="wecom-severity">{alert.severity}</span>
          <span>{statusLabel[record.status]}</span>
          <time dateTime={alert.occurred_at}>{formatDateTime(alert.occurred_at)}</time>
        </div>
      </header>

      <section className="wecom-facts" aria-label="告警基本信息">
        <div><Server size={15} /><span>告警主机</span><strong>{host}</strong></div>
        <div><Database size={15} /><span>数据库</span><strong>{[alert.database?.engine, alert.database?.database].filter(Boolean).join(" / ") || "未提供"}</strong></div>
        <div><span>环境</span><strong>{alert.environment}</strong></div>
        <div><span>服务</span><strong>{alert.service_name}</strong></div>
      </section>

      {selectedStatus === "FAILED" ? (
        <FailureContent record={record} />
      ) : !recommendation ? (
        <section className="wecom-content-card wecom-empty-content">
          <CircleHelp size={28} />
          <h2>分析结果尚未生成</h2>
          <p>当前运行尚未生成可展示的分析结果。</p>
        </section>
      ) : view === "root-cause" ? (
        <AIConclusionView record={record} />
      ) : view === "recovery-advice" ? (
        <RecoveryAdviceContent record={record} />
      ) : (
        <OverviewContent record={record} />
      )}

      <footer className="wecom-page-footer">
        {selectedStatus === "FAILED"
          ? "失败详情来自该次运行的持久化记录；历史失败不会自动重新分析。"
          : "手册与外部知识资料仅作为线索；本次根因结论以当前事件的实时证据为准。"}
      </footer>
    </main>
  );
}

function FailureContent({ record }: { record: StoredAlert }) {
  const run = record.selected_run ?? record.latest_run;
  const failure = run?.model_failure;
  return (
    <section className="wecom-content-card wecom-empty-content">
      <AlertTriangle size={28} />
      <h2>本次分析失败</h2>
      <p>{failure?.safe_detail || run?.error || record.error || "未记录失败详情"}</p>
      {failure && (
        <div className="wecom-failure-details">
          <p><strong>故障分类：</strong>{failure.category}</p>
          <p><strong>供应商 / 模型：</strong>{[failure.provider, failure.model].filter(Boolean).join(" / ")}</p>
          <p><strong>发生阶段：</strong>{failure.phase}</p>
          {failure.http_status && <p><strong>HTTP 状态：</strong>{failure.http_status}</p>}
          {failure.vendor_code && <p><strong>供应商代码：</strong>{failure.vendor_code}</p>}
          {failure.request_id && <p><strong>请求 ID：</strong>{failure.request_id}</p>}
          <p><strong>调度影响：</strong>{failure.pauses_dispatch ? "触发暂停，需管理员验证后恢复" : "未触发暂停"}</p>
        </div>
      )}
    </section>
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

function AIConclusionView({ record }: { record: StoredAlert }) {
  const recommendation = record.recommendation!;
  return (
    <div className="wecom-content-stack">
      <section className="wecom-content-card wecom-ai-conclusion">
        <div className="wecom-section-title"><BrainCircuit size={20} /><h2>AI 分析结论</h2></div>
        <AIConclusionContent rootCauses={recommendation.root_causes} />
      </section>

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
        <p className="wecom-summary">{recommendation.steps.length > 0 ? "以下为 Agent 基于已证实根因生成的实际恢复处置建议；涉及变更的动作请按前提、风险和审批要求执行，本系统未执行这些动作。" : "现有结果未建立根因；为避免误导，不提供猜测性处置动作或重复核查步骤。"}</p>
      </section>

      <section className="wecom-content-card">
        {recommendation.steps.length > 0 ? (
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
        ) : (
          <p className="wecom-summary">没有可展示的处置动作。</p>
        )}
      </section>

    </div>
  );
}
