import { ArrowRight, Beaker, Braces, CheckCircle2, Info, Send } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { InlineLoading, PageHeader, SectionCard, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import type { AlertAccepted, CanonicalAlertPayload, Severity } from "../types/api";

function parseObject(value: string, fieldLabel: string): Record<string, unknown> {
  if (!value.trim()) return {};
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${fieldLabel}必须是 JSON 对象`);
  }
  return parsed as Record<string, unknown>;
}

export function CreateAlertPage() {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [accepted, setAccepted] = useState<AlertAccepted | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const rawLabels = parseObject(String(form.get("labels") || ""), "标签");
      if (Object.values(rawLabels).some((value) => typeof value !== "string")) {
        throw new Error("标签 JSON 的值必须全部是字符串");
      }
      const payload: CanonicalAlertPayload = {
        external_id: String(form.get("external_id") || "").trim() || undefined,
        severity: String(form.get("severity")) as Severity,
        title: String(form.get("title") || "").trim(),
        reason: String(form.get("reason") || "").trim(),
        description: String(form.get("description") || "").trim(),
        environment: String(form.get("environment") || "").trim() || undefined,
        service_name: String(form.get("service_name") || "").trim() || undefined,
        alert_type: String(form.get("alert_type") || "").trim() || undefined,
        metric_name: String(form.get("metric_name") || "").trim() || undefined,
        database: {
          engine: String(form.get("db_engine") || "").trim() || undefined,
          instance: String(form.get("db_instance") || "").trim() || undefined,
          database: String(form.get("db_name") || "").trim() || undefined,
        },
        features: parseObject(String(form.get("features") || ""), "特征"),
        labels: rawLabels as Record<string, string>,
      };
      setAccepted(await api.createAlert(payload));
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "告警提交失败");
    } finally {
      setSubmitting(false);
    }
  }

  if (accepted) {
    return (
      <div className="page-stack narrow-page">
        <PageHeader eyebrow="INGRESS ACCEPTED" title="告警已进入排查队列" description="Agent 将依次查询手册、采集证据并校验处理建议。" />
        <section className="accepted-panel">
          <span className="accepted-icon"><CheckCircle2 size={34} /></span>
          <p className="eyebrow">{accepted.deduplicated ? "DUPLICATE EVENT" : "NEW EVENT"}</p>
          <h2>{accepted.deduplicated ? "已识别为重复事件" : "接收成功"}</h2>
          <p>{accepted.deduplicated ? "系统复用了该事件的既有分析记录，不会重复通知管理人员。" : "你现在可以进入详情页，实时观察分析流水。"}</p>
          <div className="accepted-facts">
            <div><span>事件 ID</span><code>{accepted.event_id}</code></div>
            <div><span>初始状态</span><StatusBadge status={accepted.status} /></div>
          </div>
          <div className="accepted-actions">
            <Link className="button primary" to={`/alerts/${accepted.alert_id}`}>跟踪排查进度 <ArrowRight size={16} /></Link>
            <button className="button secondary" type="button" onClick={() => setAccepted(null)}>再创建一条</button>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="page-stack narrow-page">
      <PageHeader
        eyebrow="CANONICAL INGRESS"
        title="发起测试告警"
        description="使用统一告警格式验证从接入、手册检索到 AI 建议的完整链路。"
      />
      <div className="safety-banner"><Beaker size={18} /><div><strong>仅用于分析验证</strong><span>此操作不会连接数据库或执行任何处置命令。</span></div></div>

      <form className="alert-form" onSubmit={submit}>
        <SectionCard eyebrow="01 · SIGNAL" title="告警信号" description="描述告警本身以及可观测到的异常现象。">
          <div className="form-grid two-cols">
            <label className="field span-2"><span>告警标题 <b>*</b></span><input name="title" required placeholder="例如：数据库连接数接近上限" /></label>
            <label className="field"><span>告警原因 <b>*</b></span><input name="reason" required placeholder="例如：connection_exhausted" /></label>
            <label className="field"><span>标准等级 <b>*</b></span><select name="severity" defaultValue="WARNING"><option value="CRITICAL">CRITICAL · 紧急</option><option value="WARNING">WARNING · 警告</option><option value="INFO">INFO · 提示</option></select></label>
            <label className="field span-2"><span>现象描述</span><textarea name="description" rows={4} placeholder="补充当前指标、持续时间和业务影响等信息" /></label>
            <label className="field"><span>外部事件 ID</span><input name="external_id" placeholder="可留空，由后端生成稳定 ID" /></label>
            <label className="field"><span>告警类型</span><input name="alert_type" placeholder="例如：database_capacity" /></label>
          </div>
        </SectionCard>

        <SectionCard eyebrow="02 · TARGET" title="定位上下文" description="帮助 Agent 建立稳定问题指纹并选择对应排查策略。">
          <div className="form-grid two-cols">
            <label className="field"><span>运行环境</span><input name="environment" placeholder="production / staging" /></label>
            <label className="field"><span>服务名称</span><input name="service_name" placeholder="order-service" /></label>
            <label className="field"><span>数据库引擎</span><input name="db_engine" placeholder="postgresql / mysql" /></label>
            <label className="field"><span>实例</span><input name="db_instance" placeholder="db-prod-01" /></label>
            <label className="field"><span>数据库名</span><input name="db_name" placeholder="orders" /></label>
            <label className="field"><span>指标名称</span><input name="metric_name" placeholder="connection_usage_percent" /></label>
          </div>
        </SectionCard>

        <SectionCard eyebrow="03 · FEATURES" title="特征与标签" description="以 JSON 对象提交监控特征；敏感字段会在后端递归脱敏。">
          <div className="json-fields">
            <label className="field"><span><Braces size={15} /> 指标特征 JSON</span><textarea name="features" rows={7} spellCheck={false} placeholder={'{\n  "connection_usage_percent": 95\n}'} /></label>
            <label className="field"><span><Braces size={15} /> 标签 JSON</span><textarea name="labels" rows={7} spellCheck={false} placeholder={'{\n  "team": "database",\n  "region": "cn-east"\n}'} /></label>
          </div>
          <p className="form-hint"><Info size={14} /> 密码、令牌、授权头与连接串等字段不应主动填入；后端仍会在模型调用和落库前执行脱敏。</p>
        </SectionCard>

        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="sticky-submit">
          <span>提交后接口将返回 202，分析会在后台异步执行。</span>
          <button className="button primary large" type="submit" disabled={submitting}>
            {submitting ? <InlineLoading label="正在接收" /> : <><Send size={17} /> 提交并开始分析</>}
          </button>
        </div>
      </form>
    </div>
  );
}
