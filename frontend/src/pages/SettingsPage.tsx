import {
  Bot,
  Check,
  CircleAlert,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  Save,
  ShieldCheck,
  Sparkles,
  Webhook,
} from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  AdminUnlock,
  ErrorState,
  InlineLoading,
  LoadingState,
  PageHeader,
  SectionCard,
} from "../components/ui";
import { useAdminAuth } from "../context/AdminAuthContext";
import { api, ApiError } from "../lib/api";
import type { AdminSettings, AdminSettingsPatch } from "../types/api";

function numberField(form: FormData, name: string): number {
  const rawValue = form.get(name);
  if (typeof rawValue !== "string" || !rawValue.trim()) {
    throw new Error("请填写所有数值配置项。");
  }
  const value = Number(rawValue);
  if (!Number.isFinite(value)) {
    throw new Error("数值配置项格式不正确。");
  }
  return value;
}

export function SettingsPage() {
  const { token, unlocked, lock } = useAdminAuth();
  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [authError, setAuthError] = useState(false);
  const [notice, setNotice] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [showWecomUrl, setShowWecomUrl] = useState(false);
  const [showKnowledgeApiKey, setShowKnowledgeApiKey] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState("openai_compatible");

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      setSettings(await api.getSettings(token));
      setError("");
      setAuthError(false);
    } catch (requestError) {
      setError(
        requestError instanceof ApiError && requestError.status === 503
          ? "后端尚未配置 ADMIN_API_TOKEN，请先在部署环境中设置并重启 API。"
          : requestError instanceof Error ? requestError.message : "设置加载失败",
      );
      setAuthError(requestError instanceof ApiError && [401, 403].includes(requestError.status));
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { if (unlocked) void load(); }, [load, unlocked]);
  useEffect(() => {
    if (settings) {
      setSelectedProvider(settings.ai_provider);
    }
  }, [settings]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!settings) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const knowledgeSources: string[] = [];
      if (form.get("knowledge_local_pdf") === "on") knowledgeSources.push("local_pdf");
      if (form.get("knowledge_external") === "on") knowledgeSources.push("external_knowledge");
      const patch: AdminSettingsPatch = {
        expected_revision: settings.revision,
        ai_provider: String(form.get("ai_provider")),
        ai_base_url: String(form.get("ai_base_url")).trim(),
        ai_model: String(form.get("ai_model")).trim(),
        ai_timeout_seconds: numberField(form, "ai_timeout_seconds"),
        ai_max_retries: numberField(form, "ai_max_retries"),
        ai_json_mode: form.get("ai_json_mode") === "on",
        ai_fallback_enabled: form.get("ai_fallback_enabled") === "on",
        react_enabled: form.get("react_enabled") === "on",
        react_max_dynamic_turns: numberField(form, "react_max_dynamic_turns"),
        validation_enabled: form.get("validation_enabled") === "on",
        shadow_enabled: form.get("shadow_enabled") === "on",
        runbook_limit: numberField(form, "runbook_limit"),
        knowledge_sources: knowledgeSources,
        flashduty_polling_enabled: form.get("flashduty_polling_enabled") === "on",
        flashduty_poll_interval_seconds: numberField(form, "flashduty_poll_interval_seconds"),
        flashduty_poll_lookback_seconds: numberField(form, "flashduty_poll_lookback_seconds"),
      };
      const apiKey = String(form.get("ai_api_key") || "").trim();
      if (apiKey) patch.ai_api_key = apiKey;
      const wecomWebhookUrl = String(form.get("wecom_webhook_url") || "").trim();
      if (wecomWebhookUrl) patch.wecom_webhook_url = wecomWebhookUrl;
      patch.external_knowledge_enabled = form.get("external_knowledge_enabled") === "on";
      patch.external_knowledge_base_url = String(form.get("external_knowledge_base_url") || "").trim();
      const knowledgeApiKey = String(form.get("external_knowledge_api_key") || "").trim();
      if (knowledgeApiKey) patch.external_knowledge_api_key = knowledgeApiKey;
      const updated = await api.updateSettings(patch, token);
      setSettings(updated);
      setNotice(updated.changed_fields.length ? `已应用 ${updated.changed_fields.length} 项配置变更` : "配置已校验，当前值无需变更");
      formElement.reset();
    } catch (saveError) {
      if (saveError instanceof ApiError && saveError.status === 409) {
        await load();
        setError("配置已被其他管理员修改，已加载最新版本；请核对后重新保存。");
      } else {
        setError(saveError instanceof Error ? saveError.message : "设置保存失败");
      }
      setAuthError(saveError instanceof ApiError && [401, 403].includes(saveError.status));
    } finally {
      setSaving(false);
    }
  }

  if (!unlocked) {
    return <AdminUnlock title="解锁 Agent 设置" description="模型凭据与企微机器人地址属于敏感运行配置，只有管理员会话可以读取安全摘要或提交新值。" />;
  }

  if (loading && !settings) return <LoadingState label="正在读取 Agent 安全配置…" />;
  if (authError) return <ErrorState message="管理员令牌无效或已过期，请重新解锁。" onRetry={lock} />;
  if (!settings) return <ErrorState message={error || "设置数据不可用"} onRetry={() => void load()} />;

  return (
    <div className="page-stack settings-page">
      <PageHeader
        eyebrow="RUNTIME CONTROL"
        title="Agent 设置"
        description="更新模型、分析护栏与企微机器人配置；密钥只写不读，响应永不返回秘密值。"
        actions={<><button type="button" className="button secondary" onClick={lock}><KeyRound size={16} /> 锁定会话</button><button type="button" className="button secondary" onClick={() => void load()}><RefreshCw size={16} /> 重新读取</button></>}
      />

      <div className="settings-status-strip">
        <div><span className={settings.ready ? "applied-dot" : "applied-dot not-ready"}>{settings.ready ? <Check size={14} /> : <CircleAlert size={14} />}</span><div><strong>{settings.ready ? "配置已应用且可用" : "配置尚未就绪"}</strong><small>{settings.app_env} · 修订版本 {settings.revision}</small></div></div>
        <div><RefreshCw size={17} /><div><strong>Worker 刷新策略</strong><small>每个任务开始前读取最新配置</small></div></div>
        <div><ShieldCheck size={17} /><div><strong>秘密值保护</strong><small>仅显示是否已配置</small></div></div>
      </div>

      {!settings.ready && (
        <div className="analysis-error" role="alert">
          <CircleAlert size={18} />
          <div><strong>当前运行配置不可用</strong><span>{settings.issues.join("；")}</span></div>
        </div>
      )}

      <form className="settings-form" key={settings.revision} onSubmit={save}>
        <SectionCard eyebrow="AI PROVIDER" title="模型与兼容接口" description="支持 OpenAI 兼容 API；留空密钥输入框将保留当前密钥。" action={<span className={`configured-chip ${settings.ai_api_key_configured ? "yes" : "no"}`}>{settings.ai_api_key_configured ? <Check size={13} /> : <CircleAlert size={13} />}{settings.ai_api_key_configured ? "API Key 已配置" : "API Key 未配置"}</span>}>
          <div className="form-grid two-cols">
            <label className="field"><span>AI Provider</span><select name="ai_provider" value={selectedProvider} onChange={(event) => setSelectedProvider(event.target.value)}><option value="openai_compatible">OpenAI Compatible</option>{(settings.fake_provider_allowed || settings.ai_provider === "fake") && <option value="fake">Fake（仅开发测试）</option>}</select></label>
            <label className="field"><span>Model {selectedProvider === "openai_compatible" && <b>*</b>}</span><input name="ai_model" defaultValue={settings.ai_model} required={selectedProvider === "openai_compatible"} placeholder={selectedProvider === "fake" ? "Fake 模式可留空" : "模型标识"} /></label>
            <label className="field span-2"><span>Base URL <b>*</b></span><input name="ai_base_url" type="url" defaultValue={settings.ai_base_url} required placeholder="https://api.openai.com/v1" /></label>
            <label className="field span-2"><span>API Key（只写） {selectedProvider === "openai_compatible" && !settings.ai_api_key_configured && <b>*</b>}</span><div className="secret-field"><input name="ai_api_key" type={showApiKey ? "text" : "password"} autoComplete="new-password" required={selectedProvider === "openai_compatible" && !settings.ai_api_key_configured} placeholder={settings.ai_api_key_configured ? "已配置 · 留空保持不变" : "输入新的 API Key"} /><button type="button" onClick={() => setShowApiKey((value) => !value)} aria-label={showApiKey ? "隐藏 API Key" : "显示 API Key"}>{showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
            <label className="field"><span>请求超时（秒）</span><input name="ai_timeout_seconds" type="number" min="1" max="600" step="1" required defaultValue={settings.ai_timeout_seconds} /></label>
            <label className="field"><span>失败重试次数</span><input name="ai_max_retries" type="number" min="0" max="20" required defaultValue={settings.ai_max_retries} /></label>
          </div>
          <label className="switch-row"><span><Bot size={17} /><span><strong>强制 JSON 输出模式</strong><small>要求模型返回可由 Pydantic 校验的结构化结果</small></span></span><input name="ai_json_mode" type="checkbox" defaultChecked={settings.ai_json_mode} /><i /></label>
        </SectionCard>

        <SectionCard eyebrow="ALERT SOURCE" title="FlashDuty API 轮询" description="仅通过 FlashDuty Open API 拉取告警；APP Key 和协作空间范围由部署环境的 .env 管理，轮询开关、间隔和回看范围可在此页运行时调整。" action={<span className={`configured-chip ${settings.flashduty_enabled && settings.flashduty_app_key_configured ? "yes" : "no"}`}><ShieldCheck size={13} />{settings.flashduty_enabled ? (settings.flashduty_app_key_configured ? "只读轮询已启用" : "APP Key 未配置") : "未启用"}</span>}>
          <div className="switch-stack">
            <label className="switch-row"><span><RefreshCw size={17} /><span><strong>启用轮询</strong><small>开启后自动按间隔拉取协作空间告警</small></span></span><input name="flashduty_polling_enabled" type="checkbox" defaultChecked={settings.flashduty_polling_enabled} disabled={!settings.flashduty_enabled} /><i /></label>
          </div>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field"><span>轮询间隔（秒）</span><input name="flashduty_poll_interval_seconds" type="number" min="300" max="86400" required defaultValue={settings.flashduty_poll_interval_seconds} disabled={!settings.flashduty_polling_enabled} /></label>
            <label className="field"><span>回看时间范围（秒）</span><input name="flashduty_poll_lookback_seconds" type="number" min="300" max="2678400" required defaultValue={settings.flashduty_poll_lookback_seconds} disabled={!settings.flashduty_polling_enabled} /></label>
          </div>
          <div className="form-grid two-cols">
            <label className="field span-2"><span>官方 API Endpoint</span><input value={settings.flashduty_base_url} readOnly /></label>
            <label className="field"><span>协作空间范围</span><input value={settings.flashduty_poll_channel_ids.length ? settings.flashduty_poll_channel_ids.join(", ") : "未配置（服务不会拉取）"} readOnly /></label>
            <label className="field"><span>集成范围</span><input value={settings.flashduty_poll_integration_ids.length ? settings.flashduty_poll_integration_ids.join(", ") : "全部集成"} readOnly /></label>
          </div>
        </SectionCard>

        <SectionCard eyebrow="KNOWLEDGE SOURCES" title="知识来源" description="选择告警分析时使用的知识来源；历史确认案例始终启用，不受此设置控制。" action={<span className={`configured-chip ${settings.external_knowledge_api_key_configured ? "yes" : "no"}`}><ShieldCheck size={13} />{settings.external_knowledge_api_key_configured ? "Knowledge API Key 已配置" : "Knowledge API Key 未配置"}</span>}>
          <div className="switch-stack">
            <label className="switch-row"><span><Sparkles size={17} /><span><strong>本地 PDF 手册</strong><small>从本地 runbooks/pdfs 目录检索已审批的 PDF 处置手册</small></span></span><input name="knowledge_local_pdf" type="checkbox" defaultChecked={settings.knowledge_sources.includes("local_pdf")} /><i /></label>
            <label className="switch-row"><span><ShieldCheck size={17} /><span><strong>启用外部知识库 API</strong><small>开启后调查图谱将查询 KnowledgePack 服务获取补充知识候选（结果视为 draft 建议数据）</small></span></span><input name="external_knowledge_enabled" type="checkbox" defaultChecked={settings.external_knowledge_enabled} /><i /></label>
            <label className="switch-row"><span><Eye size={17} /><span><strong>选择外部知识库作为来源</strong><small>勾选后在知识来源中加入 external_knowledge；本地 PDF 手册始终独立可选</small></span></span><input name="knowledge_external" type="checkbox" defaultChecked={settings.knowledge_sources.includes("external_knowledge")} disabled={!settings.external_knowledge_enabled} /><i /></label>
          </div>
          <div className="form-grid two-cols">
            <label className="field span-2"><span>外部知识库 Base URL <b>*</b></span><input name="external_knowledge_base_url" type="url" defaultValue={settings.external_knowledge_base_url} required={settings.external_knowledge_enabled} disabled={!settings.external_knowledge_enabled} placeholder="http://localhost:8001" /></label>
            <label className="field span-2"><span>Knowledge API Key（只写，默认留空）</span><div className="secret-field"><input name="external_knowledge_api_key" type={showKnowledgeApiKey ? "text" : "password"} autoComplete="new-password" disabled={!settings.external_knowledge_enabled} placeholder={settings.external_knowledge_api_key_configured ? "已配置 · 留空保持不变" : "有需要时填入，默认留空"} /><button type="button" onClick={() => setShowKnowledgeApiKey((value) => !value)} aria-label={showKnowledgeApiKey ? "隐藏 Knowledge API Key" : "显示 Knowledge API Key"}>{showKnowledgeApiKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
          </div>
        </SectionCard>

        <SectionCard eyebrow="REASONING GUARDRAILS" title="推理与校验护栏" description="动态工具规划默认关闭；只有接入真实工具适配器后再开启。">
          <div className="switch-stack">
            <label className="switch-row"><span><Sparkles size={17} /><span><strong>启用有界 ReAct</strong><small>允许模型在已注册工具内追加有限次数的证据采集</small></span></span><input name="react_enabled" type="checkbox" defaultChecked={settings.react_enabled} /><i /></label>
            <label className="switch-row"><span><ShieldCheck size={17} /><span><strong>启用独立结论校验</strong><small>建议输出前执行规则与独立模型的双重校验</small></span></span><input name="validation_enabled" type="checkbox" defaultChecked={settings.validation_enabled} /><i /></label>
            <label className="switch-row"><span><CircleAlert size={17} /><span><strong>启用保守降级建议</strong><small>模型超时或结构不合规时继续完成流程，但强制进入人工复核</small></span></span><input name="ai_fallback_enabled" type="checkbox" defaultChecked={settings.ai_fallback_enabled} /><i /></label>
            <label className="switch-row"><span><Eye size={17} /><span><strong>启用影子运行</strong><small>只生成候选分析并强制进入人工复核，不作为已完成生产结论</small></span></span><input name="shadow_enabled" type="checkbox" defaultChecked={settings.shadow_enabled} /><i /></label>
          </div>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field"><span>最大动态工具轮次</span><input name="react_max_dynamic_turns" type="number" min="0" max="10" required defaultValue={settings.react_max_dynamic_turns} /></label>
            <label className="field"><span>单次手册召回上限</span><input name="runbook_limit" type="number" min="1" max="20" required defaultValue={settings.runbook_limit} /></label>
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="WECOM OUTPUT"
          title="企微机器人"
          description="CRITICAL、WARNING、INFO 的最终 AI 分析结果都会发送到此机器人；本服务不跟踪送达、确认或升级。"
          action={<span className={`configured-chip ${settings.wecom_webhook_url_configured ? "yes" : "no"}`}><Webhook size={13} />{settings.wecom_webhook_url_configured ? "企业微信地址已配置" : "企业微信地址未配置"}</span>}
        >
          <label className="field"><span>企业微信群机器人 Webhook URL（只写） {!settings.wecom_webhook_url_configured && settings.app_env === "production" && <b>*</b>}</span><div className="secret-field"><input name="wecom_webhook_url" type={showWecomUrl ? "text" : "password"} autoComplete="new-password" required={!settings.wecom_webhook_url_configured && settings.app_env === "production"} placeholder={settings.wecom_webhook_url_configured ? "已配置 · 留空保持不变" : "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."} /><button type="button" onClick={() => setShowWecomUrl((value) => !value)} aria-label={showWecomUrl ? "隐藏企业微信地址" : "显示企业微信地址"}>{showWecomUrl ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
        </SectionCard>

        {error && <div className="form-error" role="alert">{error}</div>}
        {notice && <div className="form-success"><Check size={16} /> {notice}</div>}
        <div className="sticky-submit settings-submit"><span>保存后，新配置会在 Worker 处理下一条任务前生效。</span><button className="button primary large" type="submit" disabled={saving}>{saving ? <InlineLoading label="应用配置" /> : <><Save size={17} /> 保存并应用</>}</button></div>
      </form>
    </div>
  );
}
