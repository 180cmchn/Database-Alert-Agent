import {
  Bot,
  Check,
  CircleAlert,
  Eye,
  EyeOff,
  Filter,
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
import { knowledgeSourcesForSave } from "../lib/knowledgeSources";
import type {
  AdminSettings,
  AdminSettingsPatch,
  AIProvider,
  ReasoningEffort,
  Severity,
} from "../types/api";
import { REASONING_EFFORT_OPTIONS } from "../types/api";

const AI_PROVIDERS = new Set<AIProvider>(["openai_compatible", "openai_responses", "fake"]);

function isAIProvider(value: string): value is AIProvider {
  return AI_PROVIDERS.has(value as AIProvider);
}

function numberField(form: FormData, name: string, fallback?: number): number {
  const rawValue = form.get(name);
  if (typeof rawValue !== "string" || !rawValue.trim()) {
    if (fallback !== undefined) return fallback;
    throw new Error("请填写所有数值配置项。");
  }
  const value = Number(rawValue);
  if (!Number.isFinite(value)) {
    throw new Error("数值配置项格式不正确。");
  }
  return value;
}

function effortField(form: FormData, name: string): ReasoningEffort {
  const rawValue = form.get(name);
  if (typeof rawValue !== "string") return "";
  return REASONING_EFFORT_OPTIONS.some((option) => option.value === rawValue)
    ? (rawValue as ReasoningEffort)
    : "";
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
  const [flashdutyPollingEnabled, setFlashdutyPollingEnabled] = useState(false);
  const [alertAnalysisFilterEnabled, setAlertAnalysisFilterEnabled] = useState(false);
  const [alertAnalysisFilterMaxSeverity, setAlertAnalysisFilterMaxSeverity] = useState<Severity>("INFO");
  const [wecomEnabled, setWecomEnabled] = useState(false);
  const [externalKnowledgeSelected, setExternalKnowledgeSelected] = useState(false);

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
      setFlashdutyPollingEnabled(settings.flashduty_polling_enabled);
      setAlertAnalysisFilterEnabled(settings.alert_analysis_filter_enabled);
      setAlertAnalysisFilterMaxSeverity(settings.alert_analysis_filter_max_severity);
      setWecomEnabled(settings.wecom_enabled);
      setExternalKnowledgeSelected(settings.knowledge_sources.includes("external_knowledge"));
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
      const knowledgeSources = knowledgeSourcesForSave(
        settings.knowledge_sources,
        externalKnowledgeSelected,
      );
      if (!isAIProvider(selectedProvider)) {
        throw new Error("请选择受支持的 AI Provider。");
      }
      const patch: AdminSettingsPatch = {
        expected_revision: settings.revision,
        ai_provider: selectedProvider,
        ai_base_url: String(form.get("ai_base_url")).trim(),
        ai_model: String(form.get("ai_model")).trim(),
        ai_react_model: String(form.get("ai_react_model") || "").trim(),
        ai_mcp_model: String(form.get("ai_mcp_model") || "").trim(),
        ai_react_reasoning_effort: effortField(form, "ai_react_reasoning_effort"),
        ai_reasoning_effort: effortField(form, "ai_reasoning_effort"),
        ai_mcp_reasoning_effort: effortField(form, "ai_mcp_reasoning_effort"),
        ai_timeout_seconds: numberField(form, "ai_timeout_seconds"),
        ai_json_mode: form.get("ai_json_mode") === "on",
        ai_fallback_enabled: form.get("ai_fallback_enabled") === "on",
        stream_main_agent_reasoning: form.get("stream_main_agent_reasoning") === "on",
        react_max_rounds: numberField(form, "react_max_rounds"),
        analysis_timeout_seconds: numberField(form, "analysis_timeout_seconds"),
        scheduler_workers: numberField(form, "scheduler_workers"),
        alert_analysis_filter_enabled: alertAnalysisFilterEnabled,
        alert_analysis_filter_max_severity: alertAnalysisFilterMaxSeverity,
        knowledge_sources: knowledgeSources,
        flashduty_polling_enabled: form.get("flashduty_polling_enabled") === "on",
        flashduty_poll_interval_seconds: numberField(
          form,
          "flashduty_poll_interval_seconds",
          settings.flashduty_poll_interval_seconds,
        ),
        flashduty_poll_lookback_seconds: numberField(
          form,
          "flashduty_poll_lookback_seconds",
          settings.flashduty_poll_lookback_seconds,
        ),
      };
      const apiKey = String(form.get("ai_api_key") || "").trim();
      if (apiKey) patch.ai_api_key = apiKey;
      const wecomWebhookUrl = String(form.get("wecom_webhook_url") || "").trim();
      if (wecomWebhookUrl) patch.wecom_webhook_url = wecomWebhookUrl;
      patch.wecom_page_base_url = String(form.get("wecom_page_base_url") || "").trim();
      patch.wecom_enabled = wecomEnabled;
      const knowledgeApiKey = String(form.get("external_knowledge_api_key") || "").trim();
      if (knowledgeApiKey) patch.external_knowledge_api_key = knowledgeApiKey;
      const updated = await api.updateSettings(patch, token);
      setSettings(updated);
      setNotice(updated.changed_fields.length ? `已应用 ${updated.changed_fields.length} 项配置变更` : "配置已校验，当前值无需变更");
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
  const realProviderSelected = selectedProvider !== "fake";
  const unsupportedProviderSelected = !isAIProvider(selectedProvider);
  const extensionKnowledgeSources = settings.knowledge_sources.filter(
    (source) => source !== "external_knowledge",
  );
  const selectedKnowledgeSourceCount = extensionKnowledgeSources.length
    + (externalKnowledgeSelected ? 1 : 0);

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
        <div><RefreshCw size={17} /><div><strong>Worker 刷新策略</strong><small>每批任务开始前读取最新配置</small></div></div>
        <div><ShieldCheck size={17} /><div><strong>秘密值保护</strong><small>仅显示是否已配置</small></div></div>
      </div>

      {!settings.ready && (
        <div className="analysis-error" role="alert">
          <CircleAlert size={18} />
          <div><strong>当前运行配置不可用</strong><span>{settings.issues.join("；")}</span></div>
        </div>
      )}

      <form className="settings-form" key={settings.revision} onSubmit={save}>
        <SectionCard eyebrow="AI PROVIDER" title="模型与接口协议" description="支持 Chat Completions 兼容协议和 OpenAI Responses 协议；留空密钥输入框将保留当前密钥。" action={<span className={`configured-chip ${settings.ai_api_key_configured ? "yes" : "no"}`}>{settings.ai_api_key_configured ? <Check size={13} /> : <CircleAlert size={13} />}{settings.ai_api_key_configured ? "API Key 已配置" : "API Key 未配置"}</span>}>
          <div className="form-grid two-cols">
            <label className="field"><span>AI Provider</span><select name="ai_provider" value={selectedProvider} onChange={(event) => setSelectedProvider(event.target.value)}>{unsupportedProviderSelected && <option value={selectedProvider} disabled>不支持的 Provider（{selectedProvider}）</option>}<option value="openai_compatible">OpenAI Compatible (Chat Completions)</option><option value="openai_responses">OpenAI Responses</option>{(settings.fake_provider_allowed || settings.ai_provider === "fake") && <option value="fake">Fake（仅开发测试）</option>}</select></label>
            <label className="field"><span>Model {realProviderSelected && <b>*</b>}</span><input name="ai_model" defaultValue={settings.ai_model} required={realProviderSelected} placeholder={selectedProvider === "fake" ? "Fake 模式可留空" : "模型标识"} /></label>
            <label className="field span-2"><span>Base URL <b>*</b></span><input name="ai_base_url" type="url" defaultValue={settings.ai_base_url} required placeholder="https://api.openai.com/v1" /></label>
            <label className="field span-2"><span>API Key（只写） {realProviderSelected && !settings.ai_api_key_configured && <b>*</b>}</span><div className="secret-field"><input name="ai_api_key" type={showApiKey ? "text" : "password"} autoComplete="new-password" required={realProviderSelected && !settings.ai_api_key_configured} placeholder={settings.ai_api_key_configured ? "已配置 · 留空保持不变" : "输入新的 API Key"} /><button type="button" onClick={() => setShowApiKey((value) => !value)} aria-label={showApiKey ? "隐藏 API Key" : "显示 API Key"}>{showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
            <label className="field"><span>请求超时（秒）</span><input name="ai_timeout_seconds" type="number" min="1" max="600" step="1" required defaultValue={settings.ai_timeout_seconds} /></label>
          </div>
          <div className="form-grid two-cols">
            <label className="field"><span>ReAct 决策模型（可选）</span><input name="ai_react_model" defaultValue={settings.ai_react_model} placeholder="留空使用上方主模型" /><small>主 Agent 每轮选择工具或结束调查所用的模型，可配置为更轻量的模型以降低时延</small></label>
            <label className="field"><span>ReAct 决策 Reasoning Effort</span><select name="ai_react_reasoning_effort" defaultValue={settings.ai_react_reasoning_effort}>{REASONING_EFFORT_OPTIONS.map((option) => <option key={option.value || "default"} value={option.value}>{option.label}</option>)}</select><small>决策轮思考强度；建议 low，缩短每轮等待</small></label>
            <label className="field"><span>MCP 内循环模型（可选）</span><input name="ai_mcp_model" defaultValue={settings.ai_mcp_model} placeholder="留空使用上方主模型" /><small>MCP 工具（慢日志、指标等）参数生成内循环使用的模型</small></label>
            <label className="field"><span>MCP 内循环 Reasoning Effort</span><select name="ai_mcp_reasoning_effort" defaultValue={settings.ai_mcp_reasoning_effort}>{REASONING_EFFORT_OPTIONS.map((option) => <option key={option.value || "default"} value={option.value}>{option.label}</option>)}</select><small>工具调用参数生成的思考强度；建议 low～medium</small></label>
            <label className="field span-2"><span>终局分析 Reasoning Effort</span><select name="ai_reasoning_effort" defaultValue={settings.ai_reasoning_effort}>{REASONING_EFFORT_OPTIONS.map((option) => <option key={option.value || "default"} value={option.value}>{option.label}</option>)}</select><small>最终根因与恢复建议生成（主模型）的思考强度；建议 high 以上保证结论质量</small></label>
          </div>
          <label className="switch-row"><span><Bot size={17} /><span><strong>强制 JSON 输出模式</strong><small>要求模型返回可由 Pydantic 校验的结构化结果</small></span></span><input name="ai_json_mode" type="checkbox" defaultChecked={settings.ai_json_mode} /><i /></label>
        </SectionCard>

        <SectionCard eyebrow="ALERT SOURCE" title="FlashDuty API 轮询" description="仅通过 FlashDuty Open API 拉取告警；APP Key 和协作空间范围由部署环境的 .env 管理，轮询开关、间隔和回看范围可在此页运行时调整。" action={<span className={`configured-chip ${settings.flashduty_enabled && settings.flashduty_app_key_configured && flashdutyPollingEnabled ? "yes" : "no"}`}><ShieldCheck size={13} />{!settings.flashduty_enabled ? "数据源未启用" : !settings.flashduty_app_key_configured ? "APP Key 未配置" : flashdutyPollingEnabled ? "自动轮询中" : "自动轮询已关闭"}</span>}>
          <div className="switch-stack">
            <label className="switch-row"><span><RefreshCw size={17} /><span><strong>启用轮询</strong><small>开启后自动按间隔拉取协作空间告警</small></span></span><input name="flashduty_polling_enabled" type="checkbox" checked={flashdutyPollingEnabled} onChange={(event) => setFlashdutyPollingEnabled(event.target.checked)} disabled={!settings.flashduty_enabled} /><i /></label>
          </div>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field"><span>轮询间隔（秒）</span><input name="flashduty_poll_interval_seconds" type="number" min="300" max="86400" required defaultValue={settings.flashduty_poll_interval_seconds} disabled={!flashdutyPollingEnabled} /></label>
            <label className="field"><span>回看时间范围（秒）</span><input name="flashduty_poll_lookback_seconds" type="number" min="300" max="2678400" required defaultValue={settings.flashduty_poll_lookback_seconds} disabled={!flashdutyPollingEnabled} /></label>
          </div>
          <div className="form-grid two-cols">
            <label className="field span-2"><span>官方 API Endpoint</span><input value={settings.flashduty_base_url} readOnly /></label>
            <label className="field"><span>协作空间范围</span><input value={settings.flashduty_poll_channel_ids.length ? settings.flashduty_poll_channel_ids.join(", ") : "未配置（服务不会拉取）"} readOnly /></label>
            <label className="field"><span>集成范围</span><input value={settings.flashduty_poll_integration_ids.length ? settings.flashduty_poll_integration_ids.join(", ") : "全部集成"} readOnly /></label>
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="ALERT ADMISSION"
          title="告警分析准入"
          description="按归一化告警等级决定新告警是否进入自动分析；被过滤的告警仍会入库。"
          action={
            <span className={`configured-chip ${alertAnalysisFilterEnabled ? "yes" : "no"}`}>
              <Filter size={13} />
              {alertAnalysisFilterEnabled ? "等级过滤已开启" : "等级过滤未开启"}
            </span>
          }
        >
          <div className="switch-stack">
            <label className="switch-row">
              <span>
                <Filter size={17} />
                <span>
                  <strong>启用告警等级过滤</strong>
                  <small>开启后，指定等级及以下的新告警只入库，不分析且不发送企微通知</small>
                </span>
              </span>
              <input
                name="alert_analysis_filter_enabled"
                type="checkbox"
                checked={alertAnalysisFilterEnabled}
                onChange={(event) => setAlertAnalysisFilterEnabled(event.target.checked)}
              />
              <i />
            </label>
          </div>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field">
              <span>仅入库等级上限</span>
              <select
                name="alert_analysis_filter_max_severity"
                value={alertAnalysisFilterMaxSeverity}
                onChange={(event) => setAlertAnalysisFilterMaxSeverity(event.target.value as Severity)}
                disabled={!alertAnalysisFilterEnabled}
              >
                <option value="INFO">INFO（仅 INFO 只入库）</option>
                <option value="WARNING">WARNING（INFO、WARNING 只入库）</option>
                <option value="CRITICAL">CRITICAL（全部等级只入库）</option>
              </select>
              <small>只分析严格高于该等级的告警；关闭开关时仍保留此选择。</small>
            </label>
            <div className="field">
              <span>生效范围</span>
              <input value="之后首次接入的新告警" readOnly />
              <small>不会取消已排队或分析中的任务，也不会自动补跑历史仅入库告警。</small>
            </div>
          </div>
        </SectionCard>

        <SectionCard eyebrow="KNOWLEDGE SOURCE" title="Agent 参考依据" description="外部知识库是可选的参考来源；不可用、未命中或未选择都不会阻止实时证据分析。" action={<span className={`configured-chip ${selectedKnowledgeSourceCount > 0 ? "yes" : "no"}`}><ShieldCheck size={13} />{selectedKnowledgeSourceCount > 0 ? `已选择 ${selectedKnowledgeSourceCount} 个知识来源` : "未选择知识来源"}</span>}>
          <div className="switch-stack">
            <label className="switch-row"><span><Sparkles size={17} /><span><strong>外部知识库</strong><small>选中后连接并检索 KnowledgePack 内容；取消后仅使用告警、实时证据和通用推理</small></span></span><input name="knowledge_external" type="checkbox" checked={externalKnowledgeSelected} onChange={(event) => setExternalKnowledgeSelected(event.target.checked)} /><i /></label>
          </div>
          <div className="form-grid two-cols">
            <label className="field"><span>外部知识最低相关度（部署配置）</span><input value={settings.external_knowledge_min_relevance.toFixed(2)} readOnly /></label>
            <label className="field span-2"><span>外部知识库 Base URL（部署配置，只读）</span><input value={settings.external_knowledge_base_url} readOnly /></label>
            <label className="field span-2"><span>Knowledge API Key（只写，URL 变更后必须重新输入）</span><div className="secret-field"><input name="external_knowledge_api_key" type={showKnowledgeApiKey ? "text" : "password"} autoComplete="new-password" disabled={!externalKnowledgeSelected} placeholder={settings.external_knowledge_api_key_configured ? "已绑定当前 URL · 留空保持不变" : "认证可选；如服务启用认证请重新输入"} /><button type="button" onClick={() => setShowKnowledgeApiKey((value) => !value)} aria-label={showKnowledgeApiKey ? "隐藏 Knowledge API Key" : "显示 Knowledge API Key"}>{showKnowledgeApiKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
            {extensionKnowledgeSources.length > 0 && <label className="field span-2"><span>其他已配置知识来源（保留）</span><input value={extensionKnowledgeSources.join(", ")} readOnly /></label>}
          </div>
        </SectionCard>

        <SectionCard eyebrow="REACT" title="主 Agent 调查与校验" description="主 Agent 逐轮选择一个相关工具或结束调查，再统一分析根因；输出只经过程序侧契约校验，不会交给第二个模型裁决。">
          <div className="switch-stack">
            <label className="switch-row"><span><CircleAlert size={17} /><span><strong>启用保守降级建议</strong><small>模型超时或结构不合规时继续完成流程，并以结论不充分结束</small></span></span><input name="ai_fallback_enabled" type="checkbox" defaultChecked={settings.ai_fallback_enabled} /><i /></label>
            <label className="switch-row"><span><Sparkles size={17} /><span><strong>实时展示主 Agent 思考过程</strong><small>开启后逐增量保存并刷新 reasoning；关闭后每次模型调用结束只记录一次完整 reasoning。修改仅影响之后创建的分析运行</small></span></span><input name="stream_main_agent_reasoning" type="checkbox" defaultChecked={settings.stream_main_agent_reasoning} /><i /></label>
          </div>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field"><span>并行分析告警数</span><input name="scheduler_workers" type="number" min="1" max="16" required defaultValue={settings.scheduler_workers} /></label>
            <label className="field"><span>ReAct 最大轮次</span><input name="react_max_rounds" type="number" min="1" max="100" required defaultValue={settings.react_max_rounds} /></label>
            <label className="field"><span>整次分析超时（秒）</span><input name="analysis_timeout_seconds" type="number" min="30" max="86400" required defaultValue={settings.analysis_timeout_seconds} /></label>
          </div>
        </SectionCard>

        <SectionCard
          eyebrow="WECOM OUTPUT"
          title="企微机器人"
          description="发送告警信息卡片；根因与恢复建议在企微内嵌专用页面展示。"
          action={<span className={`configured-chip ${settings.wecom_webhook_url_configured ? "yes" : "no"}`}><Webhook size={13} />{settings.wecom_webhook_url_configured ? "企业微信地址已配置" : "企业微信地址未配置"}</span>}
        >
          <div className="switch-stack">
            <label className="switch-row"><span><Webhook size={17} /><span><strong>启用企微机器人通知</strong><small>关闭后即使已配置 Webhook URL 也不会发送通知</small></span></span><input name="wecom_enabled" type="checkbox" checked={wecomEnabled} onChange={(event) => setWecomEnabled(event.target.checked)} /><i /></label>
          </div>
          <label className="field"><span>企业微信群机器人 Webhook URL（只写） {wecomEnabled && !settings.wecom_webhook_url_configured && <b>*</b>}</span><div className="secret-field"><input name="wecom_webhook_url" type={showWecomUrl ? "text" : "password"} autoComplete="new-password" required={wecomEnabled && !settings.wecom_webhook_url_configured} placeholder={settings.wecom_webhook_url_configured ? "已配置 · 留空保持不变" : "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."} /><button type="button" onClick={() => setShowWecomUrl((value) => !value)} aria-label={showWecomUrl ? "隐藏企业微信地址" : "显示企业微信地址"}>{showWecomUrl ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
          <div className="form-grid two-cols settings-inline-fields">
            <label className="field span-2">
              <span>企微内嵌页面 Base URL {wecomEnabled && <b>*</b>}</span>
              <input
                name="wecom_page_base_url"
                type="url"
                required={wecomEnabled}
                defaultValue={settings.wecom_page_base_url}
                placeholder="https://alerts.intra.example.com"
              />
              <small>卡片前两项会在企微客户端内打开此地址下的专用根因/恢复页面。</small>
            </label>
          </div>
        </SectionCard>

        {error && <div className="form-error" role="alert">{error}</div>}
        {notice && <div className="form-success"><Check size={16} /> {notice}</div>}
        <div className="sticky-submit settings-submit"><span>保存后，新配置会在 Worker 处理下一条任务前生效。</span><button className="button primary large" type="submit" disabled={saving}>{saving ? <InlineLoading label="应用配置" /> : <><Save size={17} /> 保存并应用</>}</button></div>
      </form>
    </div>
  );
}
