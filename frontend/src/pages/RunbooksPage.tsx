import {
  BookOpenCheck,
  CirclePlus,
  Clock3,
  FilePenLine,
  KeyRound,
  Save,
  Search,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  AdminUnlock,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  InlineLoading,
  LoadingState,
  PageHeader,
  SeverityBadge,
} from "../components/ui";
import { useAdminAuth } from "../context/AdminAuthContext";
import { api, ApiError } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { RunbookCreateInput, RunbookRecord, RunbookUpdateInput, Severity } from "../types/api";

interface RunbookDraft {
  id: string;
  title: string;
  section: string;
  reasons: string;
  keywords: string;
  severities: Severity[];
  labels: string;
  sourceUrl: string;
  contentSelector: string;
  metadata: string;
  content: string;
  version: number;
}

const blankDraft: RunbookDraft = {
  id: "",
  title: "",
  section: "main",
  reasons: "",
  keywords: "",
  severities: ["HIGH", "CRITICAL"],
  labels: "{}",
  sourceUrl: "",
  contentSelector: "",
  metadata: "{}",
  content: "权威正文来自 source_url；本地内容仅为索引管理备注。",
  version: 0,
};

function toDraft(record: RunbookRecord): RunbookDraft {
  const { source_url, content_selector, ...otherMetadata } = record.metadata;
  return {
    id: record.id,
    title: record.title,
    section: record.section,
    reasons: record.reasons.join(", "),
    keywords: record.keywords.join(", "),
    severities: record.severities,
    labels: JSON.stringify(record.labels, null, 2),
    sourceUrl: typeof source_url === "string" ? source_url : "",
    contentSelector: typeof content_selector === "string" ? content_selector : "",
    metadata: JSON.stringify(otherMetadata, null, 2),
    content: record.content,
    version: record.version,
  };
}

function parseObject(value: string, name: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value || "{}");
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`${name}必须是有效的 JSON 对象`);
  }
}

export function RunbooksPage() {
  const { token, unlocked, lock } = useAdminAuth();
  const [runbooks, setRunbooks] = useState<RunbookRecord[]>([]);
  const [draft, setDraft] = useState<RunbookDraft>(blankDraft);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [authError, setAuthError] = useState(false);
  const [adminUnavailable, setAdminUnavailable] = useState(false);
  const [notice, setNotice] = useState("");
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const records = await api.getRunbooks(token);
      setRunbooks(records);
      setError("");
      setAuthError(false);
      setAdminUnavailable(false);
      setSelectedId((current) => {
        const nextId = current && records.some((item) => item.id === current) ? current : records[0]?.id || null;
        const record = records.find((item) => item.id === nextId);
        if (record) setDraft(toDraft(record));
        else setDraft(blankDraft);
        return nextId;
      });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "手册列表加载失败");
      setAuthError(requestError instanceof ApiError && [401, 403].includes(requestError.status));
      setAdminUnavailable(requestError instanceof ApiError && requestError.status === 503);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { if (unlocked) void load(); }, [load, unlocked]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return runbooks;
    return runbooks.filter((item) =>
      [item.id, item.title, item.section, ...item.reasons, ...item.keywords]
        .some((value) => value.toLowerCase().includes(term)),
    );
  }, [runbooks, search]);

  function select(record: RunbookRecord) {
    setSelectedId(record.id);
    setDraft(toDraft(record));
    setError("");
    setNotice("");
  }

  function createNew() {
    setSelectedId(null);
    setDraft(blankDraft);
    setError("");
    setNotice("");
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const labels = parseObject(draft.labels, "标签");
      if (Object.values(labels).some((value) => typeof value !== "string")) {
        throw new Error("标签 JSON 的值必须全部是字符串");
      }
      const base = {
        title: draft.title.trim(),
        section: draft.section.trim() || "main",
        reasons: draft.reasons.split(",").map((item) => item.trim()).filter(Boolean),
        keywords: draft.keywords.split(",").map((item) => item.trim()).filter(Boolean),
        severities: draft.severities,
        labels: labels as Record<string, string>,
        content: draft.content,
        metadata: {
          ...parseObject(draft.metadata, "扩展元数据"),
          source_url: draft.sourceUrl.trim(),
          ...(draft.contentSelector.trim() ? { content_selector: draft.contentSelector.trim() } : {}),
        },
      };
      let saved: RunbookRecord;
      if (selectedId) {
        const payload: RunbookUpdateInput = { ...base, expected_version: draft.version };
        saved = await api.updateRunbook(selectedId, payload, token);
        setRunbooks((items) => items.map((item) => item.id === selectedId ? saved : item));
        setNotice(`手册已更新至 v${saved.version}`);
      } else {
        const payload: RunbookCreateInput = { id: draft.id.trim(), ...base };
        saved = await api.createRunbook(payload, token);
        setRunbooks((items) => [saved, ...items]);
        setSelectedId(saved.id);
        setNotice("手册已创建并可用于后续告警匹配");
      }
      setDraft(toDraft(saved));
    } catch (saveError) {
      if (saveError instanceof ApiError && saveError.status === 409) {
        await load();
        setError("这份手册已被其他管理员更新，已加载最新版本；请核对后重新编辑。");
      } else {
        setError(saveError instanceof Error ? saveError.message : "手册保存失败");
      }
      setAuthError(saveError instanceof ApiError && [401, 403].includes(saveError.status));
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (!selectedId) return;
    setSaving(true);
    try {
      await api.deleteRunbook(selectedId, token);
      const remaining = runbooks.filter((item) => item.id !== selectedId);
      setRunbooks(remaining);
      const next = remaining[0];
      setSelectedId(next?.id || null);
      setDraft(next ? toDraft(next) : blankDraft);
      setDeleteOpen(false);
      setNotice("手册已删除");
      setError("");
    } catch (removeError) {
      setError(removeError instanceof Error ? removeError.message : "手册删除失败");
      setAuthError(removeError instanceof ApiError && [401, 403].includes(removeError.status));
    } finally {
      setSaving(false);
    }
  }

  if (!unlocked) {
    return <AdminUnlock title="解锁处置手册" description="手册会直接约束 Agent 的处理步骤，因此新增、修改与删除操作需要管理员令牌。" />;
  }

  if (adminUnavailable) {
    return (
      <ErrorState
        message="后端尚未配置 ADMIN_API_TOKEN。请先在部署环境中设置管理员令牌并重启 API。"
        onRetry={() => void load()}
      />
    );
  }

  return (
    <div className="page-stack runbooks-page">
      <PageHeader
        eyebrow="RUNBOOK LIBRARY"
        title="处置手册"
        description="管理网页手册地址、匹配条件和正文提取范围；处置依据始终来自实际网页。"
        actions={<><button type="button" className="button secondary" onClick={lock}><KeyRound size={16} /> 锁定会话</button><button type="button" className="button primary" onClick={createNew}><CirclePlus size={17} /> 新建手册</button></>}
      />

      {authError ? (
        <ErrorState message="管理员令牌无效或已过期，请锁定会话后重新输入。" onRetry={lock} />
      ) : (
        <div className="runbook-workspace">
          <aside className="runbook-list-panel">
            <div className="runbook-list-head">
              <div><strong>手册目录</strong><span>{runbooks.length} 份</span></div>
              <label className="mini-search"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="筛选手册" aria-label="筛选手册" /></label>
            </div>
            {loading ? <LoadingState label="读取手册目录…" /> : filtered.length ? (
              <div className="runbook-list">
                {filtered.map((runbook) => (
                  <button type="button" key={runbook.id} className={selectedId === runbook.id ? "active" : ""} onClick={() => select(runbook)}>
                    <span className="runbook-list-icon"><BookOpenCheck size={18} /></span>
                    <span><strong>{runbook.title}</strong><small>{runbook.id} · {runbook.section}</small><em>v{runbook.version} · {formatDateTime(runbook.updated_at)}</em></span>
                  </button>
                ))}
              </div>
            ) : <EmptyState kind="runbook" title={search ? "没有匹配手册" : "手册目录为空"} description={search ? "尝试更换关键词。" : "新建首份告警处理手册，让 Agent 有明确的首要依据。"} />}
          </aside>

          <section className="runbook-editor-panel">
            <div className="editor-heading">
              <div><span className="editor-icon"><FilePenLine size={20} /></span><div><p>{selectedId ? `EDITING · v${draft.version}` : "NEW RUNBOOK"}</p><h2>{selectedId ? draft.title || draft.id : "创建处置手册"}</h2></div></div>
              {selectedId && <button className="icon-danger-button" type="button" onClick={() => setDeleteOpen(true)}><Trash2 size={16} /> 删除</button>}
            </div>
            <form className="runbook-form" onSubmit={save}>
              <div className="form-grid two-cols">
                <label className="field"><span>手册 ID <b>*</b></span><input value={draft.id} onChange={(event) => setDraft({ ...draft, id: event.target.value })} required disabled={Boolean(selectedId)} placeholder="connection-exhausted" /></label>
                <label className="field"><span>章节 <b>*</b></span><input value={draft.section} onChange={(event) => setDraft({ ...draft, section: event.target.value })} required placeholder="initial-triage" /></label>
                <label className="field span-2"><span>标题 <b>*</b></span><input value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} required placeholder="数据库连接数耗尽处理手册" /></label>
                <label className="field span-2"><span>公司内网手册网址 <b>*</b></span><input type="url" value={draft.sourceUrl} onChange={(event) => setDraft({ ...draft, sourceUrl: event.target.value })} required placeholder="https://wiki.corp.example/runbooks/connection-limit" /></label>
                <label className="field span-2"><span>正文选择器（可选）</span><input value={draft.contentSelector} onChange={(event) => setDraft({ ...draft, contentSelector: event.target.value })} placeholder="#article-content、.wiki-content 或 main" /></label>
                <label className="field"><span>告警原因（逗号分隔）</span><input value={draft.reasons} onChange={(event) => setDraft({ ...draft, reasons: event.target.value })} placeholder="connection_exhausted, too_many_connections" /></label>
                <label className="field"><span>检索关键词（逗号分隔）</span><input value={draft.keywords} onChange={(event) => setDraft({ ...draft, keywords: event.target.value })} placeholder="连接数, connection" /></label>
              </div>

              <fieldset className="severity-selector">
                <legend>适用告警等级</legend>
                <div>{(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as Severity[]).map((severity) => (
                  <label key={severity} className={draft.severities.includes(severity) ? "checked" : ""}>
                    <input type="checkbox" checked={draft.severities.includes(severity)} onChange={(event) => setDraft({ ...draft, severities: event.target.checked ? [...draft.severities, severity] : draft.severities.filter((item) => item !== severity) })} />
                    <SeverityBadge severity={severity} />
                  </label>
                ))}</div>
              </fieldset>

              <label className="field"><span>索引管理备注（不参与匹配） <b>*</b></span><textarea className="runbook-content-editor" value={draft.content} onChange={(event) => setDraft({ ...draft, content: event.target.value })} required rows={6} spellCheck={false} placeholder="记录手册负责人、审批状态或迁移说明；处置正文始终从网址读取。" /></label>
              <div className="json-fields">
                <label className="field"><span>匹配标签 JSON</span><textarea rows={5} value={draft.labels} onChange={(event) => setDraft({ ...draft, labels: event.target.value })} spellCheck={false} /></label>
                <label className="field"><span>扩展元数据 JSON</span><textarea rows={5} value={draft.metadata} onChange={(event) => setDraft({ ...draft, metadata: event.target.value })} spellCheck={false} /></label>
              </div>

              {error && !authError && <div className="form-error" role="alert">{error}</div>}
              {notice && <div className="form-success"><BookOpenCheck size={16} /> {notice}</div>}
              <div className="editor-actions">
                {selectedId && <span><Clock3 size={14} /> 使用版本号防止覆盖他人的并发修改</span>}
                <button type="submit" className="button primary" disabled={saving}>{saving ? <InlineLoading label="保存中" /> : <><Save size={16} /> {selectedId ? "保存修改" : "创建手册"}</>}</button>
              </div>
            </form>
          </section>
        </div>
      )}

      <ConfirmDialog open={deleteOpen} title="删除这份处置手册？" description={`删除「${draft.title}」后，新的告警分析将无法再检索到这份依据。此操作不可撤销。`} busy={saving} onCancel={() => setDeleteOpen(false)} onConfirm={() => void remove()} />
    </div>
  );
}
