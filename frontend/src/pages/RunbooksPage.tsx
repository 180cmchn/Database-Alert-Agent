import { BookOpenCheck, FileText, KeyRound, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AdminUnlock,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  SeverityBadge,
} from "../components/ui";
import { useAdminAuth } from "../context/AdminAuthContext";
import { api, ApiError } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { RunbookRecord } from "../types/api";

function metadataString(record: RunbookRecord, key: string): string {
  const value = record.metadata[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "—";
}

export function RunbooksPage() {
  const { token, unlocked, lock } = useAdminAuth();
  const [runbooks, setRunbooks] = useState<RunbookRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [authError, setAuthError] = useState(false);
  const [adminUnavailable, setAdminUnavailable] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const records = await api.getRunbooks(token);
      setRunbooks(records);
      setSelectedId((current) => (
        current && records.some((item) => item.id === current) ? current : records[0]?.id || null
      ));
      setError("");
      setAuthError(false);
      setAdminUnavailable(false);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "PDF 手册列表加载失败");
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
      [item.id, item.title, item.content, metadataString(item, "file_name")]
        .some((value) => value.toLowerCase().includes(term)),
    );
  }, [runbooks, search]);
  const selected = runbooks.find((item) => item.id === selectedId) || null;

  if (!unlocked) {
    return <AdminUnlock title="解锁处置手册" description="查看本地 PDF 手册清单和已提取正文需要管理员令牌。" />;
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
        eyebrow="LOCAL PDF LIBRARY"
        title="处置手册"
        description="手册从本地 PDF 目录只读加载；Agent 直接检索 PDF 文字层，不再访问内网页面。"
        actions={<button type="button" className="button secondary" onClick={lock}><KeyRound size={16} /> 锁定会话</button>}
      />

      {authError ? (
        <ErrorState message="管理员令牌无效或已过期，请锁定会话后重新输入。" onRetry={lock} />
      ) : error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : (
        <div className="runbook-workspace">
          <aside className="runbook-list-panel">
            <div className="runbook-list-head">
              <div><strong>PDF 手册目录</strong><span>{runbooks.length} 份</span></div>
              <label className="mini-search"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索标题或正文" aria-label="搜索 PDF 手册" /></label>
            </div>
            {loading ? <LoadingState label="读取 PDF 手册目录…" /> : filtered.length ? (
              <div className="runbook-list">
                {filtered.map((runbook) => (
                  <button type="button" key={runbook.id} className={selectedId === runbook.id ? "active" : ""} onClick={() => setSelectedId(runbook.id)}>
                    <span className="runbook-list-icon"><BookOpenCheck size={18} /></span>
                    <span><strong>{runbook.title}</strong><small>{metadataString(runbook, "page_count")} 页 · {runbook.knowledge_type} · {runbook.quality_status}</small><em>{formatDateTime(runbook.updated_at)}</em></span>
                  </button>
                ))}
              </div>
            ) : <EmptyState kind="runbook" title={search ? "没有匹配手册" : "PDF 手册目录为空"} description={search ? "尝试更换关键词。" : "请把带文字层的 PDF 放入配置的本地手册目录后重启服务。"} />}
          </aside>

          <section className="runbook-editor-panel">
            {selected ? (
              <>
                <div className="editor-heading">
                  <div><span className="editor-icon"><FileText size={20} /></span><div><p>READ ONLY · LOCAL PDF</p><h2>{selected.title}</h2></div></div>
                </div>
                <div className="runbook-pdf-details">
                  <dl>
                    <div><dt>文件</dt><dd>{metadataString(selected, "file_name")}</dd></div>
                    <div><dt>页数</dt><dd>{metadataString(selected, "page_count")}</dd></div>
                    <div><dt>大小</dt><dd>{metadataString(selected, "file_size_bytes")} bytes</dd></div>
                    <div><dt>手册 ID</dt><dd>{selected.id}</dd></div>
                    <div><dt>知识类型</dt><dd>{selected.knowledge_type}</dd></div>
                    <div><dt>质量状态</dt><dd>{selected.quality_status}</dd></div>
                  </dl>
                  {selected.severities.length > 0 && <div className="runbook-severities">{selected.severities.map((severity) => <SeverityBadge key={severity} severity={severity} />)}</div>}
                  <p className="runbook-readonly-note">PDF 是审计原文；章节、诊断图和质量状态来自只读结构化索引。review_required/draft 资料不能通过生产准入门槛。</p>
                  <pre className="runbook-content-preview">{selected.content}</pre>
                </div>
              </>
            ) : <EmptyState kind="runbook" title="请选择一份 PDF 手册" description="右侧将展示服务实际用于匹配的文字内容。" />}
          </section>
        </div>
      )}
    </div>
  );
}
