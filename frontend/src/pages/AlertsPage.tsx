import { ChevronLeft, ChevronRight, Filter, Search, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTable } from "../components/AlertTable";
import { EmptyState, ErrorState, LoadingState, PageHeader, SectionCard } from "../components/ui";
import { api } from "../lib/api";
import { severityLabel, statusLabel } from "../lib/format";
import type { AlertListResponse, AlertStatus, Severity } from "../types/api";

const statuses: AlertStatus[] = ["RECEIVED", "QUEUED", "ANALYZING", "COMPLETED", "REVIEW_REQUIRED", "FAILED"];
const severities: Severity[] = ["CRITICAL", "WARNING", "INFO"];
const PAGE_SIZE = 20;

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("page")) || 1);
  const status = (params.get("status") || "") as AlertStatus | "";
  const severity = (params.get("severity") || "") as Severity | "";
  const source = params.get("source") || "";
  const environment = params.get("environment") || "";
  const search = params.get("search") || "";
  const [searchInput, setSearchInput] = useState(search);
  const [data, setData] = useState<AlertListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => setSearchInput(search), [search]);

  const updateParams = useCallback(
    (patch: Record<string, string | number>) => {
      const next = new URLSearchParams(params);
      Object.entries(patch).forEach(([key, value]) => {
        if (value === "" || value === 0) next.delete(key);
        else next.set(key, String(value));
      });
      if (!("page" in patch)) next.delete("page");
      setParams(next);
    },
    [params, setParams],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (searchInput !== search) updateParams({ search: searchInput.trim() });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [search, searchInput, updateParams]);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const result = await api.getAlerts({ page, page_size: PAGE_SIZE, status, severity, source, environment, search });
      setData(result);
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "告警列表加载失败");
    } finally {
      setLoading(false);
    }
  }, [environment, page, search, severity, source, status]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const activeFilterCount = useMemo(
    () => [status, severity, source, environment, search].filter(Boolean).length,
    [environment, search, severity, source, status],
  );

  const clearFilters = () => {
    setSearchInput("");
    setParams({});
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="ALERT INVENTORY"
        title="告警中心"
        description="按等级、状态与运行环境检索每一条告警的完整排查记录。"
        actions={<Link to="/alerts/new" className="button primary">创建测试告警</Link>}
      />

      <SectionCard className="filter-card">
        <div className="filter-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              placeholder="搜索标题、原因或外部 ID"
              aria-label="搜索告警"
            />
            {searchInput && (
              <button type="button" aria-label="清除搜索" onClick={() => setSearchInput("")}><X size={15} /></button>
            )}
          </div>
          <label className="select-field">
            <span className="sr-only">状态</span>
            <select value={status} onChange={(event) => updateParams({ status: event.target.value })}>
              <option value="">全部状态</option>
              {statuses.map((item) => <option key={item} value={item}>{statusLabel[item]}</option>)}
            </select>
          </label>
          <label className="select-field">
            <span className="sr-only">等级</span>
            <select value={severity} onChange={(event) => updateParams({ severity: event.target.value })}>
              <option value="">全部等级</option>
              {severities.map((item) => <option key={item} value={item}>{severityLabel[item]}</option>)}
            </select>
          </label>
          <label className="compact-input">
            <span className="sr-only">来源</span>
            <input value={source} onChange={(event) => updateParams({ source: event.target.value.trim() })} placeholder="来源" />
          </label>
          <label className="compact-input">
            <span className="sr-only">环境</span>
            <input value={environment} onChange={(event) => updateParams({ environment: event.target.value.trim() })} placeholder="环境" />
          </label>
          {activeFilterCount > 0 && (
            <button type="button" className="clear-filter" onClick={clearFilters}>
              <Filter size={14} /> 清除 {activeFilterCount} 项筛选
            </button>
          )}
        </div>

        {loading ? (
          <LoadingState label="正在检索告警记录…" />
        ) : error ? (
          <ErrorState message={error} onRetry={() => void load()} />
        ) : data?.items.length ? (
          <>
            <div className="results-meta">
              <span>共 <strong>{data.total}</strong> 条告警</span>
              <span>第 {data.page} / {Math.max(1, data.pages)} 页</span>
            </div>
            <AlertTable alerts={data.items} />
            {data.pages > 1 && (
              <nav className="pagination" aria-label="告警列表分页">
                <button
                  type="button"
                  className="button secondary small"
                  disabled={data.page <= 1}
                  onClick={() => updateParams({ page: data.page - 1 })}
                ><ChevronLeft size={15} /> 上一页</button>
                <span>{data.page} / {data.pages}</span>
                <button
                  type="button"
                  className="button secondary small"
                  disabled={data.page >= data.pages}
                  onClick={() => updateParams({ page: data.page + 1 })}
                >下一页 <ChevronRight size={15} /></button>
              </nav>
            )}
          </>
        ) : (
          <EmptyState
            kind={activeFilterCount ? "search" : "empty"}
            title={activeFilterCount ? "没有匹配的告警" : "尚未接收告警"}
            description={activeFilterCount ? "尝试放宽筛选条件或清除搜索词。" : "告警平台接入后，事件会在这里形成可追溯记录。"}
            action={activeFilterCount ? <button className="button secondary" type="button" onClick={clearFilters}>清除筛选</button> : undefined}
          />
        )}
      </SectionCard>
    </div>
  );
}
