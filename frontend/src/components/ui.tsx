import {
  AlertTriangle,
  CheckCircle2,
  DatabaseZap,
  FileQuestion,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  SearchX,
  ShieldAlert,
} from "lucide-react";
import type { FormEvent, ReactNode } from "react";
import { useState } from "react";
import { useAdminAuth } from "../context/AdminAuthContext";
import { severityLabel, statusLabel, toolStatusLabel } from "../lib/format";
import type { AlertStatus, Severity, ToolStatus } from "../types/api";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge severity severity-${severity.toLowerCase()}`}>
      <span className="badge-dot" aria-hidden="true" />
      {severityLabel[severity]}
    </span>
  );
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status status-${status.toLowerCase()}`}>{statusLabel[status]}</span>;
}

export function ToolStatusBadge({ status }: { status: ToolStatus }) {
  return (
    <span className={`badge tool-status tool-${status.toLowerCase()}`}>
      {status === "SUCCESS" ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />}
      {toolStatusLabel[status]}
    </span>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function SectionCard({
  title,
  eyebrow,
  description,
  action,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`section-card ${className}`}>
      {(title || eyebrow || description || action) && (
        <div className="section-heading">
          <div>
            {eyebrow && <span className="section-eyebrow">{eyebrow}</span>}
            {title && <h2>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {action && <div className="section-action">{action}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function LoadingState({ label = "正在读取告警数据…" }: { label?: string }) {
  return (
    <div className="state-panel loading-state" role="status">
      <LoaderCircle className="spin" size={26} />
      <span>{label}</span>
    </div>
  );
}

export function InlineLoading({ label = "处理中" }: { label?: string }) {
  return (
    <span className="inline-loading" role="status">
      <LoaderCircle className="spin" size={15} /> {label}
    </span>
  );
}

export function ErrorState({
  message,
  onRetry,
  compact = false,
}: {
  message: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  return (
    <div className={`state-panel error-state ${compact ? "compact" : ""}`} role="alert">
      <ShieldAlert size={compact ? 22 : 30} />
      <div>
        <strong>数据暂时不可用</strong>
        <p>{message}</p>
      </div>
      {onRetry && (
        <button className="button secondary small" type="button" onClick={onRetry}>
          <RefreshCw size={14} /> 重试
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  kind = "empty",
}: {
  title: string;
  description: string;
  action?: ReactNode;
  kind?: "empty" | "search" | "runbook";
}) {
  const Icon = kind === "search" ? SearchX : kind === "runbook" ? FileQuestion : DatabaseZap;
  return (
    <div className="state-panel empty-state">
      <span className="empty-icon"><Icon size={26} /></span>
      <strong>{title}</strong>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function AdminUnlock({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  const { unlock } = useAdminAuth();
  const [token, setToken] = useState("");

  function submit(event: FormEvent) {
    event.preventDefault();
    if (token.trim()) unlock(token);
  }

  return (
    <section className="admin-lock-card">
      <div className="lock-illustration" aria-hidden="true">
        <LockKeyhole size={30} />
      </div>
      <p className="eyebrow">管理员区域</p>
      <h1>{title}</h1>
      <p>{description}</p>
      <form onSubmit={submit} className="unlock-form">
        <label htmlFor="admin-token">管理员访问令牌</label>
        <div className="input-with-action">
          <input
            id="admin-token"
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="输入 Bearer Token"
            required
          />
          <button className="button primary" type="submit" disabled={!token.trim()}>
            解锁会话
          </button>
        </div>
      </form>
      <p className="security-note">
        <LockKeyhole size={14} /> 令牌仅保存在当前浏览器会话，关闭标签页后自动清除。
      </p>
    </section>
  );
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "确认删除",
  busy = false,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  if (!open) return null;
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onCancel}>
      <div
        className="dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <span className="dialog-icon"><AlertTriangle size={24} /></span>
        <h2 id="dialog-title">{title}</h2>
        <p>{description}</p>
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button type="button" className="button danger" onClick={onConfirm} disabled={busy}>
            {busy ? <InlineLoading label="正在删除" /> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
