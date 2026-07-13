import { ArrowRight, BookCheck, UserRoundCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { formatDateTime, relativeTime } from "../lib/format";
import type { AlertListItem } from "../types/api";
import { SeverityBadge, StatusBadge } from "./ui";

export function AlertTable({ alerts, compact = false }: { alerts: AlertListItem[]; compact?: boolean }) {
  return (
    <div className={`alert-table-wrap ${compact ? "compact" : ""}`}>
      <table className="alert-table">
        <thead>
          <tr>
            <th>告警事件</th>
            <th>等级</th>
            <th>分析状态</th>
            {!compact && <th>环境 / 服务</th>}
            <th>发生时间</th>
            <th><span className="sr-only">操作</span></th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <Link className="alert-title-link" to={`/alerts/${alert.id}`}>
                  <strong>{alert.title}</strong>
                  <span>{alert.reason}</span>
                </Link>
                <div className="row-flags">
                  {alert.manual_matched && (
                    <span title="已命中告警手册"><BookCheck size={13} /> 手册命中</span>
                  )}
                  {alert.requires_human && (
                    <span className="human-flag"><UserRoundCheck size={13} /> 需人工</span>
                  )}
                </div>
              </td>
              <td><SeverityBadge severity={alert.severity} /></td>
              <td><StatusBadge status={alert.status} /></td>
              {!compact && (
                <td>
                  <span className="environment-label">{alert.environment || "unknown"}</span>
                  <small className="service-name">{alert.service_name || "unknown"}</small>
                </td>
              )}
              <td>
                <time dateTime={alert.occurred_at} title={formatDateTime(alert.occurred_at)}>
                  {relativeTime(alert.occurred_at)}
                </time>
              </td>
              <td>
                <Link className="row-action" to={`/alerts/${alert.id}`} aria-label={`查看 ${alert.title}`}>
                  <ArrowRight size={17} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
