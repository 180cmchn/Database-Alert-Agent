import type { AlertStatus, InvestigationStage, Severity } from "../types/api";

export const severityLabel: Record<Severity, string> = {
  CRITICAL: "紧急",
  WARNING: "警告",
  INFO: "提示",
};

export const statusLabel: Record<AlertStatus, string> = {
  RECEIVED: "已接收",
  QUEUED: "排队中",
  ANALYZING: "分析中",
  COMPLETED: "已完成",
  REVIEW_REQUIRED: "待人工复核",
  FAILED: "分析失败",
};

export const stageLabel: Record<InvestigationStage, string> = {
  RECEIVED: "接收告警",
  FINGERPRINTING: "识别问题指纹",
  KNOWLEDGE_MATCHING: "匹配历史经验",
  RUNBOOK_MATCHING: "查询处置手册",
  INVESTIGATING: "采集现场证据",
  ADVISING: "生成处理建议",
  VALIDATING: "校验分析结论",
  REPORTING: "归档建议与依据",
  COMPLETED: "分析完成",
  REVIEW_REQUIRED: "等待人工复核",
  FAILED: "分析失败",
};

export const toolStatusLabel = {
  SUCCESS: "采集成功",
  TIMEOUT: "采集超时",
  FAILED: "采集失败",
  SKIPPED: "已跳过",
} as const;

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return value;
  const seconds = Math.round((timestamp - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat("zh-CN", { numeric: "auto" });
  if (abs < 60) return formatter.format(seconds, "second");
  if (abs < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function compactId(value: string, size = 8): string {
  return value.length <= size * 2 + 1
    ? value
    : `${value.slice(0, size)}…${value.slice(-size)}`;
}
