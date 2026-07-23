import type {
  AdminSettings,
  AdminSettingsPatch,
  AlertAccepted,
  AlertListResponse,
  AlertStatus,
  ApiProblem,
  CanonicalAlertPayload,
  DashboardSummary,
  FeedbackRecord,
  FeedbackRequest,
  RunbookRecord,
  Severity,
  StoredAlert,
} from "../types/api";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export class ApiError extends Error {
  readonly status: number;
  readonly problem?: ApiProblem;

  constructor(message: string, status: number, problem?: ApiProblem) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  adminToken?: string,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  headers.set("Accept", "application/json");
  if (adminToken) {
    headers.set("Authorization", `Bearer ${adminToken}`);
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new ApiError("无法连接后端服务，请确认 API 已启动并检查网络。", 0);
  }

  if (!response.ok) {
    let problem: ApiProblem | undefined;
    try {
      problem = (await response.json()) as ApiProblem;
    } catch {
      problem = undefined;
    }
    const detail = Array.isArray(problem?.detail)
      ? problem.detail.map((item) => item.msg).filter(Boolean).join("；")
      : typeof problem?.detail === "object"
        ? problem.detail.message
        : problem?.detail;
    throw new ApiError(
      problem?.message || detail || `请求失败（HTTP ${response.status}）`,
      response.status,
      problem,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

function queryString<T extends object>(values: T): string {
  const query = new URLSearchParams();
  Object.entries(values as Record<string, string | number | undefined>).forEach(([key, value]) => {
    if (value !== undefined && value !== "") query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export interface AlertFilters {
  page?: number;
  page_size?: number;
  status?: AlertStatus | "";
  severity?: Severity | "";
  source?: string;
  environment?: string;
  search?: string;
}

export const api = {
  getDashboardSummary: () => request<DashboardSummary>("/api/v1/dashboard/summary"),

  getAlerts: (filters: AlertFilters) =>
    request<AlertListResponse>(`/api/v1/alerts${queryString(filters)}`),

  getAlert: (alertId: string) =>
    request<StoredAlert>(`/api/v1/alerts/${encodeURIComponent(alertId)}`),

  createAlert: (payload: CanonicalAlertPayload) =>
    request<AlertAccepted>("/api/v1/alerts/canonical/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  submitFeedback: (alertId: string, payload: FeedbackRequest, token: string) =>
    request<FeedbackRecord>(
      `/api/v1/alerts/${encodeURIComponent(alertId)}/feedback`,
      { method: "POST", body: JSON.stringify(payload) },
      token,
    ),

  getRunbooks: async (token: string) => {
    const data = await request<RunbookRecord[] | { items: RunbookRecord[] }>(
      "/api/v1/admin/runbooks",
      {},
      token,
    );
    return Array.isArray(data) ? data : data.items;
  },

  getSettings: (token: string) =>
    request<AdminSettings>("/api/v1/admin/settings", {}, token),

  updateSettings: (patch: AdminSettingsPatch, token: string) =>
    request<AdminSettings>(
      "/api/v1/admin/settings",
      { method: "PATCH", body: JSON.stringify(patch) },
      token,
    ),
};
