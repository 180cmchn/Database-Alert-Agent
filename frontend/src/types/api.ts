export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type AlertStatus =
  | "RECEIVED"
  | "QUEUED"
  | "ANALYZING"
  | "COMPLETED"
  | "REVIEW_REQUIRED"
  | "FAILED";

export type InvestigationStage =
  | "RECEIVED"
  | "FINGERPRINTING"
  | "KNOWLEDGE_MATCHING"
  | "RUNBOOK_MATCHING"
  | "INVESTIGATING"
  | "ADVISING"
  | "VALIDATING"
  | "REPORTING"
  | "COMPLETED"
  | "REVIEW_REQUIRED"
  | "FAILED";

export interface AlertListItem {
  id: string;
  external_id: string;
  source: string;
  title: string;
  reason: string;
  severity: Severity;
  status: AlertStatus;
  environment: string;
  service_name: string;
  occurred_at: string;
  created_at: string;
  updated_at: string;
  current_stage: InvestigationStage | null;
  manual_matched: boolean;
  requires_human: boolean;
  confidence: number | null;
  notification_count: number;
}

export interface AlertListResponse {
  items: AlertListItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface DashboardSummary {
  total: number;
  active: number;
  critical_open: number;
  by_status: Partial<Record<AlertStatus, number>>;
  by_severity: Partial<Record<Severity, number>>;
  recent_alerts: AlertListItem[];
}

export interface DatabaseTarget {
  engine?: string | null;
  instance?: string | null;
  database?: string | null;
  host?: string | null;
  [key: string]: unknown;
}

export interface NormalizedAlert {
  id: string;
  external_id: string;
  source: string;
  raw_severity: string;
  severity: Severity;
  incident_fingerprint: string;
  fingerprint_version: string;
  environment: string;
  service_name: string;
  alert_type: string;
  metric_name?: string | null;
  error_pattern?: string | null;
  error_summary?: string | null;
  title: string;
  reason: string;
  description: string;
  occurred_at: string;
  database?: DatabaseTarget | null;
  features: Record<string, unknown>;
  labels: Record<string, string>;
  attributes: Record<string, unknown>;
  raw_payload: Record<string, unknown>;
}

export interface RunbookReference {
  runbook_id: string;
  section: string;
}

export interface RunbookExcerpt {
  runbook_id: string;
  title: string;
  section: string;
  content: string;
  score: number;
  metadata: Record<string, unknown>;
}

export interface RecommendationStep {
  order: number;
  action: string;
  expected_result?: string | null;
  caution?: string | null;
  source_ref?: RunbookReference | null;
}

export interface RootCauseAssessment {
  cause: string;
  evidence_refs: string[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
  verified: boolean;
}

export interface Recommendation {
  summary: string;
  likely_causes: string[];
  evidence: string[];
  steps: RecommendationStep[];
  risks: string[];
  requires_human: boolean;
  confidence: number;
  manual_matched: boolean;
  runbook_references: RunbookReference[];
  root_causes: RootCauseAssessment[];
}

export interface ProgressRecord {
  id: string;
  run_id: string;
  sequence: number;
  stage: InvestigationStage;
  message: string;
  details: Record<string, unknown>;
  created_at: string;
}

export type ToolStatus = "SUCCESS" | "TIMEOUT" | "FAILED" | "SKIPPED";

export interface EvidenceRecord {
  id: string;
  run_id: string;
  tool_name: string;
  source_system: string;
  status: ToolStatus;
  request: Record<string, unknown>;
  summary: string;
  structured_data: Record<string, unknown>;
  error?: string | null;
  started_at: string;
  collected_at: string;
  duration_ms: number;
  truncated: boolean;
}

export interface ValidationRecord {
  id: string;
  run_id: string;
  kind: "RULE" | "AGENT";
  passed: boolean;
  issues: string[];
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface NotificationRecord {
  id: string;
  phase: "INITIAL_ALERT" | "ADVICE_READY" | "ANALYSIS_FAILED";
  status: "SENT" | "FAILED";
  attempts: number;
  error?: string | null;
  external_delivery_id?: string | null;
  created_at: string;
}

export interface InvestigationRun {
  id: string;
  alert_id: string;
  attempt: number;
  status: "RUNNING" | "COMPLETED" | "REVIEW_REQUIRED" | "FAILED";
  current_stage: InvestigationStage;
  strategy_id?: string | null;
  error?: string | null;
  created_at: string;
  updated_at: string;
}

export interface KnowledgeCase {
  id: string;
  final_root_cause: string;
  actual_resolution: string;
  confirmed_by: string;
  confirmed_at: string;
}

export interface StoredAlert {
  alert: NormalizedAlert;
  status: AlertStatus;
  recommendation?: Recommendation | null;
  manual_matches: RunbookExcerpt[];
  advisor_metadata?: {
    provider: string;
    model: string;
    prompt_version: string;
    request_id?: string | null;
    usage: Record<string, unknown>;
  } | null;
  error?: string | null;
  notifications: NotificationRecord[];
  latest_run?: InvestigationRun | null;
  progress: ProgressRecord[];
  evidence_records: EvidenceRecord[];
  validations: ValidationRecord[];
  feedback: unknown[];
  knowledge_matches: KnowledgeCase[];
  created_at: string;
  updated_at: string;
}

export interface AlertAccepted {
  alert_id: string;
  event_id: string;
  status: AlertStatus;
  detail_url: string;
  deduplicated: boolean;
}

export interface CanonicalAlertPayload {
  external_id?: string;
  severity: Severity;
  title: string;
  reason: string;
  description?: string;
  occurred_at?: string;
  environment?: string;
  service_name?: string;
  alert_type?: string;
  metric_name?: string;
  database?: DatabaseTarget;
  features?: Record<string, unknown>;
  labels?: Record<string, string>;
  attributes?: Record<string, unknown>;
}

export interface RunbookRecord {
  id: string;
  title: string;
  section: string;
  reasons: string[];
  keywords: string[];
  severities: Severity[];
  labels: Record<string, string>;
  content: string;
  metadata: Record<string, unknown>;
  version: number;
  updated_at: string;
}

export type RunbookCreateInput = Omit<RunbookRecord, "updated_at" | "version">;
export type RunbookUpdateInput = Omit<RunbookRecord, "id" | "updated_at" | "version"> & {
  expected_version: number;
};

export interface AdminSettings {
  app_env: string;
  fake_provider_allowed: boolean;
  ready: boolean;
  issues: string[];
  ai_provider: string;
  ai_base_url: string;
  ai_model: string;
  ai_timeout_seconds: number;
  ai_max_retries: number;
  ai_json_mode: boolean;
  runbook_limit: number;
  escalation_severities: Severity[];
  notifier_mode: "log" | "webhook" | "wecom";
  management_webhook_url: string;
  notification_max_attempts: number;
  notification_retry_backoff_seconds: number;
  react_enabled: boolean;
  react_max_dynamic_turns: number;
  validation_enabled: boolean;
  ai_api_key_configured: boolean;
  management_webhook_bearer_token_configured: boolean;
  wecom_webhook_url_configured: boolean;
  revision: string;
  apply_status: "applied";
  worker_refresh_mode: "before_each_job";
  changed_fields: string[];
}

export interface AdminSettingsPatch {
  expected_revision: string;
  ai_provider?: string;
  ai_base_url?: string;
  ai_model?: string;
  ai_timeout_seconds?: number;
  ai_max_retries?: number;
  ai_json_mode?: boolean;
  runbook_limit?: number;
  escalation_severities?: Severity[];
  notifier_mode?: "log" | "webhook" | "wecom";
  management_webhook_url?: string;
  wecom_webhook_url?: string;
  notification_max_attempts?: number;
  notification_retry_backoff_seconds?: number;
  react_enabled?: boolean;
  react_max_dynamic_turns?: number;
  validation_enabled?: boolean;
  ai_api_key?: string;
  management_webhook_bearer_token?: string;
}

export interface ApiProblem {
  code?: string;
  message?: string;
  detail?:
    | string
    | { code?: string; message?: string }
    | Array<{ loc?: Array<string | number>; msg?: string }>;
}
