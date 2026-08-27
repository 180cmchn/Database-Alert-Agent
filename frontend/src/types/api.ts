export type Severity = "CRITICAL" | "WARNING" | "INFO";

export type AlertStatus =
  | "RECEIVED"
  | "QUEUED"
  | "ANALYZING"
  | "COMPLETED"
  | "INCONCLUSIVE"
  | "FAILED"
  | "CANCELLED";

export type InvestigationStage =
  | "RECEIVED"
  | "FINGERPRINTING"
  | "KNOWLEDGE_MATCHING"
  | "INVESTIGATING"
  | "ADVISING"
  | "VALIDATING"
  | "REPORTING"
  | "COMPLETED"
  | "INCONCLUSIVE"
  | "FAILED"
  | "CANCELLED";

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
  confidence: number | null;
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
  alert_name: string;
  resource_type?: string | null;
  cluster?: string | null;
  alarm_type?: string | null;
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

export interface KnowledgeReference {
  source: string;
  knowledge_id: string;
  title: string;
  source_uri: string;
}

export interface KnowledgeExcerpt {
  source: string;
  knowledge_id: string;
  title: string;
  content: string;
  source_uri: string;
  score: number;
  raw_score: number;
  metadata: Record<string, unknown>;
}

export interface RecommendationStep {
  order: number;
  action: string;
  expected_result?: string | null;
  caution?: string | null;
  source_ref?: KnowledgeReference | null;
}

export interface AnalysisBasis {
  source: "KNOWLEDGE" | "AI";
  statement: string;
  source_ref?: KnowledgeReference | null;
}

export interface RootCauseAssessment {
  cause: string;
  hypothesis_id?: string | null;
  cause_id?: string | null;
  // SUPPORT is accepted only when rendering recommendations persisted by older releases.
  status: "SUPPORTED" | "CONTRADICTED" | "UNKNOWN" | "SUPPORT";
  evidence_refs: string[];
  confidence: number;
  verified: boolean;
  next_probe?: string | null;
}

export interface Recommendation {
  summary: string;
  knowledge_match_summary: string;
  likely_causes: string[];
  analysis_bases: AnalysisBasis[];
  steps: RecommendationStep[];
  risks: string[];
  confidence: number;
  knowledge_matches: KnowledgeExcerpt[];
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

export type ToolStatus = "SUCCESS" | "NO_DATA" | "TIMEOUT" | "FAILED" | "SKIPPED";

export type EvidenceUnitStatus =
  | "SUCCESS"
  | "PARTIAL"
  | "FAILED"
  | "NO_DATA"
  | "RECOVERED"
  | "UNAVAILABLE"
  | "NOT_APPLICABLE";

export interface EvidenceUnit {
  contract_version: "evidence-unit/v2";
  id: string;
  parent_evidence_id: string;
  unit_key: string;
  kind: "HISTORY" | "SUPPLEMENTAL";
  stage: string;
  result_index?: number | null;
  status: EvidenceUnitStatus;
  summary: string;
  data: Record<string, unknown>;
  root_cause_eligible: boolean;
  root_cause_ineligible_reason?: string | null;
  source_artifact_id: string;
  source_paths: string[];
}

export interface EvidenceRecord {
  id: string;
  contract_version: "evidence-record/v1" | "evidence-record/v2";
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
  source_artifact_id?: string | null;
  evidence_units: EvidenceUnit[];
}

export interface ValidationRecord {
  id: string;
  run_id: string;
  kind: "RULE" | "AGENT";
  passed: boolean;
  evidence_sufficient: boolean;
  issues: string[];
  metadata: Record<string, unknown>;
  created_at: string;
}

export type AIProvider = "openai_compatible" | "openai_responses" | "fake";

export interface AnalysisConfigSnapshot {
  knowledge_sources: string[];
  external_knowledge_enabled: boolean;
  external_knowledge_base_url: string;
  external_knowledge_min_relevance: number;
  react_max_rounds: number;
  analysis_timeout_seconds: number;
  validation_enabled: boolean;
  ai_fallback_enabled: boolean;
  stream_main_agent_reasoning: boolean;
  ai_model: string;
  ai_provider: string;
}

export interface InvestigationRun {
  id: string;
  alert_id: string;
  attempt: number;
  status: "RUNNING" | "COMPLETED" | "INCONCLUSIVE" | "FAILED" | "CANCELLED";
  current_stage: InvestigationStage;
  error?: string | null;
  cancel_requested_at?: string | null;
  cancel_requested_by?: string | null;
  cancelled_at?: string | null;
  config_snapshot?: AnalysisConfigSnapshot | null;
  created_at: string;
  updated_at: string;
}

export interface StoredAlert {
  alert: NormalizedAlert;
  status: AlertStatus;
  recommendation?: Recommendation | null;
  advisor_metadata?: {
    provider: string;
    model: string;
    prompt_version: string;
    request_id?: string | null;
    usage: Record<string, unknown>;
  } | null;
  error?: string | null;
  latest_run?: InvestigationRun | null;
  selected_run?: InvestigationRun | null;
  selected_run_result_available: boolean;
  all_runs: InvestigationRun[];
  progress: ProgressRecord[];
  evidence_records: EvidenceRecord[];
  validations: ValidationRecord[];
  created_at: string;
  updated_at: string;
}

export interface ReanalyzeRequest {
  force?: boolean;
}

export interface ReanalyzeResponse {
  alert_id: string;
  run_id: string;
  attempt: number;
  config_snapshot: AnalysisConfigSnapshot;
  message: string;
}

export interface CancelRunResponse {
  alert_id: string;
  run_id: string;
  status: InvestigationRun["status"];
  cancel_requested_at: string;
  message: string;
}

export type AgentTraceKind = "REASONING" | "ACTION" | "OBSERVATION";
export type AgentTraceScope = "main_agent" | "mcp_internal";

export interface AgentTraceEntry {
  event_id: string;
  run_id: string;
  sequence: number;
  kind: AgentTraceKind;
  scope: AgentTraceScope;
  actor: string;
  provider: string;
  content: string;
  stream_id: string | null;
  delta_index: number | null;
  occurred_at: string;
}

export interface AgentTraceResponse {
  run_id: string;
  after_sequence: number;
  next_sequence: number;
  has_more: boolean;
  items: AgentTraceEntry[];
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
  alert_name?: string;
  resource_type?: string;
  cluster?: string;
  alarm_type?: string;
  metric_name?: string;
  database?: DatabaseTarget;
  features?: Record<string, unknown>;
  labels?: Record<string, string>;
  attributes?: Record<string, unknown>;
}

export type ReasoningEffort = "" | "low" | "medium" | "high" | "xhigh" | "max";

export const REASONING_EFFORT_OPTIONS: ReadonlyArray<{ value: ReasoningEffort; label: string }> = [
  { value: "", label: "默认（不发送，跟随 Provider）" },
  { value: "low", label: "low · 快速决策" },
  { value: "medium", label: "medium" },
  { value: "high", label: "high" },
  { value: "xhigh", label: "xhigh · 深度推理" },
  { value: "max", label: "max · 最大推理" },
];

export interface AdminSettings {
  app_env: string;
  fake_provider_allowed: boolean;
  ready: boolean;
  issues: string[];
  ai_provider: string;
  ai_base_url: string;
  ai_model: string;
  ai_timeout_seconds: number;
  ai_json_mode: boolean;
  ai_fallback_enabled: boolean;
  stream_main_agent_reasoning: boolean;
  ai_react_model: string;
  ai_mcp_model: string;
  ai_react_reasoning_effort: ReasoningEffort;
  ai_reasoning_effort: ReasoningEffort;
  ai_mcp_reasoning_effort: ReasoningEffort;
  scheduler_workers: number;
  react_max_rounds: number;
  analysis_timeout_seconds: number;
  ai_api_key_configured: boolean;
  wecom_enabled: boolean;
  wecom_webhook_url_configured: boolean;
  wecom_page_base_url: string;
  flashduty_enabled: boolean;
  flashduty_base_url: string;
  flashduty_app_key_configured: boolean;
  flashduty_polling_enabled: boolean;
  flashduty_poll_interval_seconds: number;
  flashduty_poll_lookback_seconds: number;
  flashduty_poll_channel_ids: number[];
  flashduty_poll_integration_ids: number[];
  external_knowledge_enabled: boolean;
  external_knowledge_base_url: string;
  external_knowledge_api_key_configured: boolean;
  external_knowledge_min_relevance: number;
  knowledge_sources: string[];
  revision: string;
  apply_status: "applied";
  worker_refresh_mode: "before_each_batch";
  changed_fields: string[];
}

export interface AdminSettingsPatch {
  expected_revision: string;
  ai_provider?: AIProvider;
  ai_base_url?: string;
  ai_model?: string;
  ai_react_model?: string;
  ai_mcp_model?: string;
  ai_react_reasoning_effort?: ReasoningEffort;
  ai_reasoning_effort?: ReasoningEffort;
  ai_mcp_reasoning_effort?: ReasoningEffort;
  ai_timeout_seconds?: number;
  ai_json_mode?: boolean;
  ai_fallback_enabled?: boolean;
  stream_main_agent_reasoning?: boolean;
  scheduler_workers?: number;
  wecom_webhook_url?: string;
  wecom_page_base_url?: string;
  wecom_enabled?: boolean;
  react_max_rounds?: number;
  analysis_timeout_seconds?: number;
  ai_api_key?: string;
  knowledge_sources?: string[];
  flashduty_polling_enabled?: boolean;
  flashduty_poll_interval_seconds?: number;
  flashduty_poll_lookback_seconds?: number;
  external_knowledge_api_key?: string;
}

export interface ApiProblem {
  code?: string;
  message?: string;
  detail?:
    | string
    | { code?: string; message?: string }
    | Array<{ loc?: Array<string | number>; msg?: string }>;
}
