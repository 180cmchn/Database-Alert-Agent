export type Severity = "CRITICAL" | "WARNING" | "INFO";

export type AlertStatus =
  | "RECEIVED"
  | "QUEUED"
  | "ANALYZING"
  | "COMPLETED"
  | "INCONCLUSIVE"
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
  | "INCONCLUSIVE"
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

export interface RunbookReference {
  runbook_id: string;
  section: string;
}

export interface ExternalKnowledgeReference {
  knowledge_id: string;
  title: string;
  source_uri: string;
}

export interface ExternalKnowledgeExcerpt {
  knowledge_id: string;
  title: string;
  content: string;
  source_uri: string;
  score: number;
  raw_score: number;
  metadata: Record<string, unknown>;
}

export interface RunbookExcerpt {
  runbook_id: string;
  title: string;
  section: string;
  content: string;
  score: number;
  match_confidence: number;
  match_reasons: string[];
  page_refs: number[];
  knowledge_type: "runbook" | "incident_case" | "reference" | "incomplete";
  metadata: Record<string, unknown>;
}

export interface RecommendationStep {
  order: number;
  action: string;
  expected_result?: string | null;
  caution?: string | null;
  source_ref?: RunbookReference | ExternalKnowledgeReference | null;
}

export interface AnalysisBasis {
  source: "RUNBOOK" | "EXTERNAL_KNOWLEDGE" | "AI";
  statement: string;
  source_ref?: RunbookReference | ExternalKnowledgeReference | null;
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
  manual_matched: boolean;
  runbook_references: RunbookReference[];
  external_knowledge_matches: ExternalKnowledgeExcerpt[];
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
  evidence_sufficient: boolean;
  issues: string[];
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AnalysisConfigSnapshot {
  knowledge_sources: string[];
  external_knowledge_enabled: boolean;
  external_knowledge_base_url: string;
  runbook_limit: number;
  runbook_match_min_score: number;
  runbook_match_min_confidence: number;
  external_knowledge_min_relevance: number;
  react_enabled: boolean;
  react_max_dynamic_turns: number;
  validation_enabled: boolean;
  ai_fallback_enabled: boolean;
  ai_model: string;
  ai_provider: string;
}

export interface InvestigationRun {
  id: string;
  alert_id: string;
  attempt: number;
  status: "RUNNING" | "COMPLETED" | "INCONCLUSIVE" | "FAILED";
  current_stage: InvestigationStage;
  strategy_id?: string | null;
  error?: string | null;
  config_snapshot?: AnalysisConfigSnapshot | null;
  created_at: string;
  updated_at: string;
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

export interface RunbookRecord {
  id: string;
  title: string;
  section: string;
  reasons: string[];
  keywords: string[];
  severities: Severity[];
  labels: Record<string, string>;
  knowledge_type: "runbook" | "incident_case" | "reference" | "incomplete";
  deprecated: boolean;
  sections: Array<{ id: string; title: string; pages: number[]; content: string }>;
  causes: Array<{
    cause_id: string;
    hypothesis: string;
    supporting_evidence: string[];
    contradicting_evidence: string[];
  }>;
  actions: Array<{
    action: string;
    execution_class: "read_only" | "change";
    expected_result?: string | null;
    approval_required: boolean;
  }>;
  content: string;
  metadata: Record<string, unknown>;
  version: number;
  updated_at: string;
}

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
  ai_fallback_enabled: boolean;
  runbook_limit: number;
  scheduler_workers: number;
  react_enabled: boolean;
  react_max_dynamic_turns: number;
  validation_enabled: boolean;
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
  archery_mcp_max_agent_steps: number;
  external_knowledge_enabled: boolean;
  external_knowledge_base_url: string;
  external_knowledge_api_key_configured: boolean;
  external_knowledge_min_relevance: number;
  runbook_match_min_confidence: number;
  knowledge_sources: string[];
  revision: string;
  apply_status: "applied";
  worker_refresh_mode: "before_each_batch";
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
  ai_fallback_enabled?: boolean;
  runbook_limit?: number;
  scheduler_workers?: number;
  wecom_webhook_url?: string;
  wecom_page_base_url?: string;
  wecom_enabled?: boolean;
  react_enabled?: boolean;
  react_max_dynamic_turns?: number;
  validation_enabled?: boolean;
  ai_api_key?: string;
  knowledge_sources?: string[];
  flashduty_polling_enabled?: boolean;
  flashduty_poll_interval_seconds?: number;
  flashduty_poll_lookback_seconds?: number;
  archery_mcp_max_agent_steps?: number;
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
