import { clearAuthToken, getAuthToken, notifySessionExpired } from "./authClient";
import { sanitizeObject } from "../utils/safety";

const DEFAULT_BASE = "http://127.0.0.1:8000";

export function getApiBaseUrl(): string {
  const fromEnv = import.meta.env.VITE_API_BASE_URL;
  return (typeof fromEnv === "string" && fromEnv.trim()) || DEFAULT_BASE;
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${getApiBaseUrl()}${path}`;
  const token = getAuthToken();
  const hasJsonBody = options.body && !(options.body instanceof FormData);
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(hasJsonBody ? { "Content-Type": "application/json" } : {}),
    ...(options.headers as Record<string, string>),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errBody = await response.json();
      if (typeof errBody?.detail === "string") {
        detail = errBody.detail;
      } else if (errBody?.detail) {
        detail = JSON.stringify(errBody.detail);
      }
    } catch {
      /* ignore parse errors */
    }
    if (response.status === 401) {
      clearAuthToken();
      notifySessionExpired();
    }
    throw new ApiError(detail, response.status);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const data = (await response.json()) as T;
  return sanitizeObject(data);
}

export interface HealthResponse {
  status: string;
  service: string;
  database: string;
  version: string;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  affected_endpoint: string | null;
  affected_service: string | null;
  status: string;
  severity: string;
  summary: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface RootCauseScore {
  root_cause_id?: string;
  rank: number | null;
  likely_root_cause: string;
  confidence_band: string | null;
  confidence: number | null;
  recommended_fix: string | null;
  supporting_evidence_ids: string[] | null;
  missing_evidence: string[] | null;
  score_breakdown?: Record<string, unknown>[];
  matched_signals?: Record<string, unknown>[];
  negative_signals?: Record<string, unknown>[];
  correlation_reasons?: string[];
  contradicting_evidence?: Record<string, unknown>[];
  evidence_roles?: Record<string, unknown>[];
  suggested_actions?: Record<string, unknown>[];
}

export interface IncidentDetail extends IncidentSummary {
  root_cause_scores: RootCauseScore[];
}

export interface IncidentTrace {
  incident_id: string;
  title: string;
  status: string;
  affected_service: string | null;
  affected_endpoint: string | null;
  detection_count: number;
  evidence_count: number;
  timeline: unknown[];
  likely_root_causes: Record<string, unknown>[];
  evidence_roles?: Record<string, unknown>[];
  score_breakdowns?: Record<string, unknown>[];
  correlation_reasons?: string[];
  contradicting_evidence?: Record<string, unknown>[];
  missing_evidence: string[];
  suggested_actions?: Record<string, unknown>[];
  trace_summary?: Record<string, unknown>;
  reviewer_warning?: string;
  human_review_required: boolean;
  disclaimer: string;
}

export interface EvidenceGraphResponse {
  incident_id: string;
  nodes: Record<string, unknown>[];
  edges: Record<string, unknown>[];
  disclaimer: string;
}

export interface EvidenceFile {
  evidence_id: string;
  evidence_type: string;
  source_system: string | null;
  parsing_status: string;
  file_hash: string | null;
  linked_incident_id: string | null;
  upload_timestamp?: string | null;
  collector_name?: string | null;
}

export interface EvidenceUploadResponse {
  message: string;
  evidence: EvidenceFile;
}

export interface LlmReportSummary {
  report_id: string;
  incident_summary_preview: string | null;
  top_likely_cause_preview: string | null;
  provider_used: string;
  safety_status: string;
  created_at: string;
}

export interface ReviewDecision {
  decision: string;
  comment: string | null;
  reason?: string | null;
  evidence_checklist?: string[];
  evidence_relied_on?: string[];
  evidence_limitations?: string | null;
  missing_evidence_acknowledged?: boolean;
  reviewer_id: number | null;
  timestamp: string;
}

export type WorkflowStageCode =
  | "overview"
  | "root_cause"
  | "human_review"
  | "remediation"
  | "fix_verification"
  | "final_report";

export interface WorkflowStage {
  code: WorkflowStageCode;
  label: string;
  status: "pending" | "ready" | "complete" | "blocked";
  available: boolean;
  completed: boolean;
  blocked_reason: string | null;
}

export interface WorkflowNextAction {
  code: string;
  label: string;
  description: string;
  target: string;
  priority: "low" | "medium" | "high";
  blocked: boolean;
  blocked_reason: string | null;
}

export interface IncidentWorkflowState {
  incident_id: string;
  current_stage: WorkflowStageCode;
  overall_status: string;
  next_action: WorkflowNextAction;
  stages: WorkflowStage[];
  current_root_cause_analysis_id?: string | null;
  current_root_cause_analysis_version?: number | null;
  current_root_cause_analysis_stale?: boolean | null;
  workflow_chain_status?: "current" | "stale" | "blocked";
  review_progression_valid?: boolean | null;
  diagnosis_id?: string | null;
  diagnosis_generation_mode?: string | null;
  remediation_action_id?: string | null;
  remediation_action_status?: string | null;
  patch_status?: string | null;
  test_execution_status?: string | null;
  verification_outcome?: string | null;
  blocked_reasons?: string[];
}

export interface RootCauseEvidenceItem {
  evidence_id: string;
  evidence_type: string;
  evidence_role: string;
  safe_summary: string;
  support_reason: string;
  source: string | null;
  event_time: string | null;
}

export interface RootCauseEvidenceStrength {
  incident_id: string;
  likely_root_cause: string | null;
  root_cause_category: string | null;
  confidence_level: string;
  confidence_score: number;
  evidence_strength_level: "weak" | "medium" | "strong" | "very_strong";
  evidence_strength_score: number;
  evidence_strength_reason: string;
  confidence_cap: string;
  confidence_cap_score: number;
  confidence_cap_reason: string;
  supporting_evidence: RootCauseEvidenceItem[];
  contradicting_evidence: RootCauseEvidenceItem[];
  symptom_evidence_count: number;
  timeline_evidence_count: number;
  technical_evidence_count: number;
  remediation_evidence_count: number;
  verification_evidence_count: number;
  matched_signals: Record<string, unknown>[];
  negative_signals: Record<string, unknown>[];
  contradiction_signals: Record<string, unknown>[];
  missing_evidence: string[];
  recommended_next_evidence: string[];
  human_review_required: boolean;
  limitations: string[];
  /** Pre-remediation causal strength (Phase M). */
  causal_evidence_strength?: {
    causal_strength_level?: string;
    causal_strength_score?: number;
    causal_strength_reason?: string;
    causal_confidence_level?: string;
    excludes_post_remediation_evidence?: boolean;
  } | null;
  /** Separate post-remediation validation (Phase M). */
  post_remediation_validation?: {
    validation_status?: string;
    validation_status_reason?: string;
    validation_score?: number;
  } | null;
  analysis_version?: number | null;
  stale?: boolean | null;
  stale_reason?: string | null;
}

export type ReviewDecisionValue =
  | "approved"
  | "request_more_evidence"
  | "rejected_false_positive"
  | "escalated"
  | "rejected"
  | "inconclusive";

export interface SubmitReviewPayload {
  decision: ReviewDecisionValue;
  reason: string;
  comment?: string;
  evidence_checklist?: string[];
  evidence_relied_on?: string[];
  evidence_limitations?: string;
  missing_evidence_acknowledged?: boolean;
}

export interface ReviewDraft {
  incident_id: string;
  selected_decision: ReviewDecisionValue | null;
  reason: string | null;
  evidence_checklist: string[];
  evidence_relied_on: string[];
  evidence_limitations: string | null;
  missing_evidence_notes: string | null;
  missing_evidence_acknowledged: boolean;
  last_updated_by: number | null;
  last_updated_at: string;
}

export interface RemediationAction {
  remediation_action_id: string;
  incident_id: string;
  action_type: string;
  action_description: string;
  affected_component: string;
  assigned_owner: string;
  status: string;
  priority: string;
  target_date: string | null;
  retest_required: boolean;
  completion_notes: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface RemediationActionInput {
  action_type: string;
  action_description: string;
  affected_component: string;
  assigned_owner: string;
  status: string;
  priority: string;
  target_date?: string | null;
  retest_required: boolean;
  completion_notes?: string | null;
}

export interface ReportReadiness {
  incident_id: string;
  report_ready: boolean;
  draft_report_available: boolean;
  report_label: string;
  checks: Record<string, boolean>;
  blocking_items: string[];
  warning_items: string[];
}

export interface AuditLog {
  id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  timestamp: string;
}

export interface FixVerification {
  verification_status: string;
  checks_run: string[] | null;
  passed_checks: string[] | null;
  failed_checks: string[] | null;
  evidence_used: string[] | null;
  timestamp: string;
}

export interface IncidentReportSummary {
  report_id: number;
  report_type: string;
  created_at: string;
  content: Record<string, unknown>;
  html_document?: string | null;
}

export interface EvaluationMetric {
  metric_name: string;
  metric_value: number | null;
  thesis_claim: string | null;
  calculation_method: string | null;
  evidence_source: string | null;
  scenario_name: string | null;
}

export const api = {
  getHealth: () => request<HealthResponse>("/health"),

  listIncidents: () => request<IncidentSummary[]>("/incidents"),

  getIncident: (incidentId: string) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId)}`),

  getWorkflowState: (incidentId: string) =>
    request<IncidentWorkflowState>(
      `/incidents/${encodeURIComponent(incidentId)}/workflow-state`,
    ),

  getRootCauseEvidenceStrength: (incidentId: string) =>
    request<RootCauseEvidenceStrength>(
      `/incidents/${encodeURIComponent(incidentId)}/root-cause-evidence-strength`,
    ),

  getReportReadiness: (incidentId: string) =>
    request<ReportReadiness>(
      `/incidents/${encodeURIComponent(incidentId)}/report-readiness`,
    ),

  getIncidentTrace: (incidentId: string) =>
    request<IncidentTrace>(`/incidents/${encodeURIComponent(incidentId)}/trace`),
  getIncidentEvidenceGraph: (incidentId: string) =>
    request<EvidenceGraphResponse>(
      `/incidents/${encodeURIComponent(incidentId)}/evidence-graph`,
    ),

  listEvidence: (linkedIncidentId?: string) => {
    const q = linkedIncidentId
      ? `?linked_incident_id=${encodeURIComponent(linkedIncidentId)}`
      : "";
    return request<EvidenceFile[]>(`/evidence${q}`);
  },

  getEvidence: (evidenceId: string) =>
    request<EvidenceFile>(`/evidence/${encodeURIComponent(evidenceId)}`),

  uploadEvidence: (input: {
    file: File;
    evidenceType: string;
    sourceSystem?: string;
    linkedIncidentId?: string;
  }) => {
    const body = new FormData();
    body.append("file", input.file);
    body.append("evidence_type", input.evidenceType);
    if (input.sourceSystem?.trim()) {
      body.append("source_system", input.sourceSystem.trim());
    }
    if (input.linkedIncidentId?.trim()) {
      body.append("linked_incident_id", input.linkedIncidentId.trim());
    }
    return request<EvidenceUploadResponse>("/evidence/upload", {
      method: "POST",
      body,
    });
  },

  listLlmReports: (incidentId: string) =>
    request<{ reports: LlmReportSummary[]; total: number }>(
      `/incidents/${encodeURIComponent(incidentId)}/llm-reports`,
    ),

  listReviews: (incidentId: string) =>
    request<{ reviews: ReviewDecision[]; total: number }>(
      `/incidents/${encodeURIComponent(incidentId)}/reviews`,
    ),

  listAuditLogs: (incidentId: string) =>
    request<{ logs: AuditLog[]; total: number }>(
      `/audit-logs?incident_id=${encodeURIComponent(incidentId)}`,
    ),

  listAllAuditLogs: (limit = 50) =>
    request<{ logs: AuditLog[]; total: number }>(`/audit-logs?limit=${limit}`),

  listFixVerifications: (incidentId: string) =>
    request<{ verifications: FixVerification[]; total: number }>(
      `/incidents/${encodeURIComponent(incidentId)}/fix-verifications`,
    ),

  generateReport: (incidentId: string, reportType: "json" | "html") =>
    request<{
      report_id: number;
      content: Record<string, unknown>;
      html_document?: string | null;
    }>(`/reports/incidents/${encodeURIComponent(incidentId)}/generate`, {
      method: "POST",
      body: JSON.stringify({ report_type: reportType }),
    }),

  listReports: (incidentId: string) =>
    request<{ reports: IncidentReportSummary[]; total: number }>(
      `/reports/incidents/${encodeURIComponent(incidentId)}`,
    ),

  getEvaluationMetrics: (scenarioName = "scenario_1") =>
    request<{ metrics: EvaluationMetric[]; total: number; scenario_name: string }>(
      `/metrics/evaluation?scenario_name=${encodeURIComponent(scenarioName)}`,
    ),

  runEvaluation: (scenarioName = "scenario_1") =>
    request<{ metrics: EvaluationMetric[]; metrics_computed: number }>(
      "/metrics/evaluation/run",
      {
        method: "POST",
        body: JSON.stringify({ scenario_name: scenarioName }),
      },
    ),

  getSecurityProfile: () => request<SecurityProfile>("/security/profile"),

  loadSampleEvidence: (scenario = "scenario_1") =>
    request<Record<string, unknown>>("/evidence/load-sample", {
      method: "POST",
      body: JSON.stringify({ scenario }),
    }),

  parseAllEvidence: (linkedIncidentId?: string) => {
    const q = linkedIncidentId
      ? `?linked_incident_id=${encodeURIComponent(linkedIncidentId)}`
      : "";
    return request<Record<string, unknown>>(`/evidence/parse-all${q}`, {
      method: "POST",
    });
  },

  detectAllEvidence: (linkedIncidentId?: string) => {
    const q = linkedIncidentId
      ? `?linked_incident_id=${encodeURIComponent(linkedIncidentId)}`
      : "";
    return request<Record<string, unknown>>(`/evidence/detect-all${q}`, {
      method: "POST",
    });
  },

  analyseIncident: (incidentId?: string, force = false) =>
    request<Record<string, unknown>>("/incidents/analyse", {
      method: "POST",
      body: JSON.stringify({ incident_id: incidentId, force }),
    }),

  explainIncident: (incidentId: string, forceTemplate = true) =>
    request<Record<string, unknown>>(
      `/incidents/${encodeURIComponent(incidentId)}/explain`,
      {
        method: "POST",
        body: JSON.stringify({ force_template: forceTemplate }),
      },
    ),

  submitReview: (
    incidentId: string,
    decisionOrPayload: ReviewDecisionValue | SubmitReviewPayload,
    legacyComment?: string,
  ) => {
    const payload: SubmitReviewPayload =
      typeof decisionOrPayload === "string"
        ? {
            decision: decisionOrPayload,
            reason: legacyComment ?? "Human review decision recorded.",
            comment: legacyComment,
          }
        : decisionOrPayload;
    return (
    request<Record<string, unknown>>(
      `/incidents/${encodeURIComponent(incidentId)}/review`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ));
  },

  getReviewDraft: (incidentId: string) =>
    request<ReviewDraft | null>(
      `/incidents/${encodeURIComponent(incidentId)}/review-draft`,
    ),

  saveReviewDraft: (
    incidentId: string,
    payload: Omit<ReviewDraft, "incident_id" | "last_updated_by" | "last_updated_at">,
  ) =>
    request<ReviewDraft>(
      `/incidents/${encodeURIComponent(incidentId)}/review-draft`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),

  deleteReviewDraft: (incidentId: string) =>
    request<void>(`/incidents/${encodeURIComponent(incidentId)}/review-draft`, {
      method: "DELETE",
    }),

  listRemediationActions: (incidentId: string) =>
    request<{ remediation_actions: RemediationAction[]; total: number }>(
      `/incidents/${encodeURIComponent(incidentId)}/remediation-actions`,
    ),

  createRemediationAction: (incidentId: string, payload: RemediationActionInput) =>
    request<RemediationAction>(
      `/incidents/${encodeURIComponent(incidentId)}/remediation-actions`,
      { method: "POST", body: JSON.stringify(payload) },
    ),

  updateRemediationAction: (
    remediationActionId: string,
    payload: Partial<RemediationActionInput>,
  ) =>
    request<RemediationAction>(
      `/remediation-actions/${encodeURIComponent(remediationActionId)}`,
      { method: "PATCH", body: JSON.stringify(payload) },
    ),

  verifyFix: (incidentId: string, retestEvidenceIds?: string[]) =>
    request<Record<string, unknown>>(
      `/incidents/${encodeURIComponent(incidentId)}/verify-fix`,
      {
        method: "POST",
        body: JSON.stringify({ retest_evidence_ids: retestEvidenceIds }),
      },
    ),
};

export interface SecurityProfile {
  security_profile: string;
  crypto_mode_enabled: boolean;
  active_key_id: string;
  symmetric_algorithm: string;
  key_wrap_algorithm: string;
  jwt_signing: string;
  jwt_asymmetric_enabled: boolean;
  password_hash_algorithm: string;
  nist_csf_functions: string[];
  nist_sp_documents_referenced: string[];
  compliance_note: string;
  fips_aware_note: string;
}
