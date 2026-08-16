import { request } from "./client";

export interface BreachDecision {
  decision_id: string;
  decision_version: number;
  status: string;
  breach_determination: string;
  affected_data_categories: string[];
  input_evidence_ids: string[];
  missing_information: string[];
  uncertainties: string[];
  created_at: string;
}

export interface ProvenanceSummary {
  incident_id: string;
  status: string;
  evidence: Array<{ evidence_id: string; provenance_status: string; source_system: string | null }>;
  relationships: Array<{ relationship_id: string; relationship_type: string; validation_status: string }>;
}

export interface IntegrityStatus {
  scope_type: string;
  scope_id: string | null;
  status: string;
  last_verification: { verification_run_id: string; chain_valid: boolean; completed_at: string | null } | null;
  records: Array<{ integrity_record_id: string; record_type: string; verification_status: string }>;
  limitations: string[];
}

export interface CounterfactualAnalysis {
  analysis_id: string;
  root_cause_id: string;
  stability_level: string;
  fragile_conclusion: boolean;
  minimal_evidence_set: string[];
  missing_evidence_recommendations: string[];
  limitations: string[];
  test_results: Array<{ test_result_id: string; evidence_id: string | null; score_change: number; rank_changed: boolean; importance_level: string; explanation: string }>;
}

export interface TimelineEvent {
  id: string;
  event_type: string;
  lifecycle_stage: string;
  event_timestamp: string;
  time_status: string;
  summary: string;
  integrity_status: string;
}

export interface PreventiveControl {
  control_id: string;
  root_cause_id: string;
  control_type: string;
  control_name: string;
  control_description: string;
  status: string;
  source: string;
  requires_human_review: boolean;
  verification_status: string;
  implementation_reference: string | null;
}

export interface SensitiveClassification {
  classification_id: string | null;
  taxonomy_code: string;
  taxonomy_version: string | null;
  category_group: string | null;
  masked_value: string | null;
  document_type: string | null;
  credential_status: string | null;
  confidence_label: string | null;
  review_status: string | null;
  internal_only: boolean;
  customer_notification_allowed: boolean;
}

export interface ExposureProfile {
  profile_id: string;
  profile_type: string;
  severity: string;
  privacy_harm_level: string;
  internal_only: boolean;
  customer_notification_allowed: boolean;
  grouping_confidence: string;
  matched_rule_ids: string[];
  possible_harms: string[];
  containment_recommendations: string[];
  missing_information: string[];
  review_status: string;
}

const post = (body: unknown = {}): RequestInit => ({ method: "POST", body: JSON.stringify(body) });
const id = encodeURIComponent;

export const incidentGovernanceApi = {
  listDecisions: (incidentId: string) => request<{ decisions: BreachDecision[]; total: number }>(`/incidents/${id(incidentId)}/breach-decisions`),
  getDecisionDifferences: (decisionId: string) => request<Record<string, unknown>>(`/breach-decisions/${id(decisionId)}/differences`),
  listProvenance: (incidentId: string) => request<ProvenanceSummary>(`/incidents/${id(incidentId)}/provenance`),
  getIntegrity: (incidentId: string) => request<IntegrityStatus>(`/incidents/${id(incidentId)}/integrity`),
  verifyIntegrity: (incidentId: string) => request(`/incidents/${id(incidentId)}/integrity/verify`, post()),
  listCounterfactual: (incidentId: string) => request<{ analyses: CounterfactualAnalysis[]; total: number }>(`/incidents/${id(incidentId)}/counterfactual-analysis`),
  runCounterfactual: (incidentId: string, rootCauseId?: string) => request(`/incidents/${id(incidentId)}/counterfactual-analysis`, post({ root_cause_id: rootCauseId, max_evidence_items: 25 })),
  getTimeline: (incidentId: string) => request<{ events: TimelineEvent[]; total: number; limitations: string[] }>(`/incidents/${id(incidentId)}/timeline`),
  listPreventiveControls: (incidentId: string) => request<{ controls: PreventiveControl[]; total: number }>(`/incidents/${id(incidentId)}/preventive-controls`),
  generatePreventiveControls: (incidentId: string, rootCauseId: string) => request(`/incidents/${id(incidentId)}/preventive-controls/generate`, post({ root_cause_id: rootCauseId, control_types: [], use_ai: false })),
reviewPreventiveControl: (controlId: string, reason: string) => request(`/preventive-controls/${id(controlId)}/review`, post({ decision: "accepted", reason })),
  approvePreventiveControl: (controlId: string, reason: string) => request(`/preventive-controls/${id(controlId)}/approve`, post({ reason })),
  implementPreventiveControl: (controlId: string, reason: string) => request(`/preventive-controls/${id(controlId)}/mark-implemented`, post({ implementation_reference: "manual-reviewed-implementation", reason })),
  verifyPreventiveControl: (controlId: string, reason: string) => request(`/preventive-controls/${id(controlId)}/verify`, post({ verification_method: "reviewed retest", verification_result: reason, passed: true, retest_evidence_ids: [], reason })),
  retirePreventiveControl: (controlId: string, reason: string) => request(`/preventive-controls/${id(controlId)}/retire`, post({ reason })),
  listClassifications: (incidentId: string) => request<{ classifications: SensitiveClassification[]; total: number; restricted_information_present: boolean; restricted_message: string | null }>(`/incidents/${id(incidentId)}/sensitive-classifications`),
  listExposureProfiles: (incidentId: string) => request<{ profiles: ExposureProfile[]; total: number; restricted_information_present: boolean; restricted_message: string | null }>(`/incidents/${id(incidentId)}/exposure-profiles`),
  recalculateExposureProfiles: (incidentId: string) => request(`/incidents/${id(incidentId)}/exposure-profiles/recalculate`, post()),
};
