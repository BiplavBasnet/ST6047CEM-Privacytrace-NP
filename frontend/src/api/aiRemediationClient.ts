import { request } from "./client";

export interface AIRemediationStatus {
  enabled: boolean;
  provider_configured: boolean;
  model: string | null;
  safety_gateway_enabled: boolean;
  message: string;
}

export interface AIRemediationSuggestion {
  suggestion_id: string;
  incident_id: string;
  requested_by_user_id: number | null;
  requested_at: string;
  ai_provider: string | null;
  ai_model: string | null;
  input_safety_status: string;
  output_safety_status: string;
  status: string;
  masked_input_summary_hash: string;
  suggestion_summary: string | null;
  likely_issue_area: string | null;
  remediation_actions: string[];
  code_or_config_areas: string[];
  suggested_tests: string[];
  retest_evidence_required: string[];
  limitations: string[];
  human_review_required: boolean;
  reviewer_decision: string | null;
  reviewer_notes: string | null;
  accepted_as_remediation_action_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface AIRemediationSuggestionListResponse {
  incident_id: string;
  suggestions: AIRemediationSuggestion[];
  total: number;
}

export interface AIRemediationSuggestResponse {
  suggestion: AIRemediationSuggestion;
  message: string;
}

export interface AIRemediationDecisionResponse {
  suggestion_id: string;
  status: string;
  reviewer_decision: string;
  accepted_as_remediation_action_id: string | null;
  message: string;
}

export interface PrimaryRemediation {
  remediation_id: string;
  title: string;
  remediation_type: string;
  exact_problem_addressed: string;
  affected_component: string;
  affected_file_if_known: string | null;
  affected_function_if_known: string | null;
  affected_configuration_if_known: string | null;
  recommended_change: string;
  why_this_solution: string;
  evidence_alignment: string;
  why_not_broader_fix: string;
  expected_privacy_impact: string;
  operational_impact: string;
  implementation_risk: string;
  tests_required: string[];
  retest_requirements: string[];
  rollback_plan: string;
  remediation_confidence: string;
  confidence_limitations: string[];
  human_approval_required: boolean;
}

export interface ProblemSpecificRemediationResponse {
  diagnosis_id: string;
  generation_mode: "playbook" | "playbook_plus_ai" | "fallback_playbook";
  playbook_id: string;
  playbook_version: string;
  model_provider: string;
  model_name: string;
  ai_failure_type: string | null;
  source_claim_evidence_refs: string[];
  diagnosis: {
    incident_id: string;
    problem_statement: string;
    technical_mechanism: string;
    exposure_location: string | null;
    detected_sensitive_type: string | null;
    affected_component: string | null;
    affected_file_if_known: string | null;
    affected_function_if_known: string | null;
    exact_source_location_known: boolean;
    missing_evidence: string[];
    diagnosis_confidence: string;
    diagnosis_limitations: string[];
    human_review_required: boolean;
  };
  primary_remediation: PrimaryRemediation;
  alternative_remediations: PrimaryRemediation[];
  exact_change_available: boolean;
  proposed_change: {
    change_type: string;
    file_path: string;
    base_content_hash: string | null;
    change_summary: string;
    proposed_diff: string;
    expected_security_effect: string;
  } | null;
  tests: string[];
  retest_plan: Record<string, unknown>;
  rollback_plan: Record<string, unknown>;
  limitations: string[];
  human_approval_required: boolean;
}

export interface DiagnosisReviewResponse {
  diagnosis_id: string;
  status: string;
  reviewer_decision: string | null;
  remediation_action_id: string | null;
  message: string;
}

export interface CurrentRemediationDiagnosis {
  diagnosis_id: string;
  incident_id: string;
  root_cause_analysis_id: string | null;
  review_decision_id: number | null;
  generation_mode: string | null;
  playbook_id: string | null;
  playbook_version: string | null;
  model_provider: string | null;
  model_name: string | null;
  prompt_template_version: string | null;
  recommendation_policy_version: string | null;
  status: string;
  workflow_status: string;
  problem_statement: string;
  technical_mechanism?: string | null;
  affected_service?: string | null;
  affected_endpoint?: string | null;
  affected_component?: string | null;
  affected_file?: string | null;
  affected_function?: string | null;
  affected_configuration?: string | null;
  exact_source_location_known: boolean;
  missing_evidence?: string[];
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  limitations: string[];
  diagnosis_confidence: string;
  primary_remediation: PrimaryRemediation & { exposure_location?: string | null; source_type?: string | null };
  alternative_remediations: PrimaryRemediation[];
  proposed_change: ProblemSpecificRemediationResponse["proposed_change"];
  exact_change_available: boolean;
  created_at: string;
}

export const aiRemediationApi = {
  getStatus: () => request<AIRemediationStatus>("/ai-remediation/status"),

  suggest: (incidentId: string) =>
    request<AIRemediationSuggestResponse>(
      `/ai-remediation/incidents/${encodeURIComponent(incidentId)}/suggest`,
      { method: "POST", body: JSON.stringify({}) },
    ),

  diagnose: (incidentId: string) =>
    request<ProblemSpecificRemediationResponse>(
      `/ai-remediation/incidents/${encodeURIComponent(incidentId)}/diagnose`,
      { method: "POST", body: JSON.stringify({}) },
    ),

  getCurrentDiagnosis: (incidentId: string) =>
    request<CurrentRemediationDiagnosis>(
      `/ai-remediation/incidents/${encodeURIComponent(incidentId)}/diagnosis/current`,
    ),

  reviewDiagnosis: (
    diagnosisId: string,
    decision: string,
    notes: string,
    createRemediationAction: boolean,
    editedPrimary?: PrimaryRemediation | null,
  ) =>
    request<DiagnosisReviewResponse>(
      `/ai-remediation/diagnoses/${encodeURIComponent(diagnosisId)}/review`,
      {
        method: "POST",
        body: JSON.stringify({
          decision,
          notes: notes.trim() || null,
          create_remediation_action: createRemediationAction,
          edited_primary: editedPrimary ?? null,
        }),
      },
    ),

  listByIncident: (incidentId: string) =>
    request<AIRemediationSuggestionListResponse>(
      `/ai-remediation/incidents/${encodeURIComponent(incidentId)}/suggestions`,
    ),

  getSuggestion: (suggestionId: string) =>
    request<AIRemediationSuggestion>(
      `/ai-remediation/suggestions/${encodeURIComponent(suggestionId)}`,
    ),

  accept: (
    suggestionId: string,
    reviewerNotes: string,
    createRemediationAction: boolean,
  ) =>
    request<AIRemediationDecisionResponse>(
      `/ai-remediation/suggestions/${encodeURIComponent(suggestionId)}/accept`,
      {
        method: "POST",
        body: JSON.stringify({
          reviewer_notes: reviewerNotes.trim() || null,
          create_remediation_action: createRemediationAction,
        }),
      },
    ),

  edit: (suggestionId: string, editedRemediationActions: string[], reviewerNotes: string) =>
    request<AIRemediationDecisionResponse>(
      `/ai-remediation/suggestions/${encodeURIComponent(suggestionId)}/edit`,
      {
        method: "POST",
        body: JSON.stringify({
          edited_remediation_actions: editedRemediationActions,
          reviewer_notes: reviewerNotes.trim() || null,
        }),
      },
    ),

  reject: (suggestionId: string, reason: string) =>
    request<AIRemediationDecisionResponse>(
      `/ai-remediation/suggestions/${encodeURIComponent(suggestionId)}/reject`,
      {
        method: "POST",
        body: JSON.stringify({ reason: reason.trim() }),
      },
    ),
};
