import { request } from "./client";

export interface PrivacyImpactFactor {
  id: number;
  factor_type: string;
  factor_code: string;
  factor_label: string;
  score_contribution: number;
  evidence_ids: string[];
  reason: string;
  source: string;
  review_status: string;
}

export interface PrivacyHarm {
  harm_id: string;
  harm_category: string;
  likelihood: number;
  magnitude: number;
  harm_score: number;
  evidence_ids: string[];
  explanation: string;
  uncertainty: string;
  recommended_mitigation: string;
}

export interface PrivacyImpactAssessment {
  assessment_id: string;
  incident_id: string;
  assessment_version: number;
  status: string;
  breach_severity_score: number;
  breach_severity_level: string;
  privacy_harm_score: number;
  privacy_harm_level: string;
  harm_likelihood: number;
  harm_magnitude: number;
  affected_subject_count: number | null;
  affected_subject_count_status: string;
  credential_exposure_present: boolean;
  public_exposure_present: boolean;
  external_access_confirmed: boolean;
  assessment_confidence: string;
  limitations: string[];
  data_categories: string[];
  reviewed_by: number | null;
  approved_by: number | null;
}

export interface PrivacyImpactResponse {
  assessment: PrivacyImpactAssessment | null;
  factors: PrivacyImpactFactor[];
  harms: PrivacyHarm[];
  history: PrivacyImpactAssessment[];
  methodology_notice: string;
}

export interface BreachAlert {
  alert_id: string;
  incident_id: string;
  assessment_id: string;
  alert_type: string;
  severity: string;
  status: string;
  title: string;
  summary: string;
  reason_codes: string[];
  affected_subject_count: number | null;
  credential_exposure_present: boolean;
  triggered_at: string;
  acknowledged_by: number | null;
  resolution_reason: string | null;
}

export interface AffectedSubject {
  subject_reference_id: string;
  incident_id: string;
  subject_reference: string;
  reference_method: string;
  resolution_status: string;
  affected_data_categories: string[];
  occurrence_count: number;
  credential_types: string[];
  notification_eligibility: string;
  created_at: string;
  resolved_at: string | null;
}

export interface ContainmentAction {
  containment_action_id: string;
  incident_id: string;
  affected_subject_reference_id: string | null;
  action_type: string;
  credential_type: string | null;
  status: string;
  reason: string;
  requires_approval: boolean;
  approved_by: number | null;
  executed_by: number | null;
  execution_reference: string | null;
  result_summary: string | null;
  failure_reason: string | null;
}

export interface CustomerNotification {
  notification_id: string;
  incident_id: string;
  assessment_id: string;
  affected_subject_reference_id: string;
  recommendation: string;
  reason_codes: string[];
  decision_rationale: string;
  status: string;
  draft_message: string;
  message_locale: string;
  created_by: number | null;
  approved_by: number | null;
  rejection_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeliveryStatus {
  notification: CustomerNotification;
  outbox: Array<{ outbox_id: string; channel: string; status: string; attempt_count: number; last_error_category: string | null }>;
  attempts: Array<{ delivery_attempt_id: string; attempt_number: number; status: string; error_category: string | null; attempted_at: string }>;
  sending_enabled: boolean;
}

const json = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

export const privacyResponseApi = {
  getImpact: (incidentId: string) => request<PrivacyImpactResponse>(`/incidents/${encodeURIComponent(incidentId)}/privacy-impact`),
  assess: (incidentId: string) => request<PrivacyImpactResponse>(`/incidents/${encodeURIComponent(incidentId)}/privacy-impact/assess`, json({})),
  reviewAssessment: (assessmentId: string, factorIds: number[]) => request<PrivacyImpactAssessment>(`/privacy-impact/${encodeURIComponent(assessmentId)}/review`, json({ decision: "accepted", reason: "Reviewed factor explanations and supporting evidence.", accepted_factor_ids: factorIds })),
  approveAssessment: (assessmentId: string) => request<PrivacyImpactAssessment>(`/privacy-impact/${encodeURIComponent(assessmentId)}/approve`, json({ reason: "Assessment methodology and reviewed factors are accepted." })),
  listAlerts: (incidentId: string) => request<{ alerts: BreachAlert[]; total: number }>(`/incidents/${encodeURIComponent(incidentId)}/alerts`),
  acknowledgeAlert: (alertId: string) => request<BreachAlert>(`/alerts/${encodeURIComponent(alertId)}/acknowledge`, { method: "POST" }),
  resolveAlert: (alertId: string, reason: string) => request<BreachAlert>(`/alerts/${encodeURIComponent(alertId)}/resolve`, json({ reason })),
  markFalsePositive: (alertId: string, reason: string) => request<BreachAlert>(`/alerts/${encodeURIComponent(alertId)}/mark-false-positive`, json({ reason })),
  listSubjects: (incidentId: string) => request<{ subjects: AffectedSubject[]; total: number }>(`/incidents/${encodeURIComponent(incidentId)}/affected-subjects`),
  listContainment: (incidentId: string) => request<{ actions: ContainmentAction[]; total: number }>(`/incidents/${encodeURIComponent(incidentId)}/containment-actions`),
  approveContainment: (actionId: string, reason: string) => request<ContainmentAction>(`/containment-actions/${encodeURIComponent(actionId)}/approve`, json({ reason })),
  executeContainment: (actionId: string, reason: string) => request<ContainmentAction>(`/containment-actions/${encodeURIComponent(actionId)}/execute`, json({ reason })),
  listNotifications: (incidentId: string) => request<{ notifications: CustomerNotification[]; total: number; sending_enabled: boolean }>(`/incidents/${encodeURIComponent(incidentId)}/customer-notifications`),
  draftNotification: (incidentId: string, subjectId: string) => request<CustomerNotification>(`/incidents/${encodeURIComponent(incidentId)}/customer-notifications/draft`, json({ affected_subject_reference_id: subjectId })),
  approveNotification: (notificationId: string, reason: string) => request<CustomerNotification>(`/customer-notifications/${encodeURIComponent(notificationId)}/approve`, json({ reason })),
  rejectNotification: (notificationId: string, reason: string) => request<CustomerNotification>(`/customer-notifications/${encodeURIComponent(notificationId)}/reject`, json({ reason })),
  queueNotification: (notificationId: string, channel: "email" | "webhook") => request(`/customer-notifications/${encodeURIComponent(notificationId)}/queue`, json({ channel })),
  deliveryStatus: (notificationId: string) => request<DeliveryStatus>(`/customer-notifications/${encodeURIComponent(notificationId)}/delivery-status`),
};
