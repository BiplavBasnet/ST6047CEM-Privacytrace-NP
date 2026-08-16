import { request } from "./client";

export interface OperationalBreachAlert {
  alert_id: string;
  incident_id: string;
  severity: string;
  status: string;
  title: string;
  summary: string;
  reason_codes: string[];
  triggered_at: string;
  occurrence_count: number;
  assigned_team: string | null;
  escalation_level: string;
  suppression_reason: string | null;
  acknowledgement_deadline: string | null;
  containment_deadline: string | null;
  reopened_count: number;
  overdue: boolean;
}

export interface AlertMetrics {
  total_alerts: number;
  active_alerts: number;
  duplicate_alerts_prevented: number;
  suppressed_alerts: number;
  false_positive_alerts: number;
  unacknowledged_past_deadline: number;
  median_acknowledgement_seconds: number | null;
  median_containment_seconds: number | null;
  escalated_alerts: number;
  reopened_alerts: number;
  generated_at: string;
}

const post = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });
const id = encodeURIComponent;

export const alertOperationsApi = {
  list: () => request<{ alerts: OperationalBreachAlert[]; total: number }>("/breach-alerts"),
  metrics: () => request<AlertMetrics>("/alerts/metrics"),
  assign: (alertId: string, team: string, reason: string) => request(`/alerts/${id(alertId)}/assign`, post({ assigned_team: team, reason })),
  suppress: (alertId: string, reason: string) => request(`/alerts/${id(alertId)}/suppress`, post({ reason, privileged_override: false })),
  unsuppress: (alertId: string, reason: string) => request(`/alerts/${id(alertId)}/unsuppress`, post({ reason })),
  escalate: (alertId: string, reason: string) => request(`/alerts/${id(alertId)}/escalate`, post({ escalation_level: "incident_manager", reason })),
  reopen: (alertId: string, reason: string) => request(`/alerts/${id(alertId)}/reopen`, post({ reason })),
};
