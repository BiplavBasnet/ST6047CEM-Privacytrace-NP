import { request } from "./client";

export interface LiveMonitorStatus {
  running: boolean;
  mode: string;
  supported_input_modes: string[];
  last_event_received_at: string | null;
  event_count: number;
  alert_count: number;
  last_alert_time: string | null;
  safety_status: string;
}

export interface LiveMonitorControlResponse {
  status: string;
  message: string;
  running: boolean;
  safe_mode: boolean;
}

export interface LiveMonitorEventRequest {
  source_type: string;
  source_name?: string | null;
  source_format: string;
  service_name?: string | null;
  endpoint?: string | null;
  environment?: string | null;
  timestamp?: string | null;
  message: string;
  metadata?: Record<string, unknown>;
  payload?: Record<string, unknown> | null;
}

export interface LiveAlert {
  alert_id: string;
  alert_time: string;
  received_at: string;
  source_type: string;
  source_name: string | null;
  source_format: string;
  service_name: string | null;
  endpoint: string | null;
  environment: string | null;
  severity: string;
  status: string;
  sensitive_types: string[];
  masked_values: string[];
  detection_ids: string[];
  evidence_id: string | null;
  linked_incident_id: string | null;
  raw_event_hash: string;
  safety_status: string;
  alert_summary: string;
  human_review_required: boolean;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  repeat_count: number;
  ingestion_source: string;
  missing_metadata: string[];
  correlation_recommendations: string[];
  evidence_strength: string;
  alert_group_key?: string | null;
  exposure_location?: string | null;
  confidence_score?: number | null;
  confidence_level?: string | null;
}

export interface LiveMonitorEventResponse {
  status: string;
  safety_status: string;
  alert_id: string | null;
  alert: LiveAlert | null;
  sensitive_types: string[];
  masked_values: string[];
  raw_event_hash: string | null;
  reason: string | null;
  message: string;
}

export interface LiveAlertListResponse {
  alerts: LiveAlert[];
  total: number;
}

export interface LiveAlertIncidentResponse {
  alert_id: string;
  incident_id: string;
  status: string;
  message: string;
}

export interface LiveMonitorRetestResponse {
  incident_id: string;
  evidence_id: string;
  retest_source: string;
  service_endpoint_match: boolean;
  sensitive_value_still_appears: boolean;
  result: string;
  explanation: string;
  next_action: string;
}

export const liveMonitorApi = {
  getStatus: () => request<LiveMonitorStatus>("/live-monitor/status"),
  start: () =>
    request<LiveMonitorControlResponse>("/live-monitor/start", {
      method: "POST",
      body: JSON.stringify({
        mode: "http_ingestion",
        source_name: "wallet-service",
        environment: "demo",
        safe_mode: true,
      }),
    }),
  stop: () =>
    request<LiveMonitorControlResponse>("/live-monitor/stop", { method: "POST" }),
  sendTestEvent: () =>
    request<LiveMonitorEventResponse>("/live-monitor/test-event", { method: "POST" }),
  ingestEvent: (event: LiveMonitorEventRequest) =>
    request<LiveMonitorEventResponse>("/live-monitor/events", {
      method: "POST",
      body: JSON.stringify(event),
    }),
  listAlerts: (filters?: { linkedIncidentId?: string; limit?: number }) => {
    const params = new URLSearchParams({
      limit: String(filters?.limit ?? 50),
    });
    if (filters?.linkedIncidentId) {
      params.set("linked_incident_id", filters.linkedIncidentId);
    }
    return request<LiveAlertListResponse>(`/live-monitor/alerts?${params}`);
  },
  getAlert: (alertId: string) =>
    request<LiveAlert>(`/live-monitor/alerts/${encodeURIComponent(alertId)}`),
  createIncident: (alertId: string) =>
    request<LiveAlertIncidentResponse>(
      `/live-monitor/alerts/${encodeURIComponent(alertId)}/create-incident`,
      {
        method: "POST",
        body: JSON.stringify({ mode: "create_new" }),
      },
    ),
  linkIncident: (alertId: string, incidentId: string) =>
    request<LiveAlertIncidentResponse>(
      `/live-monitor/alerts/${encodeURIComponent(alertId)}/create-incident`,
      {
        method: "POST",
        body: JSON.stringify({
          mode: "link_existing",
          incident_id: incidentId,
        }),
      },
    ),
  dismissAlert: (alertId: string, reason = "Dismissed after human review") =>
    request<{ alert_id: string; status: string; message: string }>(
      `/live-monitor/alerts/${encodeURIComponent(alertId)}/dismiss`,
      {
        method: "POST",
        body: JSON.stringify({ reason }),
      },
    ),
  sendRetestEvent: (incidentId: string) =>
    request<LiveMonitorRetestResponse>(
      `/live-monitor/incidents/${encodeURIComponent(incidentId)}/retest-event`,
      { method: "POST", body: JSON.stringify({}) },
    ),
};
