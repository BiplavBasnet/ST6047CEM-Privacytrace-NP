/**
 * Client helpers for the Phase 11.8 universal SIEM/SOC integration API.
 *
 * All response objects pass through `sanitizeObject` (inherited from
 * `request`/`authRequest`) so raw sensitive values can never reach
 * the UI. The frontend treats every export body as opaque text/JSON
 * and re-runs `sanitizeString` before rendering, as defence in depth.
 */
import { sanitizeObject } from "../utils/safety";
import { clearAuthToken, getAuthToken, notifySessionExpired } from "./authClient";
import { getApiBaseUrl, request } from "./client";

export const CONNECTOR_V1_EVENTS_PATH = "/integrations/connector/v1/events";
export const LEGACY_EVENTS_PATH = "/integrations/events";
export const CONNECTOR_PRIVACY_REJECTED = "CONNECTOR_PAYLOAD_PRIVACY_REJECTED";

export interface IntegrationFormatInfo {
  format_id: string;
  direction: string;
  title: string;
  description: string;
}

export interface IntegrationFormatsResponse {
  inbound: IntegrationFormatInfo[];
  outbound: IntegrationFormatInfo[];
}

export interface IntegrationEventIngestRequest {
  source_name: string;
  source_tool?: string;
  source_type?: string;
  source_format?: string;
  external_alert_id?: string;
  external_incident_id?: string;
  event_time?: string;
  service_name?: string;
  endpoint?: string;
  environment?: string;
  event_type?: string;
  sensitive_type?: string;
  masked_value?: string;
  severity?: string;
  confidence?: number;
  message?: string;
  evidence_reference?: string;
  source_ip?: string;
  destination_ip?: string;
  user_or_actor?: string;
  trace_id?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  linked_incident_id?: string;
  payload?: Record<string, unknown>;
}

export interface IntegrationEventSafeRead {
  integration_event_id: string;
  event_id: string;
  source_name: string;
  source_tool: string;
  source_type: string;
  source_format: string;
  external_alert_id: string | null;
  external_incident_id: string | null;
  event_time: string | null;
  received_at: string;
  service_name: string | null;
  endpoint: string | null;
  environment: string | null;
  event_type: string | null;
  sensitive_type: string | null;
  masked_value: string | null;
  severity: string | null;
  confidence: number | null;
  message: string | null;
  message_summary: string;
  evidence_reference: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  user_or_actor: string | null;
  trace_id: string | null;
  tags: string[];
  raw_payload_hash: string | null;
  safety_status: string;
  sensitive_types: string[];
  masked_values: string[];
  correlation_keys: Record<string, unknown>;
  linked_alert_id: string | null;
  linked_incident_id: string | null;
  missing_metadata: string[];
  recommendations: string[];
  correlation_strength: string;
  warning: string | null;
}

export interface IntegrationEventIngestResponse {
  status: string;
  integration_event_id?: string | null;
  safety_status: string;
  reason?: string | null;
  event?: IntegrationEventSafeRead | null;
  alert_created: boolean;
  alert_id?: string | null;
  missing_metadata: string[];
  recommendations: string[];
}

export interface IntegrationGatewayStatus {
  gateway_enabled: boolean;
  accepted_event_types: string[];
  last_event_received_at: string | null;
  source_name: string | null;
  events_received_count: number;
  alerts_created_count: number;
  latest_error: string | null;
  safety_status: string;
}

export interface IntegrationSchema {
  schema_version: string;
  endpoint: string;
  required_fields: string[];
  optional_fields: string[];
  accepted_source_types: string[];
  accepted_source_formats: string[];
  example: Record<string, unknown>;
}

export interface IntegrationSnippets {
  curl: string;
  python: string;
  node: string;
  docker_log_forwarder: string;
  generic_webhook: string;
  siem_alert_export: string;
}

export interface IntegrationToken {
  token_id: string;
  name: string;
  source_name: string;
  token_prefix: string;
  created_at: string;
  last_used_at: string | null;
  is_active: boolean;
}

export interface IntegrationTokenCreated extends IntegrationToken {
  token: string;
}

export interface IntegrationIncidentExportResponse {
  incident_id: string;
  format: string;
  content_type: string;
  /**
   * The export representation. Named `export_body` (not `body`) because
   * the global safety sanitizer strips fields literally called `body`
   * from API responses. The server has already validated this content,
   * and the UI re-runs `sanitizeString` before display.
   */
  export_body: string | Record<string, unknown>;
  generated_at: string;
}

export const SAFE_PAYLOAD_EXAMPLE: IntegrationEventIngestRequest = {
  source_name: "wallet-service",
  source_type: "api_log",
  source_format: "generic_json",
  environment: "staging",
  service_name: "wallet-service",
  endpoint: "/wallet/transfer",
  event_time: "2026-07-13T10:30:00Z",
  severity: "info",
  message: "Synthetic integration test event",
  metadata: {
    deployment_version: "v1.4.2",
    trace_id: "trace-demo-001",
  },
};

export interface ConnectorEventEnvelope {
  specversion: "1.0";
  id: string;
  source: string;
  type: string;
  time?: string;
  datacontenttype: "application/json";
  data: Record<string, string | number | null | undefined>;
}

export interface ConnectorIngestResponse {
  event_id?: string | null;
  status: "accepted" | "duplicate" | "rejected" | string;
  evidence_id?: string | null;
  alert_id?: string | null;
  incident_id?: string | null;
  reason?: string | null;
}

export type ConnectorCheck = "PASS" | "FAIL";

export interface ConnectorV1TestResult {
  httpStatus: number;
  body: ConnectorIngestResponse | null;
  usedMachineToken: boolean;
  checks: {
    authentication: ConnectorCheck;
    schema: ConnectorCheck;
    privacy: ConnectorCheck;
    receiver: ConnectorCheck;
    accepted: ConnectorCheck;
  };
}

export function connectorReceiverUrl(base = getApiBaseUrl()): string {
  return `${base.replace(/\/$/, "")}${CONNECTOR_V1_EVENTS_PATH}`;
}

export function isLocalDevBase(base = getApiBaseUrl()): boolean {
  try {
    const host = new URL(base).hostname;
    return host === "127.0.0.1" || host === "localhost";
  } catch {
    return false;
  }
}

export function syntheticConnectorEvent(
  type: string,
  data: ConnectorEventEnvelope["data"],
  source = "/privacytrace/integrations-ui",
): ConnectorEventEnvelope {
  const id =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? `ui-test-${crypto.randomUUID()}`
      : `ui-test-${Date.now()}`;
  return {
    specversion: "1.0",
    id,
    source,
    type,
    time: new Date().toISOString(),
    datacontenttype: "application/json",
    data,
  };
}

function checksFromStatus(
  httpStatus: number,
  body: ConnectorIngestResponse | null,
): ConnectorV1TestResult["checks"] {
  const fail = {
    authentication: "FAIL" as const,
    schema: "FAIL" as const,
    privacy: "FAIL" as const,
    receiver: "FAIL" as const,
    accepted: "FAIL" as const,
  };
  if (httpStatus === 401 || httpStatus === 403) return fail;
  if (httpStatus === 409) {
    return {
      authentication: "PASS",
      schema: "PASS",
      privacy: "PASS",
      receiver: "FAIL",
      accepted: "FAIL",
    };
  }
  if (httpStatus === 422 && body?.reason === CONNECTOR_PRIVACY_REJECTED) {
    return {
      authentication: "PASS",
      schema: "PASS",
      privacy: "FAIL",
      receiver: "PASS",
      accepted: "FAIL",
    };
  }
  if (httpStatus === 422) {
    return {
      authentication: "PASS",
      schema: "FAIL",
      privacy: "PASS",
      receiver: "PASS",
      accepted: "FAIL",
    };
  }
  if (httpStatus >= 200 && httpStatus < 300 && (body?.status === "accepted" || body?.status === "duplicate")) {
    return {
      authentication: "PASS",
      schema: "PASS",
      privacy: "PASS",
      receiver: "PASS",
      accepted: "PASS",
    };
  }
  return fail;
}

export const integrationsApi = {
  getStatus: () =>
    request<IntegrationGatewayStatus>("/integrations/status"),

  getSchema: () =>
    request<IntegrationSchema>("/integrations/schema"),

  getSnippets: () =>
    request<IntegrationSnippets>("/integrations/snippets"),

  listFormats: () =>
    request<IntegrationFormatsResponse>("/integrations/formats"),

  ingestEvent: (body: IntegrationEventIngestRequest) =>
    request<IntegrationEventIngestResponse>("/integrations/events", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  sendTestEvent: () =>
    request<IntegrationEventIngestResponse>("/integrations/test-event", {
      method: "POST",
    }),

  validateEvent: (body: IntegrationEventIngestRequest) =>
    request<{
      valid: boolean;
      detected_source_type: string;
      required_fields_missing: string[];
      safety_status: string;
      would_create_alert: boolean;
      missing_metadata: string[];
      recommendations: string[];
      reason: string | null;
    }>("/integrations/validate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listTokens: () =>
    request<{ tokens: IntegrationToken[]; total: number }>("/integrations/tokens"),

  createToken: (name: string, sourceName: string) =>
    request<IntegrationTokenCreated>("/integrations/tokens", {
      method: "POST",
      body: JSON.stringify({ name, source_name: sourceName }),
    }),

  revokeToken: (tokenId: string) =>
    request<{ token_id: string; is_active: boolean; message: string }>(
      `/integrations/tokens/${encodeURIComponent(tokenId)}`,
      { method: "DELETE" },
    ),

  getEvent: (integrationEventId: string) =>
    request<IntegrationEventSafeRead>(
      `/integrations/events/${encodeURIComponent(integrationEventId)}`,
    ),

  exportIncident: (incidentId: string, format: string) =>
    request<IntegrationIncidentExportResponse>(
      `/integrations/incidents/${encodeURIComponent(
        incidentId,
      )}/export?format=${encodeURIComponent(format)}`,
    ),

  listIncidentFormats: (incidentId: string) =>
    request<IntegrationFormatsResponse>(
      `/integrations/incidents/${encodeURIComponent(incidentId)}/formats`,
    ),

  ingestConnectorV1: async (
    body: ConnectorEventEnvelope,
    machineToken?: string,
  ): Promise<ConnectorV1TestResult> => {
    const usedMachineToken = Boolean(machineToken);
    const token = machineToken || getAuthToken();
    const response = await fetch(`${getApiBaseUrl()}${CONNECTOR_V1_EVENTS_PATH}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
    let parsed: ConnectorIngestResponse | null = null;
    try {
      parsed = sanitizeObject((await response.json()) as ConnectorIngestResponse);
    } catch {
      parsed = null;
    }
    if (!usedMachineToken && response.status === 401) {
      clearAuthToken();
      notifySessionExpired();
    }
    return {
      httpStatus: response.status,
      body: parsed,
      usedMachineToken,
      checks: checksFromStatus(response.status, parsed),
    };
  },
};
