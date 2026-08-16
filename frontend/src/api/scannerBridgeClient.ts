import { request } from "./client";

export const SCANNER_SOURCE_FORMATS = [
  "generic_secret_scanner_json",
  "external_secret_scanner_json",
  "gitleaks_json",
  "semgrep_sarif",
  "semgrep_json",
] as const;

export type ScannerSourceFormat = (typeof SCANNER_SOURCE_FORMATS)[number];

export interface ScannerPreviewFinding {
  detector_name: string | null;
  finding_type: string | null;
  masked_value: string | null;
  source_file: string | null;
  line_number: number | null;
  severity: string | null;
  confidence: number | null;
  verification_status: string | null;
  safety_status: string;
  repository: string | null;
  commit_id: string | null;
}

export interface ScannerPreviewResponse {
  detected_format: string;
  safe_preview_findings: ScannerPreviewFinding[];
  unsafe_item_count: number;
  warnings: string[];
  import_allowed: boolean;
  raw_payload_hash: string | null;
}

export interface ScannerImportResponse {
  status: string;
  imported_count: number;
  rejected_count: number;
  scanner_evidence_ids: string[];
  linked_incident_id: string | null;
  import_evidence_id: string | null;
  safety_warnings: string[];
  message: string;
}

export interface ScannerEvidenceSafeRead {
  scanner_evidence_id: string;
  source_format: string;
  scanner_category: string | null;
  finding_type: string | null;
  detector_name: string | null;
  verification_status: string | null;
  severity: string | null;
  confidence: number | null;
  causal_relevance_score: number | null;
  repository: string | null;
  source_file: string | null;
  line_number: number | null;
  commit_id: string | null;
  branch: string | null;
  masked_value: string | null;
  evidence_reference: string;
  linked_evidence_id: string | null;
  linked_incident_id: string | null;
  service_hint: string | null;
  endpoint_hint: string | null;
  release_version_hint: string | null;
  detected_at: string | null;
  imported_at: string | null;
  safety_status: string;
  raw_payload_hash: string | null;
  tags: string[];
  explanation: string | null;
  import_evidence_id: string | null;
}

export interface ScannerCorrelationItem {
  scanner_evidence_id: string;
  causal_relevance_score: number;
  detector_name: string | null;
  masked_value: string | null;
  source_file: string | null;
  explanation: string | null;
}

export interface ScannerCorrelationResponse {
  incident_id: string;
  scanner_evidence_count: number;
  strong_supporting_evidence: ScannerCorrelationItem[];
  moderate_supporting_evidence: ScannerCorrelationItem[];
  weak_supporting_evidence: ScannerCorrelationItem[];
  top_scanner_evidence: ScannerCorrelationItem[];
  missing_context: string[];
  human_review_required: boolean;
  summary: string;
}

export interface ScannerImportBody {
  source_format: string;
  payload: unknown;
  linked_incident_id?: string;
  source_system?: string;
  service_hint?: string;
  endpoint_hint?: string;
  release_version_hint?: string;
}

export const scannerBridgeApi = {
  preview(body: ScannerImportBody) {
    return request<ScannerPreviewResponse>("/scanner-bridge/preview", {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  import(body: ScannerImportBody) {
    return request<ScannerImportResponse>("/scanner-bridge/import", {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  listEvidence(params?: {
    linked_incident_id?: string;
    source_format?: string;
    severity?: string;
  }) {
    const qs = new URLSearchParams();
    if (params?.linked_incident_id) qs.set("linked_incident_id", params.linked_incident_id);
    if (params?.source_format) qs.set("source_format", params.source_format);
    if (params?.severity) qs.set("severity", params.severity);
    const q = qs.toString();
    return request<ScannerEvidenceSafeRead[]>(
      `/scanner-bridge/evidence${q ? `?${q}` : ""}`,
    );
  },

  getEvidence(scannerEvidenceId: string) {
    return request<ScannerEvidenceSafeRead>(
      `/scanner-bridge/evidence/${encodeURIComponent(scannerEvidenceId)}`,
    );
  },

  linkEvidence(scannerEvidenceId: string, incidentId: string) {
    return request<ScannerEvidenceSafeRead>(
      `/scanner-bridge/evidence/${encodeURIComponent(scannerEvidenceId)}/link`,
      {
        method: "POST",
        body: JSON.stringify({ incident_id: incidentId }),
      },
    );
  },

  incidentEvidence(incidentId: string) {
    return request<ScannerEvidenceSafeRead[]>(
      `/scanner-bridge/incidents/${encodeURIComponent(incidentId)}/scanner-evidence`,
    );
  },

  correlate(incidentId: string) {
    return request<ScannerCorrelationResponse>(
      `/scanner-bridge/incidents/${encodeURIComponent(incidentId)}/correlate`,
      { method: "POST" },
    );
  },
};
