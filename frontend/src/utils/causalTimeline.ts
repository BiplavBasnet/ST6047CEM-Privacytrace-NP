import type {
  AuditLog,
  EvidenceFile,
  FixVerification,
  IncidentReportSummary,
  IncidentTrace,
  LlmReportSummary,
  ReviewDecision,
  RootCauseScore,
} from "../api/client";

export type StageAvailability = "available" | "not_available";

export interface CausalTimelineStage {
  id: string;
  label: string;
  availability: StageAvailability;
  timestamp?: string;
}

export interface CausalTimelineInput {
  evidenceFiles: EvidenceFile[];
  trace: IncidentTrace | null;
  detections: Record<string, unknown>[];
  rootCauseScores: RootCauseScore[];
  llmReports: LlmReportSummary[];
  reviews: ReviewDecision[];
  verifications: FixVerification[];
  reports: IncidentReportSummary[];
  metricsAvailable: boolean;
  auditLogs: AuditLog[];
}

function auditTimestamp(logs: AuditLog[], action: string): string | undefined {
  return logs.find((log) => log.action === action)?.timestamp;
}

function earliestTimelineTimestamp(trace: IncidentTrace | null): string | undefined {
  if (!trace?.timeline?.length) return undefined;
  const stamps: string[] = [];
  for (const entry of trace.timeline) {
    if (!entry || typeof entry !== "object") continue;
    const ts = (entry as Record<string, unknown>).timestamp;
    if (typeof ts === "string" && ts) stamps.push(ts);
  }
  if (!stamps.length) return undefined;
  return stamps.sort()[0];
}

function latestReportTimestamp(reports: IncidentReportSummary[]): string | undefined {
  if (!reports.length) return undefined;
  const sorted = [...reports].sort((a, b) =>
    String(b.created_at).localeCompare(String(a.created_at)),
  );
  return sorted[0]?.created_at;
}

export function buildCausalTimeline(input: CausalTimelineInput): CausalTimelineStage[] {
  const {
    evidenceFiles,
    trace,
    detections,
    rootCauseScores,
    llmReports,
    reviews,
    verifications,
    reports,
    metricsAvailable,
    auditLogs,
  } = input;

  const hasEvidence = evidenceFiles.length > 0;
  const hasParsed = evidenceFiles.some((f) => f.parsing_status === "parsed");
  const hasDetections =
    (trace?.detection_count ?? 0) > 0 || detections.length > 0;
  const hasMasked = detections.some((d) => {
    const masked = d.masked_value;
    return typeof masked === "string" && masked.trim().length > 0;
  });
  const hasRanking =
    rootCauseScores.length > 0 || (trace?.likely_root_causes?.length ?? 0) > 0;
  const hasExplanation = llmReports.length > 0;
  const hasReview = reviews.length > 0;
  const hasFixVerification = verifications.length > 0;
  const hasReport = reports.length > 0;

  const eventTs = earliestTimelineTimestamp(trace);

  return [
    {
      id: "evidence_loaded",
      label: "Evidence loaded",
      availability: hasEvidence ? "available" : "not_available",
      timestamp: auditTimestamp(auditLogs, "evidence_uploaded") ?? eventTs,
    },
    {
      id: "evidence_parsed",
      label: "Evidence parsed",
      availability: hasParsed ? "available" : "not_available",
    },
    {
      id: "sensitive_detected",
      label: "Sensitive data detected",
      availability: hasDetections ? "available" : "not_available",
      timestamp:
        auditTimestamp(auditLogs, "detection_completed") ?? (hasDetections ? eventTs : undefined),
    },
    {
      id: "values_masked",
      label: "Values masked",
      availability: hasMasked ? "available" : "not_available",
      timestamp: hasMasked ? eventTs : undefined,
    },
    {
      id: "root_cause_ranked",
      label: "Likely root cause ranked",
      availability: hasRanking ? "available" : "not_available",
      timestamp: auditTimestamp(auditLogs, "incident_analysed"),
    },
    {
      id: "explanation_generated",
      label: "Guarded explanation generated",
      availability: hasExplanation ? "available" : "not_available",
      timestamp:
        llmReports[0]?.created_at ??
        auditTimestamp(auditLogs, "explanation_generated"),
    },
    {
      id: "human_review",
      label: "Human review completed",
      availability: hasReview ? "available" : "not_available",
      timestamp:
        reviews[0]?.timestamp ?? auditTimestamp(auditLogs, "review_submitted"),
    },
    {
      id: "fix_verification",
      label: "Fix verification completed",
      availability: hasFixVerification ? "available" : "not_available",
      timestamp:
        verifications[0]?.timestamp ??
        auditTimestamp(auditLogs, "fix_verification_completed"),
    },
    {
      id: "report_generated",
      label: "Report generated",
      availability: hasReport ? "available" : "not_available",
      timestamp:
        latestReportTimestamp(reports) ??
        auditTimestamp(auditLogs, "report_exported"),
    },
    {
      id: "metrics_generated",
      label: "Metrics generated",
      availability: metricsAvailable ? "available" : "not_available",
    },
  ];
}
