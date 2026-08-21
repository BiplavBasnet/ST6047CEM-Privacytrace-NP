import type {
  AuditLog,
  EvidenceFile,
  FixVerification,
  IncidentDetail,
  IncidentReportSummary,
  IncidentTrace,
  IncidentWorkflowState,
  RemediationAction,
  ReportReadiness,
  ReviewDecision,
  RootCauseEvidenceStrength,
} from "../../api/client";
import type { LiveAlert } from "../../api/liveMonitorClient";
import type { RemediationLifecycle } from "../../api/remediationLifecycleClient";
import type { CurrentRemediationDiagnosis } from "../../api/aiRemediationClient";

export interface IncidentWorkspaceData {
  incident: IncidentDetail;
  workflow: IncidentWorkflowState;
  rootStrength: RootCauseEvidenceStrength;
  readiness: ReportReadiness;
  trace: IncidentTrace | null;
  evidence: EvidenceFile[];
  reviews: ReviewDecision[];
  auditLogs: AuditLog[];
  verifications: FixVerification[];
  reports: IncidentReportSummary[];
  remediationActions: RemediationAction[];
  remediationLifecycle: RemediationLifecycle | null;
  currentDiagnosis: CurrentRemediationDiagnosis | null;
  liveAlerts: LiveAlert[];
  evidenceGraph: {
    nodes: Record<string, unknown>[];
    edges: Record<string, unknown>[];
    disclaimer?: string;
  } | null;
}
