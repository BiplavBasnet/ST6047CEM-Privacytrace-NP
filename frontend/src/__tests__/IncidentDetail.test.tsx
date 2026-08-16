import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as client from "../api/client";
import { liveMonitorApi } from "../api/liveMonitorClient";
import IncidentDetailPage from "../pages/IncidentDetailPage";
import { mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/aiRemediationClient", () => ({
  aiRemediationApi: {
    getStatus: vi.fn().mockResolvedValue({
      enabled: false,
      provider_configured: false,
      model: null,
      safety_gateway_enabled: true,
      message: "AI Remediation Assistant is disabled.",
    }),
    listByIncident: vi.fn().mockResolvedValue({
      incident_id: "INC-TEST-001",
      suggestions: [],
      total: 0,
    }),
    suggest: vi.fn(),
    accept: vi.fn(),
    edit: vi.fn(),
    reject: vi.fn(),
    getCurrentDiagnosis: vi.fn().mockRejectedValue(new Error("No current diagnosis")),
  },
}));

const incident = {
  incident_id: "INC-TEST-001",
  title: "Possible privacy exposure in payment-gateway /api/v1/payments",
  affected_endpoint: "/api/v1/payments",
  affected_service: "payment-gateway",
  status: "investigating",
  severity: "high",
  summary: "Masked sensitive values require human review.",
  first_seen: "2026-07-14T10:00:00Z",
  last_seen: "2026-07-14T10:05:00Z",
  root_cause_scores: [
    {
      rank: 1,
      likely_root_cause: "logging_misconfiguration",
      confidence_band: "medium",
      confidence: 0.68,
      recommended_fix: "Review redaction controls",
      supporting_evidence_ids: ["EVD-MASKED-001"],
      missing_evidence: ["deployment metadata"],
    },
  ],
};

const stages: client.WorkflowStage[] = [
  { code: "overview", label: "Overview", status: "complete", available: true, completed: true, blocked_reason: null },
  { code: "root_cause", label: "Root Cause & Traceability", status: "complete", available: true, completed: true, blocked_reason: null },
  { code: "human_review", label: "Human Review", status: "ready", available: true, completed: false, blocked_reason: null },
  { code: "remediation", label: "Remediation", status: "blocked", available: false, completed: false, blocked_reason: "Approved human review required." },
  { code: "fix_verification", label: "Fix Verification", status: "blocked", available: false, completed: false, blocked_reason: "A remediation action and retest evidence are required." },
  { code: "final_report", label: "Final Report", status: "ready", available: true, completed: false, blocked_reason: null },
];

const workflow: client.IncidentWorkflowState = {
  incident_id: "INC-TEST-001",
  current_stage: "human_review",
  overall_status: "awaiting_human_review",
  next_action: {
    code: "complete_human_review",
    label: "Complete Human Review",
    description: "Record a structured decision using masked evidence.",
    target: "/incidents/INC-TEST-001/review",
    priority: "high",
    blocked: false,
    blocked_reason: null,
  },
  stages,
};

const rootStrength: client.RootCauseEvidenceStrength = {
  incident_id: "INC-TEST-001",
  likely_root_cause: "logging_misconfiguration",
  root_cause_category: "logging",
  confidence_level: "medium",
  confidence_score: 0.68,
  evidence_strength_level: "medium",
  evidence_strength_score: 0.61,
  evidence_strength_reason: "Masked runtime and timeline evidence support this ranking.",
  confidence_cap: "medium",
  confidence_cap_score: 0.69,
  confidence_cap_reason: "Deployment metadata is still missing.",
  supporting_evidence: [
    {
      evidence_id: "EVD-MASKED-001",
      evidence_type: "api_log",
      evidence_role: "technical_cause",
      safe_summary: "A masked phone marker appeared after logging middleware.",
      support_reason: "The event is linked by service and endpoint.",
      source: "gateway",
      event_time: "2026-07-14T10:00:00Z",
    },
  ],
  contradicting_evidence: [],
  symptom_evidence_count: 1,
  timeline_evidence_count: 1,
  technical_evidence_count: 1,
  remediation_evidence_count: 0,
  verification_evidence_count: 0,
  matched_signals: [{ signal: "service_endpoint_match" }],
  negative_signals: [],
  contradiction_signals: [],
  missing_evidence: ["deployment metadata"],
  recommended_next_evidence: ["Import deployment metadata"],
  human_review_required: true,
  limitations: ["The ranking remains a likely cause pending human review."],
};

const readiness: client.ReportReadiness = {
  incident_id: "INC-TEST-001",
  report_ready: false,
  draft_report_available: true,
  report_label: "Draft investigation report - workflow incomplete",
  checks: {
    incident_summary_ready: true,
    root_cause_available: true,
    human_review_recorded: false,
    remediation_recorded: false,
    retest_evidence_available: false,
    fix_verification_available: false,
    limitations_available: true,
  },
  blocking_items: ["Human review is required."],
  warning_items: ["The report retains an incomplete-stage label."],
};

const trace = {
  incident_id: "INC-TEST-001",
  title: incident.title,
  status: "investigating",
  affected_service: "payment-gateway",
  affected_endpoint: "/api/v1/payments",
  detection_count: 1,
  evidence_count: 1,
  timeline: [{ detections: [{ detection_id: "DET-1", sensitive_type: "phone", masked_value: "984****567" }] }],
  likely_root_causes: [],
  missing_evidence: ["deployment metadata"],
  human_review_required: true,
  disclaimer: "Hypothesis support only.",
};

function setupApi(overrides: Partial<{
  workflow: client.IncidentWorkflowState;
  readiness: client.ReportReadiness;
  remediationActions: client.RemediationAction[];
}> = {}) {
  vi.spyOn(client.api, "getIncident").mockResolvedValue(incident);
  vi.spyOn(client.api, "getWorkflowState").mockResolvedValue(overrides.workflow ?? workflow);
  vi.spyOn(client.api, "getRootCauseEvidenceStrength").mockResolvedValue(rootStrength);
  vi.spyOn(client.api, "getReportReadiness").mockResolvedValue(overrides.readiness ?? readiness);
  vi.spyOn(client.api, "listRemediationActions").mockResolvedValue({
    remediation_actions: overrides.remediationActions ?? [],
    total: overrides.remediationActions?.length ?? 0,
  });
  vi.spyOn(client.api, "getIncidentTrace").mockResolvedValue(trace);
  vi.spyOn(client.api, "listEvidence").mockResolvedValue([
    { evidence_id: "EVD-MASKED-001", evidence_type: "api_log", source_system: "gateway", parsing_status: "parsed", file_hash: "sha256-safe", linked_incident_id: "INC-TEST-001" },
  ]);
  vi.spyOn(client.api, "listReviews").mockResolvedValue({ reviews: [], total: 0 });
  vi.spyOn(client.api, "listAuditLogs").mockResolvedValue({ logs: [], total: 0 });
  vi.spyOn(client.api, "listFixVerifications").mockResolvedValue({ verifications: [], total: 0 });
  vi.spyOn(client.api, "listReports").mockResolvedValue({ reports: [], total: 0 });
  vi.spyOn(client.api, "getIncidentEvidenceGraph").mockResolvedValue({
    incident_id: "INC-TEST-001",
    nodes: [],
    edges: [],
    disclaimer: "Evidence relationships support review only.",
  });
  vi.spyOn(liveMonitorApi, "listAlerts").mockResolvedValue({ alerts: [], total: 0 });
}

function renderStage(stage: string) {
  return render(
    <MemoryRouter initialEntries={[`/incidents/INC-TEST-001/${stage}`]}>
      <Routes>
        <Route path="/incidents/:incidentId/:stage" element={<IncidentDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("route-backed incident workspace", () => {
  beforeEach(() => {
    useAuthMock.mockReturnValue(mockUseAuth());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the six backend-supplied stages and only the selected stage", async () => {
    setupApi();
    renderStage("overview");

    const stepper = await screen.findByTestId("incident-workspace-steps");
    for (const label of ["1. Overview", "2. Likely Cause", "3. Review", "4. Remediation", "5. Verify Fix", "6. Report"]) {
      expect(within(stepper).getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByTestId("workflow-stage-panel")).toHaveAttribute("data-stage", "overview");
    expect(screen.getByText("What happened")).toBeInTheDocument();
    expect(screen.getByText("Where")).toBeInTheDocument();
    expect(screen.queryByText("Strongest Supporting Evidence")).not.toBeInTheDocument();
    expect(screen.getByText("Approved human review required.")).toBeInTheDocument();
  });

  it("uses backend evidence strength and keeps technical evidence collapsed", async () => {
    setupApi();
    renderStage("root-cause");

    expect(await screen.findByText("Strongest Supporting Evidence")).toBeInTheDocument();
    expect(screen.getByText(/Masked runtime and timeline evidence/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Technical" }));
    expect(screen.getByTestId("root-cause-technical-details")).toBeInTheDocument();
    expect(await screen.findByText("984****567")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("9841234567");
  });

  it("runs root-cause analysis from a ready workspace stage", async () => {
    const rootReadyWorkflow = {
      ...workflow,
      current_stage: "root_cause" as const,
      stages: stages.map((stage) => {
        if (stage.code === "root_cause") {
          return { ...stage, status: "ready" as const, completed: false };
        }
        if (stage.code === "human_review") {
          return {
            ...stage,
            status: "blocked" as const,
            available: false,
            blocked_reason: "Root Cause & Traceability must be completed first.",
          };
        }
        return stage;
      }),
    };
    setupApi({ workflow: rootReadyWorkflow });
    const analyse = vi.spyOn(client.api, "analyseIncident").mockResolvedValue({});
    renderStage("root-cause");

    fireEvent.click(await screen.findByRole("button", { name: "Run Root Cause Analysis" }));

    await waitFor(() => expect(analyse).toHaveBeenCalledWith("INC-TEST-001"));
  });

  it("does not offer a duplicate manual action before diagnosis acceptance", async () => {
    const remediationWorkflow = {
      ...workflow,
      current_stage: "remediation" as const,
      stages: stages.map((stage) => stage.code === "remediation"
        ? { ...stage, status: "ready" as const, available: true, blocked_reason: null }
        : stage),
    };
    setupApi({ workflow: remediationWorkflow });
    const create = vi.spyOn(client.api, "createRemediationAction").mockResolvedValue({} as client.RemediationAction);
    renderStage("remediation");

    await screen.findByTestId("remediation-action-panel");
    expect(screen.queryByRole("button", { name: "Save remediation action" })).not.toBeInTheDocument();
    expect(screen.getByText(/Accept the current diagnosis to create its single canonical remediation action/i)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });

  it("shows the exact controlled lifecycle and no verification control while blocked", async () => {
    setupApi();
    const verify = vi.spyOn(client.api, "verifyFix").mockResolvedValue({ verification_status: "passed" });
    renderStage("verification");

    expect(await screen.findByTestId("controlled-remediation-lifecycle")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Verify current controlled retest/i })).not.toBeInTheDocument();
    expect(verify).not.toHaveBeenCalled();
    expect(screen.getByText(/human-approved diagnosis action is required/i)).toBeInTheDocument();
    expect(screen.getByText(/demo-fixture sandbox capability only/i)).toBeInTheDocument();
  });

  it("renders backend report readiness without implying automatic closure", async () => {
    setupApi();
    renderStage("report");

    expect(await screen.findByText("Draft investigation report - workflow incomplete")).toBeInTheDocument();
    expect(screen.getByTestId("report-readiness")).toHaveTextContent("Human review recorded");
    expect(screen.getByText(/not performed automatically/i)).toBeInTheDocument();
  });

  it("renders neither raw sensitive values nor forbidden claims", async () => {
    setupApi();
    const { container } = renderStage("overview");
    await screen.findByTestId("workflow-stage-panel");
    const text = container.textContent?.toLowerCase() ?? "";
    for (const phrase of ["9841234567", "proven cause", "confirmed blame", "guaranteed cause", "guaranteed fixed", "attacker accessed data"]) {
      expect(text).not.toContain(phrase);
    }
  });
});
