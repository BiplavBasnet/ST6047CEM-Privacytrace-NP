import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ProblemSpecificRemediationPanel from "../components/ProblemSpecificRemediationPanel";

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    can: (perm: string) =>
      ["ai_remediation:generate", "ai_remediation:review", "ai_remediation:read"].includes(perm),
  }),
}));

const reviewDiagnosis = vi.fn();
vi.mock("../api/aiRemediationClient", () => ({
  aiRemediationApi: {
    diagnose: vi.fn(),
    reviewDiagnosis: (...args: unknown[]) => reviewDiagnosis(...args),
  },
}));

describe("ProblemSpecificRemediationPanel", () => {
  it("shows generate control and human-approval wording", () => {
    render(<ProblemSpecificRemediationPanel incidentId="INC-TEST" />);
    expect(screen.getByText(/Generate primary remediation/i)).toBeInTheDocument();
    expect(screen.getByText(/Human approval is required/i)).toBeInTheDocument();
  });

  it("resumes and reviews the persisted current diagnosis without regenerating", async () => {
    reviewDiagnosis.mockResolvedValue({ message: "Human remediation review recorded." });
    render(<ProblemSpecificRemediationPanel incidentId="INC-TEST" currentDiagnosisId="RDI-CURRENT" currentGenerationMode="playbook" chainStatus="current" currentDiagnosis={{
      diagnosis_id: "RDI-CURRENT",
      incident_id: "INC-TEST",
      root_cause_analysis_id: "RCA-1",
      review_decision_id: 1,
      generation_mode: "playbook",
      playbook_id: "privacytrace-playbook-v1", playbook_version: "1", model_provider: "deterministic_playbook", model_name: "privacytrace-playbook-v1", prompt_template_version: "problem-specific-v1", recommendation_policy_version: "playbook-v1",
      status: "awaiting_human_review",
      workflow_status: "current",
      problem_statement: "Unsafe request logging may expose a masked category.",
      diagnosis_confidence: "medium",
      exact_source_location_known: false,
      supporting_evidence_ids: [], contradicting_evidence_ids: [], limitations: [], alternative_remediations: [], proposed_change: null,
      exact_change_available: false,
      created_at: "2026-08-13T00:00:00Z",
      primary_remediation: {
        remediation_id: "REM-1", title: "Redact before logging", remediation_type: "request_body_redaction",
        exact_problem_addressed: "Unsafe request logging", affected_component: "request_logger",
        affected_file_if_known: null, affected_function_if_known: null, affected_configuration_if_known: null,
        recommended_change: "Redact sensitive fields before logging.", why_this_solution: "Targets the sink.",
        evidence_alignment: "Matches current evidence.", why_not_broader_fix: "Avoid unrelated changes.",
        expected_privacy_impact: "Reduces exposure.", operational_impact: "Low.", implementation_risk: "Low.",
        tests_required: ["Regression test"], retest_requirements: ["Controlled retest"], rollback_plan: "Revert change.",
        remediation_confidence: "medium", confidence_limitations: [], human_approval_required: true,
        exposure_location: "request_body",
      },
    }} />);
    expect(screen.queryByRole("button", { name: /Generate primary remediation/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(reviewDiagnosis).toHaveBeenCalledWith("RDI-CURRENT", "accept", "", true, null));
  });
});
