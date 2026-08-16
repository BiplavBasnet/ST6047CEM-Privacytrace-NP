import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AIRemediationAssistantPanel from "../components/AIRemediationAssistantPanel";
import { ANALYST_USER, AUDITOR_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
const getStatus = vi.fn();
const listByIncident = vi.fn();
const suggest = vi.fn();
const accept = vi.fn();
const edit = vi.fn();
const reject = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/aiRemediationClient", () => ({
  aiRemediationApi: {
    getStatus: (...args: unknown[]) => getStatus(...args),
    listByIncident: (...args: unknown[]) => listByIncident(...args),
    suggest: (...args: unknown[]) => suggest(...args),
    accept: (...args: unknown[]) => accept(...args),
    edit: (...args: unknown[]) => edit(...args),
    reject: (...args: unknown[]) => reject(...args),
  },
}));

const SUGGESTION = {
  suggestion_id: "AIR-WF-001",
  incident_id: "INC-AI-001",
  requested_by_user_id: 2,
  requested_at: "2026-05-20T10:15:00Z",
  ai_provider: "mock",
  ai_model: "mock-remediation",
  input_safety_status: "safe_masked_input",
  output_safety_status: "safe_output",
  status: "generated",
  masked_input_summary_hash: "sha256:abc123",
  suggestion_summary: "Review wallet-service logging redaction.",
  likely_issue_area: "logging_and_redaction_controls",
  remediation_actions: ["Review request logging on the affected endpoint."],
  code_or_config_areas: ["logging middleware"],
  suggested_tests: ["Run retest evidence through detection."],
  retest_evidence_required: ["Masked retest logs"],
  limitations: ["Human review and fix verification are required."],
  human_review_required: true,
  reviewer_decision: null,
  reviewer_notes: null,
  accepted_as_remediation_action_id: null,
  created_at: "2026-05-20T10:15:00Z",
  updated_at: "2026-05-20T10:15:00Z",
};

function setup(user = ANALYST_USER) {
  useAuthMock.mockReturnValue(mockUseAuth(user));
  getStatus.mockResolvedValue({
    enabled: true,
    provider_configured: true,
    model: "mock-remediation",
    safety_gateway_enabled: true,
    message: "AI Remediation Assistant is enabled with safety gateway validation.",
  });
  listByIncident.mockResolvedValue({
    incident_id: "INC-AI-001",
    suggestions: [SUGGESTION],
    total: 1,
  });
  suggest.mockResolvedValue({ suggestion: SUGGESTION, message: "generated" });
  accept.mockResolvedValue({
    suggestion_id: SUGGESTION.suggestion_id,
    status: "converted_to_remediation_action",
    reviewer_decision: "accepted",
    accepted_as_remediation_action_id: "REM-AI-123",
    message: "AI suggestion accepted as advisory remediation guidance. Fix verification remains required.",
  });
  edit.mockResolvedValue({
    suggestion_id: SUGGESTION.suggestion_id,
    status: "edited_by_reviewer",
    reviewer_decision: "edited",
    accepted_as_remediation_action_id: null,
    message: "AI suggestion edited by reviewer. Human approval and retest evidence are still required.",
  });
  reject.mockResolvedValue({
    suggestion_id: SUGGESTION.suggestion_id,
    status: "rejected_by_reviewer",
    reviewer_decision: "rejected",
    accepted_as_remediation_action_id: null,
    message: "AI suggestion rejected. Incident workflow remains under human control.",
  });
}

describe("AI Remediation Assistant workflow UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("accepts a suggestion as an advisory remediation reference", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-WF-001")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Acceptance notes"), {
      target: { value: "Accepted using masked evidence only." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accept suggestion" }));
    await waitFor(() => expect(accept).toHaveBeenCalledWith("AIR-WF-001", "Accepted using masked evidence only.", true));
    expect(await screen.findByText(/Fix verification remains required/i)).toBeInTheDocument();
  });

  it("saves reviewer-edited remediation actions", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-WF-001")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Edited remediation actions"), {
      target: { value: "Update redaction middleware\nUpload masked retest evidence" },
    });
    fireEvent.change(screen.getByLabelText("Edit notes"), {
      target: { value: "Reviewer narrowed the action list." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save reviewer edit" }));
    await waitFor(() =>
      expect(edit).toHaveBeenCalledWith(
        "AIR-WF-001",
        ["Update redaction middleware", "Upload masked retest evidence"],
        "Reviewer narrowed the action list.",
      ),
    );
    expect(await screen.findByText(/edited by reviewer/i)).toBeInTheDocument();
  });

  it("rejects a suggestion with a reviewer reason", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-WF-001")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Rejection reason"), {
      target: { value: "Not specific enough for this incident." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Reject suggestion" }));
    await waitFor(() => expect(reject).toHaveBeenCalledWith("AIR-WF-001", "Not specific enough for this incident."));
    expect(await screen.findByText(/workflow remains under human control/i)).toBeInTheDocument();
  });

  it("shows auditor read-only state", async () => {
    setup(AUDITOR_USER);
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-WF-001")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Generate AI suggestion/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept suggestion" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot accept, edit, or reject/i)).toBeInTheDocument();
  });
});
