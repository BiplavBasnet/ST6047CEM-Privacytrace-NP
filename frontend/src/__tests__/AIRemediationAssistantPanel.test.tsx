import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AIRemediationAssistantPanel from "../components/AIRemediationAssistantPanel";
import { ANALYST_USER, mockUseAuth } from "../test/authTestUtils";

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
  suggestion_id: "AIR-TEST-001",
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

function setup({ enabled = true, suggestions = [SUGGESTION] } = {}) {
  useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
  getStatus.mockResolvedValue({
    enabled,
    provider_configured: enabled,
    model: enabled ? "mock-remediation" : null,
    safety_gateway_enabled: true,
    message: enabled
      ? "AI Remediation Assistant is enabled with safety gateway validation."
      : "AI Remediation Assistant is disabled.",
  });
  listByIncident.mockResolvedValue({
    incident_id: "INC-AI-001",
    suggestions,
    total: suggestions.length,
  });
  suggest.mockResolvedValue({
    suggestion: SUGGESTION,
    message: "AI-generated remediation suggestion created. Human review and fix verification are required.",
  });
  accept.mockResolvedValue({
    suggestion_id: SUGGESTION.suggestion_id,
    status: "accepted_by_reviewer",
    reviewer_decision: "accepted",
    accepted_as_remediation_action_id: null,
    message: "AI suggestion accepted as advisory remediation guidance. Fix verification remains required.",
  });
}

describe("AIRemediationAssistantPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("renders status, safety notice, and masked suggestion detail", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);

    await waitFor(() => expect(screen.getByText("AIR-TEST-001")).toBeInTheDocument());
    expect(screen.getByText(/masked incident summaries only/i)).toBeInTheDocument();
    expect(screen.getByText("Review wallet-service logging redaction.")).toBeInTheDocument();
    expect(screen.getByText("safe_masked_input")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate AI suggestion/i })).toBeInTheDocument();
  });

  it("generates a suggestion only when backend status is ready", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByRole("button", { name: /Generate AI suggestion/i })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Generate AI suggestion/i }));
    await waitFor(() => expect(suggest).toHaveBeenCalledWith("INC-AI-001"));
    await waitFor(() => expect(screen.getAllByText(/Human review and fix verification are required/i).length).toBeGreaterThan(0));
  });

  it("disables generation when the assistant is disabled", async () => {
    setup({ enabled: false, suggestions: [] });
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    const button = await screen.findByRole("button", { name: /Generate AI suggestion/i });
    expect(button).toBeDisabled();
    expect(screen.getByText(/Generation is unavailable/i)).toBeInTheDocument();
  });
});
