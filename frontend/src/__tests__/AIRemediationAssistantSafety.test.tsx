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

const UNSAFE_FROM_API = {
  suggestion_id: "AIR-SAFE-001",
  incident_id: "INC-AI-001",
  requested_by_user_id: 2,
  requested_at: "2026-05-20T10:15:00Z",
  ai_provider: "mock",
  ai_model: "mock-remediation",
  input_safety_status: "safe_masked_input",
  output_safety_status: "safe_output",
  status: "generated",
  masked_input_summary_hash: "sha256:abc123",
  suggestion_summary: "phone 9841234567 is guaranteed fixed",
  likely_issue_area: "logging_and_redaction_controls",
  remediation_actions: ["Review request logging for WALLET-NP-88291."],
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

function setup() {
  useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
  getStatus.mockResolvedValue({
    enabled: true,
    provider_configured: true,
    model: "mock-remediation",
    safety_gateway_enabled: true,
    message: "AI Remediation Assistant is enabled with safety gateway validation.",
  });
  listByIncident.mockResolvedValue({
    incident_id: "INC-AI-001",
    suggestions: [UNSAFE_FROM_API],
    total: 1,
  });
  suggest.mockResolvedValue({ suggestion: UNSAFE_FROM_API, message: "generated" });
  accept.mockResolvedValue({
    suggestion_id: "AIR-SAFE-001",
    status: "accepted_by_reviewer",
    reviewer_decision: "accepted",
    accepted_as_remediation_action_id: null,
    message: "accepted",
  });
}

describe("AI Remediation Assistant safety UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("sanitizes raw values and unsafe claims before display", async () => {
    const { container } = render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-SAFE-001")).toBeInTheDocument());
    expect(container.textContent).not.toContain("9841234567");
    expect(container.textContent).not.toContain("WALLET-NP-88291");
    expect(container.textContent?.toLowerCase()).not.toContain("guaranteed fixed");
    expect(container.textContent).toContain("[blocked sensitive value]");
    expect(container.textContent).toContain("[blocked unsafe claim]");
  });

  it("blocks reviewer notes containing raw values or unsafe claims", async () => {
    render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-SAFE-001")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Acceptance notes"), {
      target: { value: "phone 9841234567 is the proven cause" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accept suggestion" }));
    expect(await screen.findByText(/Reviewer input was blocked/i)).toBeInTheDocument();
    expect(accept).not.toHaveBeenCalled();
  });

  it("does not display automatic closure or verification claims", async () => {
    const { container } = render(<AIRemediationAssistantPanel incidentId="INC-AI-001" />);
    await waitFor(() => expect(screen.getByText("AIR-SAFE-001")).toBeInTheDocument());
    const text = container.textContent?.toLowerCase() ?? "";
    for (const phrase of [
      "proven cause",
      "confirmed blame",
      "incident closed automatically",
      "ai solved the incident",
      "developer fault",
    ]) {
      expect(text).not.toContain(phrase);
    }
  });
});
