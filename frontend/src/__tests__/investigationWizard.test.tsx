import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import InvestigationWizard, {
  wizardFixVerificationComplete,
} from "../pages/InvestigationWizard";
import { ANALYST_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

const getHealth = vi.fn();
const getSecurityProfile = vi.fn();
const loadSampleEvidence = vi.fn();
const verifyFix = vi.fn();
const getWorkflowState = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getHealth: (...args: unknown[]) => getHealth(...args),
    getSecurityProfile: (...args: unknown[]) => getSecurityProfile(...args),
    loadSampleEvidence: (...args: unknown[]) => loadSampleEvidence(...args),
    parseAllEvidence: vi.fn(),
    runDetection: vi.fn(),
    analyseIncident: vi.fn(),
    generateExplanation: vi.fn(),
    submitReview: vi.fn(),
    verifyFix: (...args: unknown[]) => verifyFix(...args),
    getWorkflowState: (...args: unknown[]) => getWorkflowState(...args),
    generateReport: vi.fn(),
    listIncidents: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock("../api/integrationsClient", () => ({
  integrationsApi: {
    exportIncident: vi.fn(),
  },
}));

describe("InvestigationWizard", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders all workflow step titles", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    expect(
      screen.getByText("Backend and security status check"),
    ).toBeInTheDocument();
    expect(screen.getByText("Load sample evidence (or upload your own)")).toBeInTheDocument();
    expect(screen.getByText("Parse evidence into normalized events")).toBeInTheDocument();
    expect(screen.getByText("Run sensitive-data detection")).toBeInTheDocument();
    expect(screen.getByText(/Export safe SOC summary/i)).toBeInTheDocument();
  });

  it("shows ready status on the first step", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    expect(screen.getAllByText("Ready").length).toBeGreaterThan(0);
  });

  it("displays next action panel for the first incomplete step", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Run "Status check" step/i)).toBeInTheDocument();
  });

  it("surfaces backend disconnected state on status check failure", async () => {
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    getHealth.mockRejectedValue(new Error("Network error"));
    render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Check status" }));
    await waitFor(() => {
      expect(screen.getByText("Failed")).toBeInTheDocument();
    });
    expect(screen.getByText(/Network error|Status check failed/i)).toBeInTheDocument();
  });

  it("shows permission limitation for viewer on restricted steps", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    expect(screen.getAllByText(/permission/i).length).toBeGreaterThan(0);
  });

  it("does not render raw JWT or passwords in the wizard", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    const { container } = render(
      <MemoryRouter>
        <InvestigationWizard />
      </MemoryRouter>,
    );
    expect(container.textContent).not.toMatch(/Bearer /);
    expect(container.textContent).not.toMatch(/AdminPass123!/);
    expect(container.textContent).not.toMatch(/eyJhbGci/);
  });

  it("does not treat a failed backend verification as wizard completion", () => {
    expect(wizardFixVerificationComplete("failed", false)).toBe(false);
    expect(wizardFixVerificationComplete("failed", true)).toBe(false);
    expect(wizardFixVerificationComplete("passed", false)).toBe(false);
    expect(wizardFixVerificationComplete("passed", true)).toBe(true);
  });
});
