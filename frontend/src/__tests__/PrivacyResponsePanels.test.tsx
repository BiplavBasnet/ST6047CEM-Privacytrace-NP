import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ContainmentPanel from "../components/incident/ContainmentPanel";
import CustomerNotificationPanel from "../components/incident/CustomerNotificationPanel";
import IncidentPrivacyResponseTabs from "../components/incident/IncidentPrivacyResponseTabs";
import { ADMIN_USER, ANALYST_USER, mockUseAuth } from "../test/authTestUtils";

const mocks = vi.hoisted(() => ({
  getImpact: vi.fn(),
  assess: vi.fn(),
  reviewAssessment: vi.fn(),
  approveAssessment: vi.fn(),
  listAlerts: vi.fn(),
  acknowledgeAlert: vi.fn(),
  markFalsePositive: vi.fn(),
  listSubjects: vi.fn(),
  listContainment: vi.fn(),
  approveContainment: vi.fn(),
  executeContainment: vi.fn(),
  listNotifications: vi.fn(),
  draftNotification: vi.fn(),
  approveNotification: vi.fn(),
  rejectNotification: vi.fn(),
  queueNotification: vi.fn(),
  deliveryStatus: vi.fn(),
  useAuth: vi.fn(),
}));

vi.mock("../context/AuthContext", () => ({ useAuth: () => mocks.useAuth() }));
vi.mock("../api/privacyResponseClient", () => ({
  privacyResponseApi: {
    getImpact: mocks.getImpact,
    assess: mocks.assess,
    reviewAssessment: mocks.reviewAssessment,
    approveAssessment: mocks.approveAssessment,
    listAlerts: mocks.listAlerts,
    acknowledgeAlert: mocks.acknowledgeAlert,
    markFalsePositive: mocks.markFalsePositive,
    listSubjects: mocks.listSubjects,
    listContainment: mocks.listContainment,
    approveContainment: mocks.approveContainment,
    executeContainment: mocks.executeContainment,
    listNotifications: mocks.listNotifications,
    draftNotification: mocks.draftNotification,
    approveNotification: mocks.approveNotification,
    rejectNotification: mocks.rejectNotification,
    queueNotification: mocks.queueNotification,
    deliveryStatus: mocks.deliveryStatus,
  },
}));

const incidentId = "INC-PRIVACY-001";
const rawSecret = "sk-synthetic-raw-secret-value";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.useAuth.mockReturnValue(mockUseAuth(ADMIN_USER));
  mocks.listSubjects.mockResolvedValue({ subjects: [], total: 0 });
});

describe("privacy response panels", () => {
  it("renders explainable severity and credential warning without raw values", async () => {
    mocks.getImpact.mockResolvedValue({
      assessment: {
        assessment_id: "PIA-001",
        incident_id: incidentId,
        assessment_version: 1,
        status: "reviewed",
        breach_severity_score: 4,
        breach_severity_level: "very_high",
        privacy_harm_score: 12,
        privacy_harm_level: "critical",
        harm_likelihood: 3,
        harm_magnitude: 4,
        affected_subject_count: 2,
        affected_subject_count_status: "estimated",
        credential_exposure_present: true,
        public_exposure_present: false,
        external_access_confirmed: false,
        assessment_confidence: "medium",
        limitations: ["Credential validity requires review."],
        data_categories: ["authentication_data"],
        reviewed_by: 2,
        approved_by: null,
      },
      factors: [{
        id: 1,
        factor_type: "circumstance",
        factor_code: "active_credential_exposure",
        factor_label: "Active credential exposure",
        score_contribution: 1,
        evidence_ids: ["DET-MASKED-001"],
        reason: "Masked evidence supports containment review.",
        source: "review_input",
        review_status: "accepted",
      }],
      harms: [],
      history: [],
      methodology_notice: "ENISA-inspired assessment support; not a legal determination.",
    });

    const { container } = render(<MemoryRouter><IncidentPrivacyResponseTabs incidentId={incidentId} /></MemoryRouter>);
    expect(await screen.findByText("very_high (4)")).toBeInTheDocument();
    expect(screen.getByText(/Credential exposure requires authorised containment review/)).toBeInTheDocument();
    expect(screen.getByText("Active credential exposure")).toBeInTheDocument();
    expect(container.textContent).not.toContain(rawSecret);
  });

  it("supports alert acknowledgement and validates false-positive reasons", async () => {
    mocks.useAuth.mockReturnValue(mockUseAuth(ANALYST_USER));
    mocks.getImpact.mockResolvedValue({ assessment: null, factors: [], harms: [], history: [], methodology_notice: "Assessment support only." });
    mocks.listAlerts.mockResolvedValue({ alerts: [{
      alert_id: "BRA-001",
      incident_id: incidentId,
      assessment_id: "PIA-001",
      alert_type: "customer_exposure",
      severity: "critical",
      status: "suspected",
      title: "Possible customer privacy exposure",
      summary: "Masked evidence requires review.",
      reason_codes: ["active_credential_exposure"],
      affected_subject_count: 1,
      credential_exposure_present: true,
      triggered_at: "2026-07-16T03:00:00Z",
      acknowledged_by: null,
      resolution_reason: null,
    }], total: 1 });
    mocks.acknowledgeAlert.mockResolvedValue({});

    render(<MemoryRouter><IncidentPrivacyResponseTabs incidentId={incidentId} /></MemoryRouter>);
    fireEvent.click(screen.getByRole("tab", { name: "Breach Alerts" }));
    expect(await screen.findByText("Possible customer privacy exposure")).toBeInTheDocument();
    const falsePositive = screen.getByRole("button", { name: "Mark false positive" });
    expect(falsePositive).toBeDisabled();
    fireEvent.change(screen.getByLabelText("False-positive reason for BRA-001"), { target: { value: "Reviewed synthetic false-positive evidence." } });
    expect(falsePositive).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(mocks.acknowledgeAlert).toHaveBeenCalledWith("BRA-001"));
  });

  it("renders containment approval only for an authorised role", async () => {
    mocks.listContainment.mockResolvedValue({ actions: [{
      containment_action_id: "CTA-001",
      incident_id: incidentId,
      affected_subject_reference_id: null,
      action_type: "rotate_api_key",
      credential_type: "api_key",
      status: "recommended",
      reason: "Credential exposure requires authorised containment review.",
      requires_approval: true,
      approved_by: null,
      executed_by: null,
      execution_reference: null,
      result_summary: null,
      failure_reason: null,
    }], total: 1 });
    render(<ContainmentPanel incidentId={incidentId} />);
    expect(await screen.findByText("rotate api key")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve containment" })).toBeDisabled();
  });

  it("shows disabled sending and a safe notification preview", async () => {
    mocks.listNotifications.mockResolvedValue({ notifications: [{
      notification_id: "NTF-001",
      incident_id: incidentId,
      assessment_id: "PIA-001",
      affected_subject_reference_id: "ASR-001",
      recommendation: "recommended",
      reason_codes: ["privacy_harm_high"],
      decision_rationale: "Reviewed assessment supports protective guidance.",
      status: "approved",
      draft_message: "Incident reference INC-PRIVACY-001. Contact support through the approved channel.",
      message_locale: "en",
      created_by: 2,
      approved_by: 1,
      rejection_reason: null,
      created_at: "2026-07-16T03:00:00Z",
      updated_at: "2026-07-16T03:05:00Z",
    }], total: 1, sending_enabled: false });

    const { container } = render(<CustomerNotificationPanel incidentId={incidentId} />);
    expect(await screen.findByText("External customer notification sending is disabled.")).toBeInTheDocument();
    expect(screen.getByText(/Incident reference INC-PRIVACY-001/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Queue email" })).toBeDisabled();
    expect(container.textContent).not.toContain(rawSecret);
  });
});
