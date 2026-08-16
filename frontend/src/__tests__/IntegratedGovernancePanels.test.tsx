import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CounterfactualAnalysisPanel from "../components/incident/CounterfactualAnalysisPanel";
import IncidentDecisionTraceabilityPanel from "../components/incident/IncidentDecisionTraceabilityPanel";
import IncidentTimelinePanel from "../components/incident/IncidentTimelinePanel";
import NepalExposurePanel from "../components/incident/NepalExposurePanel";
import PreventiveControlsPanel from "../components/incident/PreventiveControlsPanel";
import { ADMIN_USER, mockUseAuth } from "../test/authTestUtils";

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(), listDecisions: vi.fn(), listProvenance: vi.fn(), getIntegrity: vi.fn(), verifyIntegrity: vi.fn(),
  listCounterfactual: vi.fn(), runCounterfactual: vi.fn(), getTimeline: vi.fn(), listPreventiveControls: vi.fn(),
  generatePreventiveControls: vi.fn(), reviewPreventiveControl: vi.fn(), approvePreventiveControl: vi.fn(),
  implementPreventiveControl: vi.fn(), verifyPreventiveControl: vi.fn(), retirePreventiveControl: vi.fn(),
  listExposureProfiles: vi.fn(), listClassifications: vi.fn(), recalculateExposureProfiles: vi.fn(),
}));

vi.mock("../context/AuthContext", () => ({ useAuth: () => mocks.useAuth() }));
vi.mock("../api/incidentGovernanceClient", () => ({ incidentGovernanceApi: mocks }));

const incidentId = "INC-GOV-001";
const rawSecret = "sk-synthetic-never-render";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.useAuth.mockReturnValue(mockUseAuth(ADMIN_USER));
  mocks.listDecisions.mockResolvedValue({ decisions: [{ decision_id: "BDR-001", decision_version: 2, status: "approved", breach_determination: "suspected", affected_data_categories: ["authentication_data"], input_evidence_ids: ["EVD-001"], missing_information: [], uncertainties: [], created_at: "2026-07-17T00:00:00Z" }], total: 1 });
  mocks.listProvenance.mockResolvedValue({ incident_id: incidentId, status: "partial", evidence: [{ evidence_id: "EVD-001", provenance_status: "verified", source_system: "synthetic" }], relationships: [] });
  mocks.getIntegrity.mockResolvedValue({ scope_type: "incident", scope_id: incidentId, status: "verified", last_verification: null, records: [{ integrity_record_id: "ILR-001", record_type: "decision", verification_status: "verified" }], limitations: [] });
  mocks.listCounterfactual.mockResolvedValue({ analyses: [], total: 0 });
  mocks.getTimeline.mockResolvedValue({ events: [], total: 0, limitations: [] });
  mocks.listPreventiveControls.mockResolvedValue({ controls: [], total: 0 });
  mocks.listExposureProfiles.mockResolvedValue({ profiles: [], total: 0, restricted_information_present: false, restricted_message: null });
  mocks.listClassifications.mockResolvedValue({ classifications: [], total: 0, restricted_information_present: false, restricted_message: null });
});

describe("integrated governance panels", () => {
  it("renders decision, provenance, and integrity without raw values", async () => {
    const { container } = render(<MemoryRouter><IncidentDecisionTraceabilityPanel incidentId={incidentId} /></MemoryRouter>);
    expect(await screen.findByText("Version 2")).toBeInTheDocument();
    expect(screen.getByText("1 evidence records")).toBeInTheDocument();
    expect(screen.getByText("1 ledger records")).toBeInTheDocument();
    expect(container.textContent).not.toContain(rawSecret);
  });

  it("shows fragile counterfactual conclusions and can rerun analysis", async () => {
    mocks.listCounterfactual.mockResolvedValue({ analyses: [{ analysis_id: "CFA-001", root_cause_id: "RCS-001", stability_level: "fragile", fragile_conclusion: true, minimal_evidence_set: ["EVD-001"], missing_evidence_recommendations: ["Independent deployment evidence"], limitations: [], test_results: [] }], total: 1 });
    render(<MemoryRouter><CounterfactualAnalysisPanel incidentId={incidentId} rootCauseId="RCS-001" /></MemoryRouter>);
    fireEvent.click(screen.getByText("Counterfactual stability analysis"));
    expect(await screen.findByText("fragile conclusion")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Run stability analysis" }));
    await waitFor(() => expect(mocks.runCounterfactual).toHaveBeenCalledWith(incidentId, "RCS-001"));
  });

  it("renders timeline integrity state and restricted exposure warning", async () => {
    mocks.getTimeline.mockResolvedValue({ events: [{ id: "T-1", event_type: "assessment", lifecycle_stage: "impact_assessment", event_timestamp: "2026-07-17T00:00:00Z", time_status: "estimated", summary: "Assessment recorded from masked evidence.", integrity_status: "not_yet_verified" }], total: 1, limitations: [] });
    mocks.listExposureProfiles.mockResolvedValue({ profiles: [], total: 0, restricted_information_present: true, restricted_message: "Restricted internal classifications are hidden for this role." });
    render(<MemoryRouter><IncidentTimelinePanel incidentId={incidentId} /><NepalExposurePanel incidentId={incidentId} /></MemoryRouter>);
    expect(await screen.findByText("Assessment recorded from masked evidence.")).toBeInTheDocument();
    expect(await screen.findByText("Restricted internal classifications are hidden for this role.")).toBeInTheDocument();
  });

  it("keeps preventive controls human-reviewed and non-deploying", async () => {
    mocks.listPreventiveControls.mockResolvedValue({ controls: [{ control_id: "CTL-001", root_cause_id: "RCS-001", control_type: "regression_test", control_name: "Masked response regression", control_description: "Reject unmasked credential fields.", status: "proposed", source: "deterministic_template", requires_human_review: true, verification_status: "not_started", implementation_reference: null }], total: 1 });
    render(<MemoryRouter><PreventiveControlsPanel incidentId={incidentId} rootCauseId="RCS-001" /></MemoryRouter>);
    expect(await screen.findByText("Masked response regression")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review" }));
    await waitFor(() => expect(mocks.reviewPreventiveControl).toHaveBeenCalled());
    expect(screen.getByText(/do not change production systems/i)).toBeInTheDocument();
  });
});
