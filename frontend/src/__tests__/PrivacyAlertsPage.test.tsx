import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PrivacyAlertsPage from "../pages/PrivacyAlertsPage";
import { ANALYST_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
const listAlerts = vi.fn();
const createIncident = vi.fn();
const linkIncident = vi.fn();
const dismissAlert = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    listAlerts: (...args: unknown[]) => listAlerts(...args),
    createIncident: (...args: unknown[]) => createIncident(...args),
    linkIncident: (...args: unknown[]) => linkIncident(...args),
    dismissAlert: (...args: unknown[]) => dismissAlert(...args),
  },
}));

const ALERT = {
  alert_id: "LPA-QUEUE-001",
  alert_time: "2026-07-13T10:00:00Z",
  received_at: "2026-07-13T10:00:01Z",
  first_seen: "2026-07-13T10:00:00Z",
  last_seen: "2026-07-13T10:00:01Z",
  repeat_count: 1,
  source_type: "api_log",
  source_name: "wallet-service",
  source_format: "generic_json",
  service_name: "wallet-service",
  endpoint: "/wallet/transfer",
  environment: "demo",
  severity: "high",
  status: "new",
  sensitive_types: ["nepal_phone"],
  masked_values: ["984****567"],
  detection_ids: [],
  evidence_id: null,
  linked_incident_id: null,
  raw_event_hash: "sha256:safe",
  safety_status: "safe",
  alert_summary: "Possible masked privacy exposure.",
  human_review_required: true,
  created_at: "2026-07-13T10:00:01Z",
  updated_at: "2026-07-13T10:00:01Z",
};

describe("Privacy Alerts queue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
    listAlerts.mockResolvedValue({ alerts: [ALERT], total: 1 });
    linkIncident.mockResolvedValue({
      alert_id: ALERT.alert_id,
      incident_id: "INC-SEED-001",
      status: "linked_to_incident",
      message: "linked",
    });
  });

  it("shows compact spec columns, filters, and never raw values", async () => {
    const { container } = render(
      <MemoryRouter>
        <PrivacyAlertsPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByRole("columnheader", { name: "Action" })).toBeInTheDocument());
    for (const column of ["Time", "Service", "Endpoint", "Severity", "Status", "Linked Incident", "Action"]) {
      expect(screen.getAllByText(column).length).toBeGreaterThan(0);
    }
    for (const filter of ["Status", "Severity", "Linked / Unlinked"]) {
      expect(screen.getAllByText(filter).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("More filters")).toBeInTheDocument();
    expect(screen.getAllByText("/wallet/transfer").length).toBeGreaterThan(0);
    // Safety: the raw phone number must never render in the queue.
    expect(container.textContent).not.toContain("9841234567");
  });

  it("opens an unlinked alert before one-click incident creation", async () => {
    render(
      <MemoryRouter initialEntries={["/alerts"]}>
        <Routes>
          <Route path="/alerts" element={<PrivacyAlertsPage />} />
          <Route path="/live-monitor" element={<div>Alert Detail LPA-QUEUE-001</div>} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByRole("columnheader", { name: "Action" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("link", { name: "Open Alert" }));
    expect(await screen.findByText("Alert Detail LPA-QUEUE-001")).toBeInTheDocument();
  });

  it("shows Open Incident for an already-linked alert", async () => {
    listAlerts.mockResolvedValue({
      alerts: [{ ...ALERT, linked_incident_id: "INC-SEED-001", status: "linked_to_incident" }],
      total: 1,
    });
    render(
      <MemoryRouter>
        <PrivacyAlertsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByRole("columnheader", { name: "Action" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Open Incident" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create Incident" })).not.toBeInTheDocument();
  });

  it("keeps service and endpoint filters in More filters", async () => {
    render(
      <MemoryRouter>
        <PrivacyAlertsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByRole("columnheader", { name: "Action" })).toBeInTheDocument());
    const more = screen.getByTestId("more-alert-filters");
    expect(more).not.toHaveAttribute("open");
    expect(screen.getByLabelText("Service")).toBeInTheDocument();
    expect(screen.getByLabelText("Endpoint")).toBeInTheDocument();
  });
});
