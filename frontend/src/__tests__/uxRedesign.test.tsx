import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import Breadcrumbs from "../components/Breadcrumbs";
import EmptyState from "../components/EmptyState";
import Layout from "../components/Layout";
import NotFoundState from "../components/NotFoundState";
import PageHeader from "../components/PageHeader";
import PermissionDenied from "../components/PermissionDenied";
import SectionNavigation from "../components/SectionNavigation";
import HomePage from "../pages/HomePage";
import { userFacingLabel } from "../utils/userFacing";
import { ADMIN_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/client", () => ({
  api: {
    getHealth: vi.fn().mockResolvedValue({
      status: "healthy",
      service: "privacytrace-np",
      database: "connected",
      version: "0.1.0",
    }),
    listIncidents: vi.fn().mockResolvedValue([]),
    getWorkflowState: vi.fn().mockResolvedValue({
      next_action: { label: "Continue investigation", blocked: false },
    }),
  },
}));

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    getStatus: vi.fn().mockResolvedValue({
      running: false,
      mode: "http_ingestion",
      supported_input_modes: ["http_json"],
      last_event_received_at: null,
      event_count: 0,
      alert_count: 0,
      last_alert_time: null,
      safety_status: "safe",
    }),
    listAlerts: vi.fn().mockResolvedValue({ alerts: [], total: 0 }),
  },
}));

const FORBIDDEN_WORDING = [
  /proven cause/i,
  /confirmed blame/i,
  /guaranteed cause/i,
  /definitely caused by/i,
  /developer fault/i,
  /guaranteed fixed/i,
  /confirmed BOLA/i,
  /confirmed IDOR/i,
  /attacker accessed data/i,
];

describe("UX redesign", () => {
  it("dashboard is live-first and omits workflow-card clutter", async () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    const { container } = render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Privacy operations" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByTestId("status-card").length).toBeGreaterThanOrEqual(3));
    expect(screen.getByTestId("current-priority")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Open Live Monitor" }).length).toBeGreaterThan(0);
    expect(screen.queryByTestId("workflow-card")).not.toBeInTheDocument();
    expect(screen.queryByText(/Composite privacy risk/i)).not.toBeInTheDocument();
    expect(screen.getByText("No active incident.")).toBeInTheDocument();
    for (const pattern of FORBIDDEN_WORDING) {
      expect(container.textContent).not.toMatch(pattern);
    }
  });

  it("dashboard shows compact empty alert and incident states", async () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No live alerts.")).toBeInTheDocument(),
    );
    expect(screen.getByText("No active incident.")).toBeInTheDocument();
  });

  it("navigation is grouped with clear headings", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("Operations")).toBeInTheDocument();
    expect(screen.getByText("Data & sources")).toBeInTheDocument();
    expect(screen.getByText("Management")).toBeInTheDocument();
    expect(screen.getByText("Reference")).toBeInTheDocument();
    expect(screen.getByText("Help")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Guided Demo" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "User Guide" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Demo Guide" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "About" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reports" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit Logs" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Evidence Import" })).toBeInTheDocument();
  });

  it("viewer does not see governance links they lack permission for", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Audit Logs" }),
    ).not.toBeInTheDocument();
  });

  it("breadcrumbs render clickable previous levels", () => {
    render(
      <MemoryRouter>
        <Breadcrumbs
          items={[
            { label: "Dashboard", to: "/" },
            { label: "Incidents", to: "/incidents" },
            { label: "INC-001" },
          ]}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Incidents" })).toBeInTheDocument();
    expect(screen.getByText("INC-001")).toBeInTheDocument();
  });

  it("page header shows back button", () => {
    render(
      <MemoryRouter>
        <PageHeader
          title="Incidents"
          description="All incidents."
          backTo="/"
          backLabel="Back to Dashboard"
        />
      </MemoryRouter>,
    );
    expect(
      screen.getByRole("link", { name: /Back to Dashboard/ }),
    ).toBeInTheDocument();
  });

  it("page header omits back when breadcrumbs exist", () => {
    render(
      <MemoryRouter>
        <PageHeader
          breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Incidents" }]}
          title="Incidents"
          backTo="/"
          backLabel="Back to Dashboard"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: /Back to Dashboard/ })).not.toBeInTheDocument();
  });

  it("section navigation renders previous, next and overview targets", () => {
    render(
      <MemoryRouter>
        <SectionNavigation
          previous={{ label: "Overview", to: "#overview" }}
          next={{ label: "Evidence Chain", to: "#evidence-chain" }}
          overview={{ label: "Return to Overview", to: "#overview" }}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/← Overview/)).toBeInTheDocument();
    expect(screen.getByText(/Evidence Chain →/)).toBeInTheDocument();
    expect(screen.getByText("Return to Overview")).toBeInTheDocument();
  });

  it("not-found state offers a way back", () => {
    render(
      <MemoryRouter>
        <NotFoundState
          title="Incident not found"
          description="We could not find this incident."
          backTo="/incidents"
          backLabel="Back to Incidents"
        />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("not-found-state")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to Incidents" }),
    ).toBeInTheDocument();
  });

  it("permission denied state names the current role and offers a return", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <PermissionDenied requiredHint="security analyst or admin" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("permission-denied")).toBeInTheDocument();
    expect(
      screen.getByText(/do not have permission to perform this action/),
    ).toBeInTheDocument();
    expect(screen.getByText(/security analyst or admin/)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Return to Dashboard" }),
    ).toBeInTheDocument();
  });

  it("empty state renders title, description and action", () => {
    render(
      <MemoryRouter>
        <EmptyState
          title="No incidents found."
          description="Load demo evidence to begin."
          action={<a href="/wizard">Start</a>}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText("No incidents found.")).toBeInTheDocument();
    expect(screen.getByText("Load demo evidence to begin.")).toBeInTheDocument();
  });

  it("maps backend enums to user-facing labels", () => {
    expect(userFacingLabel("pending_verification")).toBe("Pending verification");
    expect(userFacingLabel("fix_verification")).toBe("Verify the fix");
    expect(userFacingLabel("linked_to_incident")).toBe("Linked to incident");
  });
});
