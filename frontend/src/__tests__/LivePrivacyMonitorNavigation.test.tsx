import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Layout from "../components/Layout";
import LivePrivacyMonitorPage from "../pages/LivePrivacyMonitor";
import { ANALYST_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
const getStatus = vi.fn();
const listAlerts = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    getStatus: (...args: unknown[]) => getStatus(...args),
    listAlerts: (...args: unknown[]) => listAlerts(...args),
    sendTestEvent: vi.fn(),
    start: vi.fn(),
    stop: vi.fn(),
    createIncident: vi.fn(),
    getAlert: vi.fn(),
    dismissAlert: vi.fn(),
  },
}));

function setup(user = ANALYST_USER) {
  useAuthMock.mockReturnValue(mockUseAuth(user));
  getStatus.mockResolvedValue({
    running: true,
    mode: "http_ingestion",
    supported_input_modes: ["http_json"],
    last_event_received_at: null,
    alert_count: 0,
    last_alert_time: null,
    safety_status: "safe",
  });
  listAlerts.mockResolvedValue({ alerts: [], total: 0 });
}

describe("Live Privacy Monitor navigation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("shows navigation link for allowed role", () => {
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Live Monitor" })).toBeInTheDocument();
  });

  it("hides navigation link for viewer", () => {
    setup(VIEWER_USER);
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Live Monitor" })).not.toBeInTheDocument();
  });

  it("renders breadcrumb on live monitor page", async () => {
    render(
      <MemoryRouter initialEntries={["/live-monitor"]}>
        <Routes>
          <Route path="/live-monitor" element={<LivePrivacyMonitorPage />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Live Monitor").length).toBeGreaterThan(0));
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
  });
});
