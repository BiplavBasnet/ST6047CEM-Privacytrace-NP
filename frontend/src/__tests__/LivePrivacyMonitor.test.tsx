import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LivePrivacyMonitorPage from "../pages/LivePrivacyMonitor";
import { ANALYST_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
const getStatus = vi.fn();
const listAlerts = vi.fn();
const sendTestEvent = vi.fn();
const start = vi.fn();
const stop = vi.fn();
const createIncident = vi.fn();
const getAlert = vi.fn();
const dismissAlert = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    getStatus: (...args: unknown[]) => getStatus(...args),
    listAlerts: (...args: unknown[]) => listAlerts(...args),
    sendTestEvent: (...args: unknown[]) => sendTestEvent(...args),
    start: (...args: unknown[]) => start(...args),
    stop: (...args: unknown[]) => stop(...args),
    createIncident: (...args: unknown[]) => createIncident(...args),
    getAlert: (...args: unknown[]) => getAlert(...args),
    dismissAlert: (...args: unknown[]) => dismissAlert(...args),
  },
}));

const ALERT = {
  alert_id: "LPA-TEST-001",
  alert_time: "2026-05-20T10:15:00Z",
  received_at: "2026-05-20T10:15:01Z",
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
  raw_event_hash: "sha256:abc123",
  safety_status: "safe",
  alert_summary: "Possible privacy exposure detected with masked value 984****567. Human review is required.",
  human_review_required: true,
  created_at: "2026-05-20T10:15:01Z",
  updated_at: "2026-05-20T10:15:01Z",
};

function setupMocks() {
  useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
  getStatus.mockResolvedValue({
    running: true,
    mode: "http_ingestion",
    supported_input_modes: ["http_json", "syslog_like_text"],
    last_event_received_at: "2026-05-20T10:15:01Z",
    alert_count: 1,
    last_alert_time: "2026-05-20T10:15:00Z",
    safety_status: "safe",
  });
  listAlerts.mockResolvedValue({ alerts: [ALERT], total: 1 });
  sendTestEvent.mockResolvedValue({
    status: "alert_created",
    safety_status: "safe",
    alert_id: ALERT.alert_id,
    alert: ALERT,
    sensitive_types: ["nepal_phone"],
    masked_values: ["984****567"],
    raw_event_hash: "sha256:abc123",
    reason: null,
    message: "Privacy alert created with masked values only. Human review is required.",
  });
  start.mockResolvedValue({ status: "started", message: "started", running: true, safe_mode: true });
  stop.mockResolvedValue({ status: "stopped", message: "stopped", running: false, safe_mode: true });
  createIncident.mockResolvedValue({ alert_id: ALERT.alert_id, incident_id: "INC-LIVE-001", status: "linked_to_incident", message: "linked" });
  getAlert.mockResolvedValue({ ...ALERT, linked_incident_id: "INC-LIVE-001", status: "linked_to_incident" });
  dismissAlert.mockResolvedValue({ alert_id: ALERT.alert_id, status: "dismissed_false_positive", message: "dismissed" });
}

describe("LivePrivacyMonitorPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupMocks();
  });

  it("renders the focused live monitor status, controls, and compact alerts", async () => {
    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getAllByText("Live Monitor").length).toBeGreaterThan(0);
    });
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Start monitor/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Stop monitor/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Send Synthetic Test Event/i })).toBeInTheDocument();
    expect(screen.getByText("wallet-service")).toBeInTheDocument();
    expect(screen.getByText("/wallet/transfer")).toBeInTheDocument();
    expect(screen.queryByTestId("live-monitor-curl-example")).not.toBeInTheDocument();
  });

  it("can open alert detail and show human review notice", async () => {
    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("wallet-service")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Open Alert" }));
    expect(screen.getByText("Masked alert detail")).toBeInTheDocument();
    expect(screen.getByText(/Human review required: yes/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Create incident/i }).length).toBeGreaterThan(0);
  });

  it("sends synthetic test event through the API client", async () => {
    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: /Send Synthetic Test Event/i })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Send Synthetic Test Event/i }));
    await waitFor(() => expect(sendTestEvent).toHaveBeenCalled());
    expect(await screen.findByText(/Privacy alert created with masked values only/i)).toBeInTheDocument();
  });

  it("disables synthetic ingestion while the monitor is stopped", async () => {
    getStatus.mockResolvedValueOnce({
      running: false,
      mode: "http_ingestion",
      supported_input_modes: ["http_json"],
      last_event_received_at: null,
      alert_count: 0,
      last_alert_time: null,
      safety_status: "safe",
    });

    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );

    const button = await screen.findByRole("button", { name: /Send Synthetic Test Event/i });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(sendTestEvent).not.toHaveBeenCalled();
  });
});
