import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LivePrivacyMonitorPage from "../pages/LivePrivacyMonitor";
import { ANALYST_USER, AUDITOR_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";

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

const SAFE_ALERT = {
  alert_id: "LPA-SAFE-001",
  alert_time: "2026-05-20T10:15:00Z",
  received_at: "2026-05-20T10:15:01Z",
  source_type: "api_log",
  source_name: "wallet-service",
  source_format: "generic_json",
  service_name: "wallet-service",
  endpoint: "/wallet/transfer",
  environment: "demo",
  severity: "critical",
  status: "new",
  sensitive_types: ["jwt_token", "api_key"],
  masked_values: ["jwt_[masked]", "api_key_[masked]"],
  detection_ids: [],
  evidence_id: null,
  linked_incident_id: null,
  raw_event_hash: "sha256:safehash",
  safety_status: "safe",
  alert_summary: "Possible privacy exposure detected with masked values only. Human review is required.",
  human_review_required: true,
  created_at: "2026-05-20T10:15:01Z",
  updated_at: "2026-05-20T10:15:01Z",
};

function setup(roleUser = ANALYST_USER) {
  useAuthMock.mockReturnValue(mockUseAuth(roleUser));
  getStatus.mockResolvedValue({
    running: false,
    mode: "http_ingestion",
    supported_input_modes: ["http_json"],
    last_event_received_at: null,
    alert_count: 1,
    last_alert_time: null,
    safety_status: "safe",
  });
  listAlerts.mockResolvedValue({ alerts: [SAFE_ALERT], total: 1 });
}

describe("Live Privacy Monitor safety UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("renders masked values and no raw phone, wallet, JWT, or API key", async () => {
    const { container } = render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("wallet-service")).toBeInTheDocument());
    screen.getByRole("button", { name: "Open Alert" }).click();
    await waitFor(() => expect(container.textContent).toContain("jwt_[masked]"));
    expect(container.textContent).toContain("api_key_[masked]");
    expect(container.textContent).not.toMatch(/9841234567/);
    expect(container.textContent).not.toMatch(/WALLET-NP-88291/);
    expect(container.textContent).not.toMatch(/eyJ[A-Za-z0-9_.-]+/);
    expect(container.textContent).not.toMatch(/pk_test_np_fake_12345/);
  });

  it("does not render forbidden overclaim wording", async () => {
    const { container } = render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("wallet-service")).toBeInTheDocument());
    const text = container.textContent?.toLowerCase() ?? "";
    for (const phrase of [
      "proven cause",
      "confirmed blame",
      "guaranteed cause",
      "confirmed bola",
      "confirmed idor",
      "attacker accessed data",
      "works in any environment",
      "production certified",
    ]) {
      expect(text).not.toContain(phrase);
    }
  });

  it("hides restricted actions for auditor", async () => {
    setup(AUDITOR_USER);
    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("wallet-service")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Start monitor/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Send Synthetic Test Event/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Create incident/i })).not.toBeInTheDocument();
  });

  it("shows restricted message for viewer", () => {
    setup(VIEWER_USER);
    render(
      <MemoryRouter>
        <LivePrivacyMonitorPage />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Live Monitor is restricted/i)).toBeInTheDocument();
  });
});
