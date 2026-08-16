import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import NotificationBell from "../components/NotificationBell";
import type { LiveAlert } from "../api/liveMonitorClient";

const listAlerts = vi.fn();

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    listAlerts: (...args: unknown[]) => listAlerts(...args),
  },
}));

function makeAlert(overrides: Partial<LiveAlert> = {}): LiveAlert {
  return {
    alert_id: "ALT-001",
    alert_time: new Date().toISOString(),
    received_at: new Date().toISOString(),
    source_type: "http",
    source_name: "wallet-service",
    source_format: "json",
    service_name: "wallet-service",
    endpoint: "/api/v1/transfer",
    environment: "demo",
    severity: "high",
    status: "new",
    sensitive_types: ["mobile"],
    masked_values: ["98******67"],
    detection_ids: ["DET-1"],
    evidence_id: null,
    linked_incident_id: null,
    raw_event_hash: "abc",
    safety_status: "safe",
    alert_summary: "Possible mobile number exposure",
    human_review_required: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    repeat_count: 1,
    ingestion_source: "http",
    missing_metadata: [],
    correlation_recommendations: [],
    evidence_strength: "moderate",
    ...overrides,
  };
}

describe("NotificationBell", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listAlerts.mockResolvedValue({ alerts: [], total: 0 });
  });

  it("opens a YouTube-style notification panel with recent alerts", async () => {
    listAlerts.mockResolvedValue({
      alerts: [
        makeAlert(),
        makeAlert({
          alert_id: "ALT-002",
          status: "linked_to_incident",
          alert_summary: "Linked wallet alert",
          linked_incident_id: "INC-9",
        }),
      ],
      total: 2,
    });

    render(
      <MemoryRouter>
        <NotificationBell />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /1 new privacy alert/i })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /1 new privacy alert/i }));

    expect(screen.getByRole("dialog", { name: /privacy alert notifications/i })).toBeInTheDocument();
    expect(screen.getByText("Possible mobile number exposure")).toBeInTheDocument();
    expect(screen.getByText("Linked wallet alert")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /view all/i })).toHaveAttribute("href", "/alerts");
    expect(screen.getByRole("link", { name: /open alert queue/i })).toHaveAttribute("href", "/alerts");
    expect(
      screen.getByRole("link", { name: /possible mobile number exposure/i }),
    ).toHaveAttribute("href", "/live-monitor?alert=ALT-001");
    expect(screen.getByRole("link", { name: /linked wallet alert/i })).toHaveAttribute(
      "href",
      "/incidents/INC-9",
    );
  });

  it("shows empty state when there are no alerts", async () => {
    render(
      <MemoryRouter>
        <NotificationBell />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /privacy alert notifications/i }),
      ).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /privacy alert notifications/i }));
    expect(screen.getByText(/you're all caught up/i)).toBeInTheDocument();
  });
});
