import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ReportsPage from "../pages/ReportsPage";
import { mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

const listIncidents = vi.fn();
const listReports = vi.fn();
const getReportReadiness = vi.fn();
vi.mock("../api/client", () => ({
  api: {
    listIncidents: (...args: unknown[]) => listIncidents(...args),
    listReports: (...args: unknown[]) => listReports(...args),
    getReportReadiness: (...args: unknown[]) => getReportReadiness(...args),
  },
}));

const readiness = {
  incident_id: "INC-DYNAMIC-777",
  report_ready: false,
  draft_report_available: true,
  report_label: "Draft investigation report - workflow incomplete",
  checks: {
    incident_summary_ready: true,
    root_cause_available: true,
    human_review_recorded: false,
  },
  blocking_items: ["Human review is required."],
  warning_items: [],
};

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthMock.mockReturnValue(mockUseAuth());
    listIncidents.mockResolvedValue([
      {
        incident_id: "INC-DYNAMIC-777",
        title: "Dynamic incident",
        affected_endpoint: "/events",
        affected_service: "wallet-service",
        status: "investigating",
        severity: "high",
        summary: "Masked event under review.",
      },
    ]);
    listReports.mockResolvedValue({
      reports: [{ report_id: 42, report_type: "json", created_at: "2026-07-15T08:00:00Z", content: {} }],
      total: 1,
    });
    getReportReadiness.mockResolvedValue(readiness);
  });

  it("builds recent report history from API incidents without a hardcoded default", async () => {
    render(
      <MemoryRouter initialEntries={["/reports"]}>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("link", { name: "INC-DYNAMIC-777" })).toHaveAttribute(
      "href",
      "/incidents/INC-DYNAMIC-777/report",
    );
    expect(listReports).toHaveBeenCalledWith("INC-DYNAMIC-777");
    expect(screen.queryByRole("textbox", { name: /incident/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/INC-SEED-001/)).not.toBeInTheDocument();
  });

  it("uses the selected incident query and backend readiness for the primary report view", async () => {
    render(
      <MemoryRouter initialEntries={["/reports?incident=INC-DYNAMIC-777"]}>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Final Investigation Report - INC-DYNAMIC-777")).toBeInTheDocument();
    expect(screen.getByText("Draft investigation report - workflow incomplete")).toBeInTheDocument();
    expect(screen.getByTestId("reports-readiness")).toHaveTextContent("human review recorded");
    await waitFor(() => expect(getReportReadiness).toHaveBeenCalledWith("INC-DYNAMIC-777"));
    expect(screen.getByText("Advanced export formats")).toBeInTheDocument();
  });
});
