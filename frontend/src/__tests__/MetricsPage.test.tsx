import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import MetricsPage from "../pages/MetricsPage";
import * as client from "../api/client";
import { mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

describe("MetricsPage", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows thesis_claim and calculation_method columns", async () => {
    useAuthMock.mockReturnValue(mockUseAuth());
    vi.spyOn(client.api, "getEvaluationMetrics").mockResolvedValue({
      scenario_name: "scenario_1",
      total: 1,
      metrics: [
        {
          metric_name: "masked_detection_recall",
          metric_value: 1,
          thesis_claim: "Detections remain masked in outputs",
          calculation_method: "Compare masked labels to ground truth types",
          evidence_source: "scenario_1 seed bundle",
          scenario_name: "scenario_1",
        },
      ],
    });

    render(
      <MemoryRouter>
        <MetricsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Thesis claim")).toBeInTheDocument();
    expect(screen.getByText("Detections remain masked in outputs")).toBeInTheDocument();
    expect(screen.getByText("Compare masked labels to ground truth types")).toBeInTheDocument();
  });
});
