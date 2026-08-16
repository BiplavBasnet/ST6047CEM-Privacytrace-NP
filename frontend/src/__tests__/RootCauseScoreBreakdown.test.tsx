import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import RootCauseScoreBreakdown from "../components/differentiation/RootCauseScoreBreakdown";

describe("RootCauseScoreBreakdown", () => {
  it("renders score breakdown rows", () => {
    render(
      <RootCauseScoreBreakdown
        breakdown={[
          {
            signal_name: "endpoint_and_service_match",
            matched: true,
            weight: 0.12,
            reason: "Evidence matched both endpoint and service.",
          },
        ]}
      />,
    );
    expect(screen.getByText(/Root-cause score breakdown/i)).toBeInTheDocument();
    expect(screen.getByText(/endpoint_and_service_match/i)).toBeInTheDocument();
    expect(screen.getByText(/Matched: true/i)).toBeInTheDocument();
    expect(screen.queryByText(/proven cause/i)).not.toBeInTheDocument();
  });
});
