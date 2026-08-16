import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import TraceSummaryPanel from "../components/differentiation/TraceSummaryPanel";

describe("TraceabilitySafety", () => {
  it("shows likely cause language and avoids raw/forbidden wording", () => {
    render(
      <TraceSummaryPanel
        summary={{
          what_happened: "Masked sensitive values were detected in API evidence.",
          strongest_likely_cause: "unsafe_request_body_logging",
          why_ranked_highest: ["Evidence suggests request body logging was enabled."],
          what_is_missing: ["Missing code scan finding"],
          safe_conclusion:
            "Evidence suggests unsafe request-body logging is the strongest likely cause, but human review is required.",
        }}
        reviewerWarning="Root-cause ranking is based on available evidence and must be reviewed by a human analyst."
      />,
    );
    expect(screen.getAllByText(/strongest likely cause/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/human review is required/i)).toBeInTheDocument();
    expect(screen.queryByText(/confirmed blame/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/9841234567/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/WALLET-NP-88291/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/eyJhbGci/i)).not.toBeInTheDocument();
  });
});
