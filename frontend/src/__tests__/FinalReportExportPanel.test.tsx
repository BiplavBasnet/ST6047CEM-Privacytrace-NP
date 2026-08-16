import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import FinalReportExportPanel from "../components/FinalReportExportPanel";

vi.mock("../api/finalReportClient", () => ({
  downloadFinalReport: vi.fn(),
}));

describe("FinalReportExportPanel", () => {
  it("prioritises PDF and ZIP while keeping advanced formats collapsed", () => {
    render(<FinalReportExportPanel incidentId="INC-SEED-001" canExport />);
    expect(screen.getByTestId("final-report-export-panel")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download PDF" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download ZIP Bundle" })).toBeInTheDocument();
    const advanced = screen.getByTestId("advanced-report-formats");
    expect(advanced).not.toHaveAttribute("open");
    expect(screen.getByText("Advanced export formats")).toBeInTheDocument();
    expect(screen.queryByText(/proven cause/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/TruffleHog/i)).not.toBeInTheDocument();
  });

  it("renders nothing when export not permitted", () => {
    const { container } = render(
      <FinalReportExportPanel incidentId="INC-SEED-001" canExport={false} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
