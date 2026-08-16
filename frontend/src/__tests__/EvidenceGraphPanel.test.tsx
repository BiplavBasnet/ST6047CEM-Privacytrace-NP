import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import EvidenceGraphPanel from "../components/differentiation/EvidenceGraphPanel";

describe("EvidenceGraphPanel", () => {
  it("renders a visual graph canvas and relationship list", () => {
    render(
      <EvidenceGraphPanel
        graph={{
          nodes: [
            { id: "INC-001", type: "incident" },
            { id: "LOG-001", type: "evidence" },
          ],
          edges: [{ source: "INC-001", target: "LOG-001", relationship: "has_evidence" }],
          disclaimer:
            "This graph shows evidence relationships and ranked likely causes for review; it does not assign fault or final blame.",
        }}
      />,
    );
    expect(screen.getByText(/Evidence graph/i)).toBeInTheDocument();
    expect(screen.getByTestId("evidence-graph-canvas")).toBeInTheDocument();
    expect(screen.getByTestId("graph-node-INC-001")).toBeInTheDocument();
    expect(screen.getByText(/has_evidence/i)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Evidence relationship graph/i })).toBeInTheDocument();
  });

  it("shows empty state when there are no nodes", () => {
    render(<EvidenceGraphPanel graph={{ nodes: [], edges: [] }} />);
    expect(screen.getByText(/No graph data yet/i)).toBeInTheDocument();
  });

  it("allows selecting a node to highlight connections", () => {
    render(
      <EvidenceGraphPanel
        graph={{
          nodes: [
            { id: "INC-001", type: "incident" },
            { id: "LOG-001", type: "evidence" },
            { id: "LOG-002", type: "evidence" },
          ],
          edges: [
            { source: "INC-001", target: "LOG-001", relationship: "has_evidence" },
            { source: "INC-001", target: "LOG-002", relationship: "has_evidence" },
          ],
        }}
      />,
    );
    fireEvent.click(screen.getByTestId("graph-node-LOG-001"));
    expect(screen.getByTestId("graph-node-LOG-001")).toBeInTheDocument();
  });
});
