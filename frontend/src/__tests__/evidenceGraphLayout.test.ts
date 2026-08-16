import { describe, expect, it } from "vitest";

import { layoutEvidenceGraph, shortNodeId } from "../utils/evidenceGraphLayout";

describe("evidenceGraphLayout", () => {
  it("positions nodes in layers and builds edge paths", () => {
    const { positions, positionedEdges, width, height } = layoutEvidenceGraph(
      [
        { id: "INC-1", type: "incident" },
        { id: "EVD-1", type: "evidence" },
        { id: "EVT-1", type: "normalized_event" },
      ],
      [
        { source: "INC-1", target: "EVD-1", relationship: "has_evidence" },
        { source: "EVD-1", target: "EVT-1", relationship: "normalized_as" },
      ],
    );
    expect(positions.get("INC-1")?.layer).toBe(0);
    expect(positions.get("EVD-1")?.layer).toBe(1);
    expect(positions.get("EVT-1")?.layer).toBe(2);
    expect(positionedEdges).toHaveLength(2);
    expect(width).toBeGreaterThan(0);
    expect(height).toBeGreaterThan(0);
  });

  it("shortens long node ids for display", () => {
    expect(shortNodeId("EVT-EVD-S1-API-001-001")).toContain("…");
  });
});
