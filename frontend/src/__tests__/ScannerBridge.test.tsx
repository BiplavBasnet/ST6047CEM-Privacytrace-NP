import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import ScannerBridgePage from "../pages/ScannerBridge";

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    can: (perm: string) =>
      perm === "scanner_bridge:read" || perm === "scanner_bridge:import",
    user: { role: "admin" },
    logout: vi.fn(),
  }),
}));

vi.mock("../api/scannerBridgeClient", () => ({
  scannerBridgeApi: {
    listEvidence: vi.fn().mockResolvedValue([]),
    preview: vi.fn(),
    import: vi.fn(),
    correlate: vi.fn(),
  },
  SCANNER_SOURCE_FORMATS: ["gitleaks_json"],
}));

describe("ScannerBridge page", () => {
  it("renders ScannerBridge-NP title without vendor branding", () => {
    render(
      <MemoryRouter>
        <ScannerBridgePage />
      </MemoryRouter>,
    );
    expect(screen.getAllByText("ScannerBridge-NP").length).toBeGreaterThan(0);
    expect(screen.queryByRole("heading", { name: /Gitleaks/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Semgrep/i })).not.toBeInTheDocument();
  });
});
