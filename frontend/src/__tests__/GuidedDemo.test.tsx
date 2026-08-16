import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import DemoGuidePage from "../pages/DemoGuidePage";

describe("live-first guided demo", () => {
  it("starts with system status and Live Privacy Monitor", () => {
    render(
      <MemoryRouter>
        <DemoGuidePage />
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: "Demo Guide" })).toBeInTheDocument();
    expect(screen.getByText("01. Check system status")).toBeInTheDocument();
    expect(screen.getByText("02. Open Live Privacy Monitor")).toBeInTheDocument();
    expect(screen.getByText("Use Evidence Import instead")).toBeInTheDocument();
    expect(screen.getByText("10. Record a controlled retest")).toBeInTheDocument();
    expect(screen.getByText("12. Generate the final report")).toBeInTheDocument();
  });
});
