import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import Layout from "../components/Layout";
import RoleGate from "../components/RoleGate";
import MetricsPage from "../pages/MetricsPage";
import { ADMIN_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/client", () => ({
  api: {
    getEvaluationMetrics: vi.fn().mockResolvedValue({ metrics: [], total: 0, scenario_name: "s1" }),
    runEvaluation: vi.fn(),
  },
}));

describe("role-based UI access", () => {
  it("header displays user role for admin", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Admin User/)).toBeInTheDocument();
    expect(screen.getAllByText("Admin").length).toBeGreaterThan(0);
  });

  it("admin sees user management link", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Integrations" })).toBeInTheDocument();
  });

  it("viewer does not see restricted nav links", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Evidence Import" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });

  it("viewer does not see run evaluation button", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <MetricsPage />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: /run evaluation/i })).not.toBeInTheDocument();
  });

  it("RoleGate hides unauthorised content", () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <RoleGate permission="user:manage">
        <span>Secret admin panel</span>
      </RoleGate>,
    );
    expect(screen.queryByText("Secret admin panel")).not.toBeInTheDocument();
  });

  it("does not render password or token in layout", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    const { container } = render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(container.textContent).not.toMatch(/Bearer /);
    expect(container.textContent).not.toMatch(/AdminPass123!/);
  });
});
