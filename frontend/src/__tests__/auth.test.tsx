import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ProtectedRoute from "../components/ProtectedRoute";
import LoginPage from "../pages/Login";
import { AuthProvider, useAuth } from "../context/AuthContext";
import * as authClient from "../api/authClient";

vi.mock("../api/authClient", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/authClient")>();
  return {
    ...actual,
    authApi: {
      login: vi.fn(),
      me: vi.fn(),
      logout: vi.fn(),
      register: vi.fn(),
      registrationStatus: vi.fn(),
    },
  };
});

function LogoutProbe() {
  const { logout, user } = useAuth();
  return (
    <div>
      <span>{user?.email ?? "none"}</span>
      <button type="button" onClick={() => void logout()}>
        Logout now
      </button>
    </div>
  );
}

describe("authentication UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    vi.mocked(authClient.authApi.me).mockRejectedValue(new Error("no session"));
  });

  it("renders login page", async () => {
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /privacytrace-np/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
  });

  it("stores authenticated user context after login", async () => {
    vi.mocked(authClient.authApi.login).mockResolvedValue({
      access_token: "test-token",
      token_type: "bearer",
      user: {
        id: 1,
        name: "Admin User",
        email: "admin@privacytrace.local",
        role: "admin",
      },
    });

    render(
      <MemoryRouter initialEntries={["/login"]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText(/email address/i), {
      target: { value: "admin@privacytrace.local" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "AdminPass123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(authClient.getAuthToken()).toBe("test-token");
    });
    expect(screen.queryByText(/AdminPass123!/)).not.toBeInTheDocument();
    expect(screen.queryByText(/test-token/)).not.toBeInTheDocument();
  });

  it("clears authenticated user context on logout", async () => {
    authClient.setAuthToken("test-token");
    vi.mocked(authClient.authApi.me).mockResolvedValue({
      id: 1,
      name: "Admin User",
      email: "admin@privacytrace.local",
      role: "admin",
    });
    vi.mocked(authClient.authApi.logout).mockResolvedValue({ message: "ok" });

    render(
      <MemoryRouter>
        <AuthProvider>
          <LogoutProbe />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("admin@privacytrace.local")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /logout now/i }));

    await waitFor(() => {
      expect(authClient.getAuthToken()).toBeNull();
    });
  });

  it("protected route redirects unauthenticated user to login", async () => {
    render(
      <MemoryRouter initialEntries={["/incidents"]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<ProtectedRoute />}>
              <Route path="/incidents" element={<div>Incidents list</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
    });
    expect(screen.queryByText("Incidents list")).not.toBeInTheDocument();
  });
});
