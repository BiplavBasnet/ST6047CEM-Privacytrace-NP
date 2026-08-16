import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import AuthPage from "../pages/AuthPage";
import * as authClient from "../api/authClient";
import { ApiError } from "../api/client";

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
      invitationPreview: vi.fn(),
    },
    setupApi: {
      status: vi.fn().mockResolvedValue({ required: false, completed: true }),
      createOrganisation: vi.fn(),
    },
  };
});

function renderAuth(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<AuthPage />} />
          <Route path="/signup" element={<AuthPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("auth signup UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    vi.mocked(authClient.authApi.me).mockRejectedValue(new Error("no session"));
    vi.mocked(authClient.authApi.registrationStatus).mockResolvedValue({
      enabled: true,
      email_verification_required: false,
      default_role: "viewer",
    });
  });

  it("renders signup page", async () => {
    renderAuth("/signup");
    expect(await screen.findByRole("heading", { name: /create your account/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/full name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^email address$/i)).toBeInTheDocument();
    expect(screen.queryByText(/google|facebook|github|sso/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /forgot password/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/role/i)).not.toBeInTheDocument();
  });

  it("switches between login and signup modes", async () => {
    renderAuth("/login");
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: /create an account/i }));
    expect(await screen.findByRole("heading", { name: /create your account/i })).toBeInTheDocument();
  });

  it("toggles password visibility", async () => {
    renderAuth("/login");
    const password = await screen.findByLabelText(/^password$/i);
    expect(password).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: /show password/i }));
    expect(password).toHaveAttribute("type", "text");
  });

  it("shows password strength guidance", async () => {
    renderAuth("/signup");
    await screen.findByRole("heading", { name: /create your account/i });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "Short1!" },
    });
    expect(screen.getByText(/at least 10 characters/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password strength/i)).toBeInTheDocument();
  });

  it("validates password mismatch client-side", async () => {
    renderAuth("/signup");
    await screen.findByRole("heading", { name: /create your account/i });
    fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: "Synth User" } });
    fireEvent.change(screen.getByLabelText(/^email address$/i), {
      target: { value: "synth@example.test" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "SyntheticPass123!" },
    });
    fireEvent.change(screen.getByLabelText(/confirm password/i), {
      target: { value: "DifferentPass123!" },
    });
    fireEvent.click(screen.getByLabelText(/research prototype/i));
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
    expect(authClient.authApi.register).not.toHaveBeenCalled();
  });

  it("shows loading state then succeeds on registration", async () => {
    let resolveRegister!: (value: authClient.RegisterResponse) => void;
    vi.mocked(authClient.authApi.register).mockImplementation(
      () =>
        new Promise<authClient.RegisterResponse>((resolve) => {
          resolveRegister = resolve;
        }),
    );

    renderAuth("/signup");
    await screen.findByRole("heading", { name: /create your account/i });
    fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: "Synth User" } });
    fireEvent.change(screen.getByLabelText(/^email address$/i), {
      target: { value: "synth@example.test" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "SyntheticPass123!" },
    });
    fireEvent.change(screen.getByLabelText(/confirm password/i), {
      target: { value: "SyntheticPass123!" },
    });
    fireEvent.click(screen.getByLabelText(/research prototype/i));
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    expect(await screen.findByRole("button", { name: /creating account/i })).toBeDisabled();

    resolveRegister({
      id: 99,
      name: "Synth User",
      email: "synth@example.test",
      role: "viewer",
      message: "Account created. Sign in with your email and password.",
    });

    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
    expect(screen.getByText(/account created/i)).toBeInTheDocument();
  });

  it("shows duplicate account error safely", async () => {
    vi.mocked(authClient.authApi.register).mockRejectedValue(
      new ApiError("An account with this email already exists.", 409),
    );
    renderAuth("/signup");
    await screen.findByRole("heading", { name: /create your account/i });
    fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: "Synth User" } });
    fireEvent.change(screen.getByLabelText(/^email address$/i), {
      target: { value: "synth@example.test" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "SyntheticPass123!" },
    });
    fireEvent.change(screen.getByLabelText(/confirm password/i), {
      target: { value: "SyntheticPass123!" },
    });
    fireEvent.click(screen.getByLabelText(/research prototype/i));
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(await screen.findByText(/already exists/i)).toBeInTheDocument();
  });

  it("shows unavailable notice when registration is disabled", async () => {
    vi.mocked(authClient.authApi.registrationStatus).mockResolvedValue({
      enabled: false,
      email_verification_required: false,
      default_role: "viewer",
    });
    renderAuth("/signup");
    expect(await screen.findByRole("heading", { name: /unavailable/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create account/i })).not.toBeInTheDocument();
  });

  it("login page has no social buttons and includes forgot-password link", async () => {
    renderAuth("/login");
    await screen.findByRole("heading", { name: /welcome back/i });
    expect(screen.queryByText(/google|facebook|github/i)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /forgot password/i })).toBeInTheDocument();
  });

  it("shows safe login error without echoing credentials", async () => {
    vi.mocked(authClient.authApi.login).mockRejectedValue(new ApiError("Invalid", 401));
    renderAuth("/login");
    await screen.findByRole("heading", { name: /welcome back/i });
    fireEvent.change(screen.getByLabelText(/email address/i), {
      target: { value: "analyst@privacytrace.local" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "WrongPass123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText(/could not sign you in/i)).toBeInTheDocument();
    expect(screen.queryByText("WrongPass123!")).not.toBeInTheDocument();
  });

  it("login loading state disables submit", async () => {
    let resolveLogin!: (value: authClient.LoginResponse) => void;
    vi.mocked(authClient.authApi.login).mockImplementation(
      () =>
        new Promise<authClient.LoginResponse>((resolve) => {
          resolveLogin = resolve;
        }),
    );
    renderAuth("/login");
    await screen.findByRole("heading", { name: /welcome back/i });
    fireEvent.change(screen.getByLabelText(/email address/i), {
      target: { value: "analyst@privacytrace.local" },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "AnalystPass123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("button", { name: /signing in/i })).toBeDisabled();
    resolveLogin({
      access_token: "tok",
      token_type: "bearer",
      user: {
        id: 1,
        name: "Analyst",
        email: "analyst@privacytrace.local",
        role: "security_analyst",
      },
    });
    await waitFor(() => {
      expect(authClient.getAuthToken()).toBe("tok");
    });
  });

  it("reduced-motion media query does not break the auth visual", async () => {
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: query.includes("prefers-reduced-motion"),
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
    renderAuth("/login");
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
  });
});
