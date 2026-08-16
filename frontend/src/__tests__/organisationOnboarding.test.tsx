import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Layout from "../components/Layout";
import SetupPage from "../pages/SetupPage";
import UnassignedPage from "../pages/UnassignedPage";
import UserManagementPage from "../pages/UserManagement";
import HomePage from "../pages/HomePage";
import SignupForm from "../components/auth/SignupForm";
import { ADMIN_USER, UNASSIGNED_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";
import * as authClient from "../api/authClient";

const useAuthMock = vi.fn();
vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

vi.mock("../api/client", () => ({
  api: {
    listIncidents: vi.fn().mockResolvedValue([]),
    getHealth: vi.fn().mockResolvedValue({ status: "healthy" }),
  },
  request: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 400) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock("../api/liveMonitorClient", () => ({
  liveMonitorApi: {
    getStatus: vi.fn(),
    listAlerts: vi.fn().mockResolvedValue({ alerts: [] }),
  },
}));

vi.mock("../api/authClient", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/authClient")>();
  return {
    ...actual,
    setupApi: {
      status: vi.fn(),
      createOrganisation: vi.fn(),
      verificationStatus: vi.fn(),
      verifyLegal: vi.fn(),
      verifyPan: vi.fn(),
      createDomainChallenge: vi.fn(),
      verifyDomain: vi.fn(),
      issueEmailToken: vi.fn(),
      confirmEmail: vi.fn(),
      requestManualReview: vi.fn(),
    },
    authApi: {
      ...actual.authApi,
      invitationPreview: vi.fn(),
      register: vi.fn(),
      registrationStatus: vi.fn(),
    },
  };
});

describe("organisation onboarding UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthMock.mockReturnValue({
      user: null,
      loading: false,
      login: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn(),
      refresh: vi.fn().mockResolvedValue(undefined),
      can: () => false,
    });
  });

  it("offers setup when deployment has no organisation", async () => {
    vi.mocked(authClient.setupApi.status).mockResolvedValue({ required: true, completed: false });
    render(
      <MemoryRouter>
        <SetupPage />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: /register company/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/bootstrap token/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/organisation name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/administrator full name/i)).toBeInTheDocument();
  });

  it("hides setup after completion", async () => {
    vi.mocked(authClient.setupApi.status).mockResolvedValue({
      required: false,
      completed: true,
      registration_open: false,
    });
    render(
      <MemoryRouter initialEntries={["/setup"]}>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/login" element={<p>Login destination</p>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: /setup complete/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.queryByText("Login destination")).not.toBeInTheDocument();
  });

  it("offers registration when a demo organisation can still be replaced", async () => {
    vi.mocked(authClient.setupApi.status).mockResolvedValue({
      required: false,
      completed: false,
      registration_open: true,
    });
    render(
      <MemoryRouter>
        <SetupPage />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: /register company/i })).toBeInTheDocument();
  });

  it("asks the first admin to sign in when verification is pending", async () => {
    vi.mocked(authClient.setupApi.status).mockResolvedValue({
      required: false,
      completed: false,
      verification_pending: true,
      registration_open: false,
    });
    render(
      <MemoryRouter initialEntries={["/setup"]}>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/login" element={<p>Login destination</p>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("heading", { name: /continue verification/i })).toBeInTheDocument();
    expect(screen.queryByText("Login destination")).not.toBeInTheDocument();
  });

  it("organisation admin sees Users nav and viewer does not", () => {
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    const { unmount } = render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
    unmount();
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });

  it("unassigned user sees assignment message and no investigation nav", () => {
    useAuthMock.mockReturnValue(mockUseAuth(UNASSIGNED_USER));
    render(
      <MemoryRouter>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: "Incidents" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Reports" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });

  it("renders unassigned copy", () => {
    render(<UnassignedPage />);
    expect(
      screen.getByText(/your account is not currently assigned to an organisation/i),
    ).toBeInTheDocument();
  });

  it("user management does not offer platform_admin", async () => {
    const { request } = await import("../api/client");
    vi.mocked(request).mockResolvedValue({ users: [], total: 0 });
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <UserManagementPage />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("button", { name: /invite user/i })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "platform_admin" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Platform Admin" })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Organisation Admin" })).toBeInTheDocument();
  });

  it("live monitor shows Restricted when the viewer cannot read it", async () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );
    expect((await screen.findAllByText("Restricted")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument();
  });

  it("setup submits organisation and first administrator", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    useAuthMock.mockReturnValue({
      user: null,
      loading: false,
      login,
      logout: vi.fn(),
      refresh: vi.fn().mockResolvedValue(undefined),
      can: () => false,
    });
    vi.mocked(authClient.setupApi.status).mockResolvedValue({ required: true, completed: false });
    vi.mocked(authClient.setupApi.createOrganisation).mockResolvedValue({
      organisation_name: "ABC Wallet",
      role: "organisation_admin",
    });
    vi.mocked(authClient.setupApi.verificationStatus).mockResolvedValue({
      organisation_id: 1,
      organisation_name: "ABC Wallet",
      legal_name: "ABC Wallet Pvt Ltd",
      registration_number: "123456",
      website_domain: "abcwallet.test",
      legal_verification_status: "pending_verification",
      pan_verification_status: "unverified",
      pan_verification_required: false,
      domain_verification_status: "pending_verification",
      admin_email_verification_status: "unverified",
      overall_verification_status: "pending_verification",
      verification_mode: "demo",
      demo_verification_simulated: true,
      demo_banner: null,
      legal_verification_source: null,
      policy_satisfied: false,
      setup_completed: false,
    });
    render(
      <MemoryRouter>
        <SetupPage />
      </MemoryRouter>,
    );
    fireEvent.change(await screen.findByLabelText(/organisation name/i), { target: { value: "ABC Wallet" } });
    fireEvent.change(screen.getByLabelText(/legal company name/i), { target: { value: "ABC Wallet Pvt Ltd" } });
    fireEvent.change(screen.getByLabelText(/registration number/i), { target: { value: "123456" } });
    fireEvent.change(screen.getByLabelText(/website domain/i), { target: { value: "abcwallet.test" } });
    fireEvent.change(screen.getByLabelText(/administrator full name/i), { target: { value: "Ada Admin" } });
    fireEvent.change(screen.getByLabelText(/work email/i), { target: { value: "ada.admin@abc.test" } });
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "OrgAdminPass123!" } });
    fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: "OrgAdminPass123!" } });
    fireEvent.change(screen.getByLabelText(/bootstrap token/i), { target: { value: "dev-bootstrap-change-me" } });
    fireEvent.click(screen.getByRole("button", { name: /submit company registration/i }));
    await waitFor(() => {
      expect(authClient.setupApi.createOrganisation).toHaveBeenCalled();
    });
    expect(login).toHaveBeenCalledWith("ada.admin@abc.test", "OrgAdminPass123!");
    expect(await screen.findByRole("heading", { name: /verify organisation/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run legal verification/i })).toBeInTheDocument();
  });

  it("invite user shows invitation path", async () => {
    const { request } = await import("../api/client");
    vi.mocked(request)
      .mockResolvedValueOnce({ users: [], total: 0 })
      .mockResolvedValueOnce({ invite_path: "/signup?invite=tok", invite_token: "tok" })
      .mockResolvedValue({ users: [], total: 0 });
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <UserManagementPage />
      </MemoryRouter>,
    );
    fireEvent.change(await screen.findByPlaceholderText(/work email/i), {
      target: { value: "employee@abc.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: /invite user/i }));
    expect(await screen.findByText(/\/signup\?invite=tok/)).toBeInTheDocument();
  });

  it("last-admin protection shows the backend message", async () => {
    const { request, ApiError } = await import("../api/client");
    vi.mocked(request)
      .mockResolvedValueOnce({
        users: [
          {
            id: 1,
            name: "Ada Admin",
            email: "ada.admin@abc.test",
            role: "organisation_admin",
            is_active: true,
            membership_status: "active",
            membership_role: "organisation_admin",
          },
        ],
        total: 1,
      })
      .mockRejectedValueOnce(
        new ApiError("Another active Organisation Administrator must exist first.", 409),
      );
    useAuthMock.mockReturnValue(mockUseAuth(ADMIN_USER));
    render(
      <MemoryRouter>
        <UserManagementPage />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByText("Ada Admin"));
    const roleSelect = await screen.findByLabelText(/change role for ada.admin@abc.test/i);
    fireEvent.change(roleSelect, { target: { value: "viewer" } });
    expect(
      await screen.findByText(/another active organisation administrator must exist first/i),
    ).toBeInTheDocument();
  });

  it("invitation signup prefills the invited email", async () => {
    vi.mocked(authClient.authApi.registrationStatus).mockResolvedValue({
      enabled: false,
      email_verification_required: false,
      default_role: "viewer",
      invite_only: true,
    });
    vi.mocked(authClient.authApi.invitationPreview).mockResolvedValue({
      email: "employee@abc.test",
      role: "viewer",
      organisation_name: "ABC Wallet",
      expires_at: "2099-01-01T00:00:00Z",
    });
    render(
      <MemoryRouter initialEntries={["/signup?invite=one-time-token"]}>
        <Routes>
          <Route path="/signup" element={<SignupForm />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByDisplayValue("employee@abc.test")).toBeInTheDocument();
    expect(screen.getByText(/join abc wallet/i)).toBeInTheDocument();
  });
});
