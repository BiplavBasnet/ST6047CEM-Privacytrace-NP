import type { ReactNode } from "react";
import { vi } from "vitest";
import type { AuthUser } from "../api/authClient";
import { hasPermission } from "../utils/permissions";

const DEMO_MEMBERSHIP = {
  organisation_id: 1,
  organisation_name: "PrivacyTrace Demo",
  organisation_status: "active",
  status: "active",
};

export const ADMIN_USER: AuthUser = {
  id: 1,
  name: "Admin User",
  email: "admin@privacytrace.local",
  role: "admin",
  membership: { ...DEMO_MEMBERSHIP, role: "admin" },
};

export const VIEWER_USER: AuthUser = {
  id: 5,
  name: "Viewer",
  email: "viewer@privacytrace.local",
  role: "viewer",
  membership: { ...DEMO_MEMBERSHIP, role: "viewer" },
};

export const ANALYST_USER: AuthUser = {
  id: 2,
  name: "Security Analyst",
  email: "analyst@privacytrace.local",
  role: "security_analyst",
  membership: { ...DEMO_MEMBERSHIP, role: "security_analyst" },
};

export const AUDITOR_USER: AuthUser = {
  id: 4,
  name: "Auditor",
  email: "auditor@privacytrace.local",
  role: "auditor",
  membership: { ...DEMO_MEMBERSHIP, role: "auditor" },
};

export const UNASSIGNED_USER: AuthUser = {
  id: 9,
  name: "Unassigned Viewer",
  email: "unassigned@example.test",
  role: "viewer",
  membership: null,
};

export function mockUseAuth(user: AuthUser | null = ADMIN_USER) {
  return {
    user,
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refresh: vi.fn(),
    can: (permission: string) => {
      if (!user?.membership || user.membership.status !== "active") return false;
      return hasPermission(user.membership.role || user.role, permission);
    },
  };
}

export function mockAuthContext(user: AuthUser | null = ADMIN_USER) {
  vi.mock("../context/AuthContext", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../context/AuthContext")>();
    return {
      ...actual,
      useAuth: () => mockUseAuth(user),
      AuthProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
    };
  });
}
