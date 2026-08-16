import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import SecurityPage from "../pages/SecurityPage";
vi.mock("../api/client", () => ({
  api: {
    getSecurityProfile: vi.fn().mockResolvedValue({
      security_profile: "NIST_ALIGNED_DEMO",
      crypto_mode_enabled: true,
      active_key_id: "demo-key-001",
      symmetric_algorithm: "AES-256-GCM",
      key_wrap_algorithm: "RSA-OAEP-SHA256",
      jwt_signing: "RS256",
      jwt_asymmetric_enabled: true,
      password_hash_algorithm: "pbkdf2-sha256",
      nist_csf_functions: [
        "Govern",
        "Identify",
        "Protect",
        "Detect",
        "Respond",
        "Recover",
      ],
      nist_sp_documents_referenced: ["SP 800-53 Rev. 5"],
      compliance_note: "NIST-aligned thesis prototype. Not formal certification.",
      fips_aware_note: "FIPS-aware design. Not FIPS-certified.",
    }),
  },
}));

const authValue = {
  user: {
    id: 1,
    name: "Admin",
    email: "admin@privacytrace.local",
    role: "admin",
    is_active: true,
  },
  token: "test-token",
  login: vi.fn(),
  logout: vi.fn(),
  can: () => true,
};

vi.mock("../context/AuthContext", async () => {
  const actual = await vi.importActual("../context/AuthContext");
  return {
    ...actual,
    useAuth: () => authValue,
  };
});

describe("SecurityPage", () => {
  it("renders crypto and NIST summary without secrets", async () => {
    render(
      <MemoryRouter>
        <SecurityPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText(/AES-256-GCM/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/RSA-OAEP-SHA256/i)).toBeInTheDocument();
    expect(screen.getByText(/RS256/i)).toBeInTheDocument();
    expect(screen.getByText(/Govern/i)).toBeInTheDocument();
    const body = document.body.textContent || "";
    expect(body).not.toMatch(/BEGIN PRIVATE KEY/i);
    expect(body).not.toMatch(/eyJ[a-zA-Z0-9_-]+\./);
    expect(body).not.toMatch(/9800000000000000/);
  });
});
