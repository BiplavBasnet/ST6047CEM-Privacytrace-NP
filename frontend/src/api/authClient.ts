import { sanitizeObject } from "../utils/safety";
import { getApiBaseUrl, ApiError } from "./client";

const TOKEN_KEY = "privacytrace_auth_token";

let onSessionExpired: (() => void) | null = null;

/** Register handler when API returns 401 (clears token before invoking). */
export function setOnSessionExpired(handler: (() => void) | null): void {
  onSessionExpired = handler;
}

export function notifySessionExpired(): void {
  onSessionExpired?.();
}

export interface Membership {
  organisation_id: number;
  organisation_name: string | null;
  organisation_status: string | null;
  role: string;
  status: string;
}

export interface AuthUser {
  id: number;
  name: string;
  email: string;
  role: string;
  membership?: Membership | null;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

export interface RegisterRequest {
  full_name: string;
  email: string;
  password: string;
  confirm_password: string;
  invite_token?: string;
}

export interface RegisterResponse {
  id: number;
  name: string;
  email: string;
  role: string;
  message: string;
}

export interface RegistrationStatus {
  enabled: boolean;
  email_verification_required: boolean;
  default_role: string;
  invite_only?: boolean;
}

export interface SetupStatus {
  required: boolean;
  completed: boolean;
  verification_pending?: boolean;
  bootstrap_required?: boolean;
  registration_open?: boolean;
}

export interface VerificationStatus {
  organisation_id: number;
  organisation_name: string;
  legal_name: string | null;
  registration_number: string | null;
  pan_masked?: string | null;
  website_domain: string | null;
  legal_verification_status: string;
  pan_verification_status: string;
  pan_verification_required: boolean;
  domain_verification_status: string;
  admin_email_verification_status: string;
  overall_verification_status: string;
  overall_verification_method?: string | null;
  legal_verification_method?: string | null;
  verification_mode: string;
  demo_verification_simulated: boolean;
  demo_banner: string | null;
  legal_verification_source: string | null;
  policy_satisfied: boolean;
  setup_completed: boolean;
  organisation_operational_status?: string | null;
}

export interface InvitationPreview {
  email: string;
  role: string;
  organisation_name: string;
  expires_at: string;
}

function getTokenStorage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getAuthToken(): string | null {
  try {
    const sessionToken = getTokenStorage()?.getItem(TOKEN_KEY);
    if (sessionToken) return sessionToken;
    const legacyToken = window.localStorage?.getItem(TOKEN_KEY);
    if (legacyToken) {
      getTokenStorage()?.setItem(TOKEN_KEY, legacyToken);
      window.localStorage.removeItem(TOKEN_KEY);
    }
    return legacyToken || null;
  } catch {
    return null;
  }
}

export function setAuthToken(token: string): void {
  getTokenStorage()?.setItem(TOKEN_KEY, token);
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore unavailable storage */
  }
}

export function clearAuthToken(): void {
  getTokenStorage()?.removeItem(TOKEN_KEY);
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore unavailable storage */
  }
}

async function authRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${getApiBaseUrl()}${path}`;
  const token = getAuthToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers as Record<string, string>),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errBody = await response.json();
      if (typeof errBody?.detail === "string") {
        detail = errBody.detail;
      }
    } catch {
      /* ignore */
    }
    if (
      response.status === 401 &&
      path !== "/auth/login" &&
      path !== "/auth/register" &&
      path !== "/auth/registration-status" &&
      !path.startsWith("/setup")
    ) {
      clearAuthToken();
      notifySessionExpired();
    }
    throw new ApiError(detail, response.status);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return sanitizeObject((await response.json()) as T);
}

export const authApi = {
  login: (email: string, password: string) =>
    authRequest<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  register: (payload: RegisterRequest) =>
    authRequest<RegisterResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  registrationStatus: () => authRequest<RegistrationStatus>("/auth/registration-status"),

  me: () => authRequest<AuthUser>("/auth/me"),

  logout: () =>
    authRequest<{ message: string }>("/auth/logout", {
      method: "POST",
    }),

  invitationPreview: (token: string) =>
    authRequest<InvitationPreview>(`/invitations/preview?token=${encodeURIComponent(token)}`),
};

export const setupApi = {
  status: () => authRequest<SetupStatus>("/setup/status"),
  createOrganisation: (payload: {
    organisation_name: string;
    administrator_full_name: string;
    email: string;
    password: string;
    confirm_password: string;
    bootstrap_token: string;
    legal_name?: string;
    registration_number?: string;
    pan_number?: string;
    registered_address?: string;
    website_domain?: string;
  }) =>
    authRequest("/setup/organisation", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  verificationStatus: () => authRequest<VerificationStatus>("/setup/verification/status"),
  verifyLegal: (payload: Record<string, string | undefined>) =>
    authRequest<VerificationStatus>("/setup/verification/legal", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  verifyPan: (payload: Record<string, string | undefined>) =>
    authRequest<VerificationStatus>("/setup/verification/pan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createDomainChallenge: (domain: string) =>
    authRequest<{ domain: string; txt_record: string; expires_at: string; status: string }>(
      "/setup/verification/domain/challenge",
      { method: "POST", body: JSON.stringify({ domain }) },
    ),
  verifyDomain: (txtRecord?: string) =>
    authRequest<VerificationStatus>("/setup/verification/domain/verify", {
      method: "POST",
      body: JSON.stringify(txtRecord ? { txt_record: txtRecord } : {}),
    }),
  issueEmailToken: () =>
    authRequest<{
      email: string;
      expires_at: string;
      verify_path: string | null;
      verify_token: string | null;
      delivery?: string;
      demo_simulated?: boolean;
    }>("/setup/verification/email/issue", { method: "POST" }),
  confirmEmail: (token: string) =>
    authRequest<VerificationStatus>("/setup/verification/email/confirm", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  requestManualReview: (reason: string) =>
    authRequest<VerificationStatus>("/setup/verification/manual-review", {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
};

export const passwordResetApi = {
  request: (email: string) =>
    authRequest<{ message: string; demo_reset_token?: string | null; demo_simulated?: boolean }>(
      "/auth/password-reset/request",
      { method: "POST", body: JSON.stringify({ email }) },
    ),
  confirm: (token: string, password: string, confirm_password: string) =>
    authRequest<{ message: string }>("/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify({ token, password, confirm_password }),
    }),
};
