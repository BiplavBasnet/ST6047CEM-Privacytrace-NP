import { describe, expect, it } from "vitest";
import {
  BLOCKED_CLAIM_FALLBACK,
  BLOCKED_SENSITIVE_FALLBACK,
  sanitizeObject,
  sanitizeString,
} from "../utils/safety";

describe("safety utility", () => {
  it("blocks raw phone number", () => {
    expect(sanitizeString("contact 9841234567 now")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
    expect(sanitizeString("contact 9841234567 now")).not.toContain("9841234567");
  });

  it("blocks raw wallet ID", () => {
    expect(sanitizeString("wallet WALLET-NP-88291")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
  });

  it("blocks raw API key", () => {
    expect(sanitizeString("key pk_test_np_fake_12345")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
  });

  it("blocks JWT and bearer token in display text", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(sanitizeString(jwt)).toContain(BLOCKED_SENSITIVE_FALLBACK);
    expect(sanitizeString("Bearer abcdef1234567890")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
  });

  it("preserves access_token in login responses for session storage", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const login = sanitizeObject({
      access_token: jwt,
      token_type: "bearer",
      user: { email: "admin@privacytrace.local" },
    });
    expect(login.access_token).toBe(jwt);
    expect(login.token_type).toBe("bearer");
  });

  it("blocks overclaim phrases", () => {
    const phrases = [
      "proven cause",
      "confirmed blame",
      "guaranteed cause",
      "definitely caused by",
      "developer fault",
      "guaranteed fixed",
      "incident closed automatically",
    ];
    for (const phrase of phrases) {
      expect(sanitizeString(`This is a ${phrase} of the leak`)).toContain(
        BLOCKED_CLAIM_FALLBACK,
      );
    }
  });
});
