import { afterEach, describe, expect, it, vi } from "vitest";
import { api, getApiBaseUrl, request } from "../api/client";
import * as authClient from "../api/authClient";

describe("api client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses default backend base URL", () => {
    expect(getApiBaseUrl()).toBe("http://127.0.0.1:8000");
  });

  it("calls health endpoint without logging responses", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "healthy",
        service: "PrivacyTrace-NP",
        database: "connected",
        version: "0.1.0",
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const health = await api.getHealth();
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/health",
      expect.objectContaining({ headers: expect.any(Object) }),
    );
    expect(health.status).toBe("healthy");
    expect(logSpy).not.toHaveBeenCalled();
  });

  it("sends Authorization header when token is set", async () => {
    authClient.setAuthToken("unit-test-jwt");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ ok: true }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await request("/auth/me");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/auth/me",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer unit-test-jwt",
        }),
      }),
    );
    authClient.clearAuthToken();
  });
});
