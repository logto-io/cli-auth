import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { createCliAuth } from "../index.js";

const server = setupServer();

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const tokenEndpoint = "https://auth.example.com/token";

function useCaptureTokenEndpoint() {
  let capturedBody: URLSearchParams;
  let capturedHeaders: Headers;
  server.use(
    http.post(tokenEndpoint, async ({ request }) => {
      capturedBody = new URLSearchParams(await request.text());
      capturedHeaders = request.headers;
      return HttpResponse.json({
        access_token: "test-token",
        token_type: "Bearer",
        expires_in: 3600,
      });
    })
  );
  return {
    getBody: () => capturedBody,
    getHeaders: () => capturedHeaders,
  };
}

function createTestAuth(overrides: Record<string, unknown> = {}) {
  const stored: Record<string, unknown> = {};
  return createCliAuth({
    strategy: "client-credentials",
    provider: {
      tokenEndpoint,
      clientId: "my-client",
      clientSecret: "my-secret",
    },
    storage: {
      load: async () => stored.credential ?? null,
      save: async (credential: unknown) => {
        stored.credential = credential;
      },
      clear: async () => {
        delete stored.credential;
      },
    },
    ...overrides,
  });
}

describe("client-credentials", () => {
  describe("login — client_secret_post (default)", () => {
    it("sends grant_type=client_credentials in request body", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().get("grant_type")).toBe("client_credentials");
    });

    it("sends client_id and client_secret in request body by default", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().get("client_id")).toBe("my-client");
      expect(getBody().get("client_secret")).toBe("my-secret");
    });

    it("sends resource in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({ resource: "https://shopping.api" });
      await auth.login();
      expect(getBody().get("resource")).toBe("https://shopping.api");
    });

    it("sends scope in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({ scope: "read:products write:products" });
      await auth.login();
      expect(getBody().get("scope")).toBe("read:products write:products");
    });

    it("sends extra params in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        extraParams: { audience: "https://my-api.com", custom_field: "value" },
      });
      await auth.login();
      expect(getBody().get("audience")).toBe("https://my-api.com");
      expect(getBody().get("custom_field")).toBe("value");
    });
  });

  describe("login — client_secret_basic", () => {
    it("sends Basic Auth header with base64(clientId:clientSecret)", async () => {
      const { getHeaders } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        provider: {
          tokenEndpoint,
          clientId: "my-client",
          clientSecret: "my-secret",
          tokenEndpointAuthMethod: "client_secret_basic",
        },
      });
      await auth.login();
      const expected = `Basic ${btoa("my-client:my-secret")}`;
      expect(getHeaders().get("Authorization")).toBe(expected);
    });

    it("does not include client_id or client_secret in request body", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        provider: {
          tokenEndpoint,
          clientId: "my-client",
          clientSecret: "my-secret",
          tokenEndpointAuthMethod: "client_secret_basic",
        },
      });
      await auth.login();
      expect(getBody().has("client_id")).toBe(false);
      expect(getBody().has("client_secret")).toBe(false);
    });
  });

  describe("getToken after login", () => {
    it("returns the access token from login response", async () => {
      useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(await auth.getToken()).toBe("test-token");
    });
  });

  describe("getToken caching", () => {
    it("returns cached token without re-requesting", async () => {
      let callCount = 0;
      server.use(
        http.post(tokenEndpoint, async () => {
          callCount++;
          return HttpResponse.json({
            access_token: `token-${callCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );
      const auth = createTestAuth();
      await auth.login();
      await auth.getToken();
      await auth.getToken();
      expect(callCount).toBe(1);
    });

    it("throws before login", async () => {
      const auth = createTestAuth();
      await expect(auth.getToken()).rejects.toThrow();
    });
  });

  describe("status", () => {
    it("returns unauthenticated before login", async () => {
      const auth = createTestAuth();
      expect(await auth.status()).toEqual({
        authenticated: false,
        strategy: "client-credentials",
      });
    });

    it("returns authenticated after login", async () => {
      useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(await auth.status()).toEqual({
        authenticated: true,
        strategy: "client-credentials",
      });
    });
  });

  describe("logout", () => {
    it("after logout, getToken throws", async () => {
      useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      await auth.logout();
      await expect(auth.getToken()).rejects.toThrow();
    });

    it("after logout, status returns unauthenticated", async () => {
      useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      await auth.logout();
      expect(await auth.status()).toEqual({
        authenticated: false,
        strategy: "client-credentials",
      });
    });
  });

  describe("token expiry", () => {
    it("re-acquires token when expired", async () => {
      vi.useFakeTimers();
      let callCount = 0;
      server.use(
        http.post(tokenEndpoint, async () => {
          callCount++;
          return HttpResponse.json({
            access_token: `token-${callCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );
      const auth = createTestAuth();
      await auth.login();
      expect(await auth.getToken()).toBe("token-1");

      vi.advanceTimersByTime(3601 * 1000);

      expect(await auth.getToken()).toBe("token-2");
      expect(callCount).toBe(2);
      vi.useRealTimers();
    });

    it("does not re-acquire when token is still valid", async () => {
      vi.useFakeTimers();
      let callCount = 0;
      server.use(
        http.post(tokenEndpoint, async () => {
          callCount++;
          return HttpResponse.json({
            access_token: `token-${callCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );
      const auth = createTestAuth();
      await auth.login();

      vi.advanceTimersByTime(1800 * 1000);

      await auth.getToken();
      expect(callCount).toBe(1);
      vi.useRealTimers();
    });

    it("refreshes token within configurable threshold", async () => {
      vi.useFakeTimers();
      let callCount = 0;
      server.use(
        http.post(tokenEndpoint, async () => {
          callCount++;
          return HttpResponse.json({
            access_token: `token-${callCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );
      const auth = createTestAuth({ tokenRefreshThreshold: 300 });
      await auth.login();

      vi.advanceTimersByTime(3301 * 1000);

      expect(await auth.getToken()).toBe("token-2");
      expect(callCount).toBe(2);
      vi.useRealTimers();
    });
  });

  describe("login errors", () => {
    it("throws on 401 (invalid credentials)", async () => {
      server.use(
        http.post(tokenEndpoint, () => {
          return HttpResponse.json(
            { error: "invalid_client" },
            { status: 401 }
          );
        })
      );
      const auth = createTestAuth();
      await expect(auth.login()).rejects.toThrow();
    });

    it("throws on network/server error", async () => {
      server.use(
        http.post(tokenEndpoint, () => {
          return HttpResponse.error();
        })
      );
      const auth = createTestAuth();
      await expect(auth.login()).rejects.toThrow();
    });
  });
});
