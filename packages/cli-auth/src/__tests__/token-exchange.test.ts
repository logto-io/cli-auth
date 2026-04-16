import { describe, it, expect, vi, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { createCliAuth } from "../index.js";
import type { TokenSet } from "../types.js";

const server = setupServer();

beforeAll(() => server.listen());
beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
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
        refresh_token: "test-refresh-token",
      });
    })
  );
  return {
    getBody: () => capturedBody,
    getHeaders: () => capturedHeaders,
  };
}

function createTestAuth(overrides: Record<string, unknown> = {}) {
  let stored: TokenSet | undefined;
  return createCliAuth({
    strategy: "token-exchange",
    provider: { type: "oidc", metadata: { tokenEndpoint } },
    clientId: "my-client",
    subjectToken: "pat_abc123",
    subjectTokenType: "urn:logto:token-type:personal_access_token",
    storage: {
      load: async () => stored,
      save: async (credential: TokenSet) => {
        stored = credential;
      },
      clear: async () => {
        stored = undefined;
      },
    },
    ...overrides,
  });
}

describe("token-exchange", () => {
  describe("login — public client", () => {
    it("sends grant_type=urn:ietf:params:oauth:grant-type:token-exchange", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().get("grant_type")).toBe(
        "urn:ietf:params:oauth:grant-type:token-exchange"
      );
    });

    it("sends subject_token and subject_token_type in request body", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().get("subject_token")).toBe("pat_abc123");
      expect(getBody().get("subject_token_type")).toBe(
        "urn:logto:token-type:personal_access_token"
      );
    });

    it("sends client_id in request body for public client", async () => {
      const { getBody, getHeaders } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().get("client_id")).toBe("my-client");
      expect(getHeaders().get("Authorization")).toBeNull();
    });

    it("sends resource in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({ resource: "https://api.example.com" });
      await auth.login();
      expect(getBody().get("resource")).toBe("https://api.example.com");
    });

    it("sends scope in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({ scope: "read write" });
      await auth.login();
      expect(getBody().get("scope")).toBe("read write");
    });

    it("sends extra params in request body when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        extraParams: { organization_id: "org_123" },
      });
      await auth.login();
      expect(getBody().get("organization_id")).toBe("org_123");
    });

    it("returns access token via getToken after login", async () => {
      useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(await auth.getToken()).toBe("test-token");
    });
  });

  describe("login — client_secret_post (default)", () => {
    it("sends client_id and client_secret in request body", async () => {
      const { getBody, getHeaders } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        clientSecret: "my-secret",
      });
      await auth.login();
      expect(getBody().get("client_id")).toBe("my-client");
      expect(getBody().get("client_secret")).toBe("my-secret");
      expect(getHeaders().get("Authorization")).toBeNull();
    });
  });

  describe("login — client_secret_basic", () => {
    it("sends Basic auth header and omits client_id/client_secret from body", async () => {
      const { getBody, getHeaders } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        clientSecret: "my-secret",
        tokenEndpointAuthMethod: "client_secret_basic",
      });
      await auth.login();
      expect(getHeaders().get("Authorization")).toBe(
        `Basic ${btoa("my-client:my-secret")}`
      );
      expect(getBody().has("client_id")).toBe(false);
      expect(getBody().has("client_secret")).toBe(false);
    });
  });

  describe("login — actor token", () => {
    it("includes actor_token and actor_token_type when configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        actorToken: "sarah_access_token",
        actorTokenType: "urn:ietf:params:oauth:token-type:access_token",
      });
      await auth.login();
      expect(getBody().get("actor_token")).toBe("sarah_access_token");
      expect(getBody().get("actor_token_type")).toBe(
        "urn:ietf:params:oauth:token-type:access_token"
      );
    });

    it("omits actor_token and actor_token_type when not configured", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth();
      await auth.login();
      expect(getBody().has("actor_token")).toBe(false);
      expect(getBody().has("actor_token_type")).toBe(false);
    });
  });

  describe("custom fetch", () => {
    it("uses config.fetch for token exchange requests", async () => {
      const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
        Response.json({
          access_token: "custom-fetch-exchange-token",
          token_type: "Bearer",
          expires_in: 3600,
        })
      );

      const auth = createTestAuth({ fetch: fakeFetch });
      await auth.login();

      expect(await auth.getToken()).toBe("custom-fetch-exchange-token");
      expect(fakeFetch).toHaveBeenCalledOnce();
    });
  });

  describe("getToken — refresh", () => {
    it("refreshes via refresh_token grant when token expires and refresh token is available", async () => {
      server.use(
        http.post(tokenEndpoint, async ({ request }) => {
          const body = await request.text();
          const params = new URLSearchParams(body);

          if (params.get("grant_type") === "refresh_token") {
            return HttpResponse.json({
              access_token: "refreshed-token",
              token_type: "Bearer",
              expires_in: 3600,
              refresh_token: "new-refresh-token",
            });
          }

          return HttpResponse.json({
            access_token: "initial-token",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "rt-1",
          });
        })
      );

      let stored: TokenSet | undefined;
      const auth = createTestAuth({
        storage: {
          load: async () => stored,
          save: async (credential: TokenSet) => {
            stored = credential;
          },
          clear: async () => {
            stored = undefined;
          },
        },
      });

      await auth.login();
      expect(await auth.getToken()).toBe("initial-token");

      vi.advanceTimersByTime(3601 * 1000);
      expect(await auth.getToken()).toBe("refreshed-token");
    });

    it("re-exchanges subject token when token expires and no refresh token", async () => {
      let callCount = 0;
      server.use(
        http.post(tokenEndpoint, async ({ request }) => {
          callCount++;
          const body = await request.text();
          const params = new URLSearchParams(body);
          // Both calls should be token-exchange, not refresh_token
          expect(params.get("grant_type")).toBe(
            "urn:ietf:params:oauth:grant-type:token-exchange"
          );
          expect(params.get("subject_token")).toBe("pat_abc123");
          return HttpResponse.json({
            access_token: `token-${callCount}`,
            token_type: "Bearer",
            expires_in: callCount === 1 ? 0 : 3600,
          });
        })
      );

      const auth = createTestAuth();
      await auth.login();
      const token = await auth.getToken();
      expect(token).toBe("token-2");
      expect(callCount).toBe(2);
    });
  });
});
