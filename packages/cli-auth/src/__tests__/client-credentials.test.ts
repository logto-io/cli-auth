import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { createCliAuth } from "../index.js";
import type { TokenSet } from "../types.js";

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
  let stored: TokenSet | undefined;
  return createCliAuth({
    strategy: "client-credentials",
    provider: { type: "oidc", metadata: { tokenEndpoint } },
    clientId: "my-client",
    clientSecret: "my-secret",
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
        tokenEndpointAuthMethod: "client_secret_basic",
      });
      await auth.login();
      const expected = `Basic ${btoa("my-client:my-secret")}`;
      expect(getHeaders().get("Authorization")).toBe(expected);
    });

    it("does not include client_id or client_secret in request body", async () => {
      const { getBody } = useCaptureTokenEndpoint();
      const auth = createTestAuth({
        tokenEndpointAuthMethod: "client_secret_basic",
      });
      await auth.login();
      expect(getBody().has("client_id")).toBe(false);
      expect(getBody().has("client_secret")).toBe(false);
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

  describe("getToken with resource", () => {
    it("fetches token with resource param via client_credentials grant", async () => {
      let requestBodies: URLSearchParams[] = [];
      server.use(
        http.post(tokenEndpoint, async ({ request }) => {
          const body = new URLSearchParams(await request.text());
          requestBodies.push(body);
          const resource = body.get("resource");
          return HttpResponse.json({
            access_token: resource ? `token-for-${resource}` : "default-token",
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );

      const auth = createTestAuth();
      await auth.login();

      const token = await auth.getToken({ resource: "https://api.example.com" });

      expect(token).toBe("token-for-https://api.example.com");
      // Should have made a second request (login + getToken)
      expect(requestBodies).toHaveLength(2);
      expect(requestBodies[1]!.get("grant_type")).toBe("client_credentials");
      expect(requestBodies[1]!.get("resource")).toBe("https://api.example.com");
    });

    it("caches resource tokens separately", async () => {
      let requestCount = 0;
      server.use(
        http.post(tokenEndpoint, async ({ request }) => {
          requestCount++;
          const body = new URLSearchParams(await request.text());
          return HttpResponse.json({
            access_token: `token-${requestCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );

      const auth = createTestAuth();
      await auth.login(); // request 1

      await auth.getToken({ resource: "https://api-a.example.com" }); // request 2
      await auth.getToken({ resource: "https://api-a.example.com" }); // cached
      expect(requestCount).toBe(2);

      await auth.getToken({ resource: "https://api-b.example.com" }); // request 3
      expect(requestCount).toBe(3);
    });

    it("uses config.fetch for token requests when provided", async () => {
      const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
        Response.json({
          access_token: "custom-fetch-token",
          token_type: "Bearer",
          expires_in: 3600,
        })
      );

      const auth = createTestAuth({ fetch: fakeFetch });
      await auth.login();

      const token = await auth.getToken();
      expect(token).toBe("custom-fetch-token");
      expect(fakeFetch).toHaveBeenCalled();
    });

    it("sends extraParams in client_credentials request", async () => {
      let capturedBody: URLSearchParams | undefined;
      server.use(
        http.post(tokenEndpoint, async ({ request }) => {
          capturedBody = new URLSearchParams(await request.text());
          return HttpResponse.json({
            access_token: "test-token",
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );

      const auth = createTestAuth();
      await auth.login();

      await auth.getToken({ extraParams: { organization_id: "org_1" } });

      expect(capturedBody!.get("organization_id")).toBe("org_1");
    });
  });
});
