import {
  describe,
  it,
  expect,
  vi,
  beforeAll,
  afterAll,
  afterEach,
} from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { createCliAuth } from "../index.js";
import { memoryStorage } from "../storage/memory.js";
import type { TokenSet } from "../types.js";
import { createServer } from "node:http";
import type { ServerResponse } from "node:http";
import type { CallbackResult } from "../config.js";

const server = setupServer();

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const authorizationEndpoint = "https://auth.example.com/authorize";
const tokenEndpoint = "https://auth.example.com/token";
const revocationEndpoint = "https://auth.example.com/revoke";

function useTokenEndpoint(
  handler?: Parameters<typeof http.post>[1]
) {
  server.use(
    http.post(
      tokenEndpoint,
      handler ??
        (() =>
          HttpResponse.json({
            access_token: "test-token",
            token_type: "Bearer",
            expires_in: 3600,
          }))
    )
  );
}

function createTestAuth(overrides: Record<string, unknown> = {}) {
  return createCliAuth({
    strategy: "authorization-code" as const,
    provider: { metadata: { authorizationEndpoint, tokenEndpoint } },
    clientId: "my-client",
    storage: memoryStorage<TokenSet>(),
    ...overrides,
  });
}

async function loginWithCallback(
  auth: ReturnType<typeof createTestAuth>,
  options?: {
    callbackQuery?: string;
  }
) {
  const onAuthorization = vi.fn();
  const loginPromise = auth.login({ onAuthorization });

  await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

  const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
  const redirectUri = authUrl.searchParams.get("redirect_uri")!;
  const state = authUrl.searchParams.get("state")!;

  const query =
    options?.callbackQuery ?? `code=test-auth-code&state=${state}`;
  await fetch(`${redirectUri}?${query}`);

  await loginPromise;

  return { authUrl, redirectUri, state, onAuthorization };
}

describe("authorization-code", () => {
  describe("login — core flow", () => {
    it("calls onAuthorization with correct authorization URL and exchanges code for token", async () => {
      let capturedTokenBody: URLSearchParams;
      useTokenEndpoint(async ({ request }) => {
        capturedTokenBody = new URLSearchParams(await request.text());
        return HttpResponse.json({
          access_token: "authcode-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "authcode-refresh-token",
        });
      });

      const auth = createTestAuth({ scope: "openid" });
      const { authUrl } = await loginWithCallback(auth);

      // Verify authorization URL params
      expect(authUrl.searchParams.get("response_type")).toBe("code");
      expect(authUrl.searchParams.get("client_id")).toBe("my-client");
      expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authUrl.searchParams.get("code_challenge")).toBeTruthy();
      expect(authUrl.searchParams.get("state")).toBeTruthy();
      expect(authUrl.searchParams.get("scope")).toBe("openid");

      // Verify redirect_uri uses 127.0.0.1
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      expect(redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);

      // Verify token exchange params
      expect(capturedTokenBody!.get("grant_type")).toBe("authorization_code");
      expect(capturedTokenBody!.get("code")).toBe("test-auth-code");
      expect(capturedTokenBody!.get("code_verifier")).toBeTruthy();
      expect(capturedTokenBody!.get("client_id")).toBe("my-client");

      expect(await auth.getToken()).toBe("authcode-access-token");
    });

    it("generates valid PKCE pair where code_challenge is S256 of code_verifier", async () => {
      let capturedTokenBody: URLSearchParams;
      useTokenEndpoint(async ({ request }) => {
        capturedTokenBody = new URLSearchParams(await request.text());
        return HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      const auth = createTestAuth();
      const { authUrl } = await loginWithCallback(auth);

      const codeChallenge = authUrl.searchParams.get("code_challenge")!;
      const codeVerifier = capturedTokenBody!.get("code_verifier")!;

      // Verify S256: base64url(sha256(code_verifier)) === code_challenge
      const { createHash } = await import("node:crypto");
      const expected = createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");
      expect(codeChallenge).toBe(expected);
    });

    it("generates different code_verifier and state for each login", async () => {
      useTokenEndpoint();

      const auth1 = createTestAuth();
      const { authUrl: url1 } = await loginWithCallback(auth1);

      const auth2 = createTestAuth();
      const { authUrl: url2 } = await loginWithCallback(auth2);

      expect(url1.searchParams.get("state")).not.toBe(
        url2.searchParams.get("state")
      );
      expect(url1.searchParams.get("code_challenge")).not.toBe(
        url2.searchParams.get("code_challenge")
      );
    });
  });

  describe("login — state validation", () => {
    it("rejects callback with mismatched state", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;

      // Fire callback without awaiting — avoid race between fetch completion and loginPromise rejection
      void fetch(`${redirectUri}?code=some-code&state=wrong-state`);

      await expect(loginPromise).rejects.toThrow();
    });
  });

  describe("login — callback server", () => {
    it("closes server after successful login", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();
      const { redirectUri } = await loginWithCallback(auth);

      // Server should be closed — fetch should fail
      await expect(fetch(redirectUri)).rejects.toThrow();
    });

    it("uses specified callbackPort", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({ callbackPort: 19022 });
      const { redirectUri } = await loginWithCallback(auth);

      expect(redirectUri).toBe("http://127.0.0.1:19022/callback");
    });

    it("uses random available port by default", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();
      const { redirectUri } = await loginWithCallback(auth);

      const port = Number(new URL(redirectUri).port);
      expect(port).toBeGreaterThan(0);
    });

    it("throws when fixed port is already in use", async () => {
      // Occupy the port
      const blocker = createServer();
      await new Promise<void>((resolve) =>
        blocker.listen(19023, "127.0.0.1", resolve)
      );

      try {
        const auth = createTestAuth({ callbackPort: 19023 });
        await expect(
          auth.login({ onAuthorization: vi.fn() })
        ).rejects.toThrow();
      } finally {
        await new Promise<void>((resolve) => blocker.close(() => resolve()));
      }
    });
  });

  describe("login — callbackPath", () => {
    it("uses custom callbackPath in redirect_uri", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({ callbackPath: "/oauth/callback" });
      const { redirectUri } = await loginWithCallback(auth);

      expect(new URL(redirectUri).pathname).toBe("/oauth/callback");
    });

    it("supports nested callbackPath", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({ callbackPath: "/auth/v1/callback" });
      const { redirectUri } = await loginWithCallback(auth);

      expect(new URL(redirectUri).pathname).toBe("/auth/v1/callback");
    });

    it("only responds to the configured callbackPath", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({ callbackPath: "/oauth/callback" });

      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });
      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;
      const base = new URL(redirectUri);

      // Hitting the default /callback path should 404 (login stays pending)
      const wrongPath = new URL(`/callback?code=test&state=${state}`, base);
      const res = await fetch(wrongPath);
      expect(res.status).toBe(404);

      // Hitting the configured path completes login
      await fetch(`${redirectUri}?code=test-auth-code&state=${state}`);
      await loginPromise;
      expect(await auth.getToken()).toBe("test-token");
    });

    it.each([
      ["callback", "no leading slash"],
      ["/callback?foo=bar", "contains query"],
      ["/callback#section", "contains fragment"],
      ["", "empty"],
    ])("rejects invalid callbackPath %j (%s)", (callbackPath) => {
      expect(() => createTestAuth({ callbackPath })).toThrow();
    });
  });

  describe("custom fetch", () => {
    it("uses config.fetch for token exchange", async () => {
      const fakeFetch = vi.fn<typeof fetch>().mockResolvedValue(
        Response.json({
          access_token: "custom-fetch-authcode-token",
          token_type: "Bearer",
          expires_in: 3600,
        })
      );

      const auth = createTestAuth({ fetch: fakeFetch });
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      // Use real global fetch to hit the loopback callback server
      await globalThis.fetch(`${redirectUri}?code=test-code&state=${state}`);
      await loginPromise;

      expect(await auth.getToken()).toBe("custom-fetch-authcode-token");
      expect(fakeFetch).toHaveBeenCalledOnce();
    });
  });

  describe("login — request parameters", () => {
    it("sends scope in authorization URL", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({ scope: "openid profile" });
      const { authUrl } = await loginWithCallback(auth);
      expect(authUrl.searchParams.get("scope")).toBe("openid profile");
    });

    it("sends resource to token endpoint", async () => {
      let capturedBody: URLSearchParams;
      useTokenEndpoint(async ({ request }) => {
        capturedBody = new URLSearchParams(await request.text());
        return HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      const auth = createTestAuth({ resource: "https://shopping.api" });
      await loginWithCallback(auth);
      expect(capturedBody!.get("resource")).toBe("https://shopping.api");
    });

    it("sends extraParams in authorization URL", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        extraParams: { organization_id: "org_123", ui_locales: "zh-CN" },
      });
      const { authUrl } = await loginWithCallback(auth);
      expect(authUrl.searchParams.get("organization_id")).toBe("org_123");
      expect(authUrl.searchParams.get("ui_locales")).toBe("zh-CN");
    });

    it("sends client_id to token endpoint", async () => {
      let capturedBody: URLSearchParams;
      useTokenEndpoint(async ({ request }) => {
        capturedBody = new URLSearchParams(await request.text());
        return HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);
      expect(capturedBody!.get("client_id")).toBe("my-client");
    });
  });

  describe("login — callback errors", () => {
    it("rejects when callback is missing code parameter", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      void fetch(`${redirectUri}?state=${state}`);

      await expect(loginPromise).rejects.toThrow();
    });

    it("rejects when callback contains error parameter", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      void fetch(
        `${redirectUri}?error=access_denied&error_description=User+denied&state=${state}`
      );

      await expect(loginPromise).rejects.toThrow();
    });
  });

  describe("getToken", () => {
    it("refreshes using refresh_token when token expires", async () => {
      vi.useFakeTimers();
      useTokenEndpoint(async ({ request }) => {
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
          refresh_token: "first-refresh-token",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);
      expect(await auth.getToken()).toBe("initial-token");

      vi.advanceTimersByTime(3601 * 1000);
      expect(await auth.getToken()).toBe("refreshed-token");
      vi.useRealTimers();
    });

    it("returns resource-specific token via refresh_token and sends resource in request", async () => {
      let refreshBody: URLSearchParams | undefined;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshBody = body;
          return HttpResponse.json({
            access_token: `token-for-${body.get("resource")}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-opaque-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "my-refresh-token",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      const token = await auth.getToken({ resource: "https://api.example.com" });

      expect(token).toBe("token-for-https://api.example.com");
      expect(refreshBody!.get("resource")).toBe("https://api.example.com");
      expect(refreshBody!.get("grant_type")).toBe("refresh_token");
    });

    it("caches resource token — second call does not trigger extra HTTP request", async () => {
      let refreshCallCount = 0;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshCallCount++;
          return HttpResponse.json({
            access_token: "resource-token",
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      await auth.getToken({ resource: "https://api.example.com" });
      await auth.getToken({ resource: "https://api.example.com" });

      expect(refreshCallCount).toBe(1);
    });

    it("returns different tokens for different resources", async () => {
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          return HttpResponse.json({
            access_token: `token-for-${body.get("resource")}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      const tokenA = await auth.getToken({ resource: "https://api-a.example.com" });
      const tokenB = await auth.getToken({ resource: "https://api-b.example.com" });

      expect(tokenA).toBe("token-for-https://api-a.example.com");
      expect(tokenB).toBe("token-for-https://api-b.example.com");
    });

    it("re-refreshes only the expired resource token", async () => {
      vi.useFakeTimers();
      let refreshCallCount = 0;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshCallCount++;
          return HttpResponse.json({
            access_token: `token-${body.get("resource")}-${refreshCallCount}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      // Fetch two resource tokens
      const tokenA1 = await auth.getToken({ resource: "https://api-a.example.com" });
      const tokenB1 = await auth.getToken({ resource: "https://api-b.example.com" });
      expect(refreshCallCount).toBe(2);

      // Expire both tokens
      vi.advanceTimersByTime(3601 * 1000);

      // Refresh resource A — should trigger one more refresh
      const tokenA2 = await auth.getToken({ resource: "https://api-a.example.com" });
      expect(tokenA2).not.toBe(tokenA1);
      expect(refreshCallCount).toBe(3);

      // Resource B should also be expired and trigger its own refresh
      const tokenB2 = await auth.getToken({ resource: "https://api-b.example.com" });
      expect(tokenB2).not.toBe(tokenB1);
      expect(refreshCallCount).toBe(4);

      vi.useRealTimers();
    });

    it("sends extraParams in refresh request and returns provider-specific token", async () => {
      let refreshBody: URLSearchParams | undefined;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshBody = body;
          return HttpResponse.json({
            access_token: `org-token-${body.get("organization_id")}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      const token = await auth.getToken({
        extraParams: { organization_id: "org_1" },
      });

      expect(token).toBe("org-token-org_1");
      expect(refreshBody!.get("organization_id")).toBe("org_1");
    });

    it("combines resource and extraParams in refresh request", async () => {
      let refreshBody: URLSearchParams | undefined;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshBody = body;
          return HttpResponse.json({
            access_token: "combined-token",
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      await auth.getToken({
        resource: "https://api.example.com",
        extraParams: { organization_id: "org_1" },
      });

      expect(refreshBody!.get("resource")).toBe("https://api.example.com");
      expect(refreshBody!.get("organization_id")).toBe("org_1");
    });

    it("caches tokens separately for different extraParams", async () => {
      let refreshCallCount = 0;
      useTokenEndpoint(async ({ request }) => {
        const body = new URLSearchParams(await request.text());

        if (body.get("grant_type") === "refresh_token") {
          refreshCallCount++;
          return HttpResponse.json({
            access_token: `token-${body.get("organization_id") ?? "none"}`,
            token_type: "Bearer",
            expires_in: 3600,
          });
        }

        return HttpResponse.json({
          access_token: "initial-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
        });
      });

      const auth = createTestAuth();
      await loginWithCallback(auth);

      const tokenOrg1 = await auth.getToken({
        extraParams: { organization_id: "org_1" },
      });
      const tokenOrg2 = await auth.getToken({
        extraParams: { organization_id: "org_2" },
      });

      expect(tokenOrg1).toBe("token-org_1");
      expect(tokenOrg2).toBe("token-org_2");
      expect(refreshCallCount).toBe(2);

      // Second calls should be cached
      await auth.getToken({ extraParams: { organization_id: "org_1" } });
      await auth.getToken({ extraParams: { organization_id: "org_2" } });
      expect(refreshCallCount).toBe(2);
    });
  });

  describe("error handling", () => {
    it("throws on token endpoint error status", async () => {
      server.use(
        http.post(tokenEndpoint, () =>
          HttpResponse.json(
            { error: "invalid_grant" },
            { status: 400 }
          )
        )
      );
      const auth = createTestAuth();
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      void fetch(`${redirectUri}?code=some-code&state=${state}`);

      await expect(loginPromise).rejects.toThrow();
    });

    it("throws on token endpoint network error", async () => {
      server.use(
        http.post(tokenEndpoint, () => HttpResponse.error())
      );
      const auth = createTestAuth();
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });

      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      void fetch(`${redirectUri}?code=some-code&state=${state}`);

      await expect(loginPromise).rejects.toThrow();
    });
  });

  describe("logout — token revocation", () => {
    it("revokes refresh token at revocation endpoint on logout", async () => {
      let revokeBody: URLSearchParams | undefined;
      server.use(
        http.post(revocationEndpoint, async ({ request }) => {
          revokeBody = new URLSearchParams(await request.text());
          return new HttpResponse(null, { status: 200 });
        })
      );
      useTokenEndpoint(() =>
        HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "rt-to-revoke",
        })
      );

      const auth = createTestAuth({
        provider: {
          metadata: { authorizationEndpoint, tokenEndpoint, revocationEndpoint },
        },
      });
      await loginWithCallback(auth);
      await auth.logout();

      expect(revokeBody).toBeDefined();
      expect(revokeBody!.get("client_id")).toBe("my-client");
      expect(revokeBody!.get("token")).toBe("rt-to-revoke");
    });

    it("does not call revocation endpoint when revocationEndpoint is not configured", async () => {
      let revokeCalled = false;
      server.use(
        http.post(revocationEndpoint, () => {
          revokeCalled = true;
          return new HttpResponse(null, { status: 200 });
        })
      );
      useTokenEndpoint(() =>
        HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "rt",
        })
      );

      const auth = createTestAuth();
      await loginWithCallback(auth);
      await auth.logout();

      expect(revokeCalled).toBe(false);
    });
  });

  describe("login — callbackSource default response", () => {
    async function triggerCallback(
      auth: ReturnType<typeof createTestAuth>,
      buildQuery: (state: string) => string
    ) {
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });
      // Attach a silent catch so the rejection does not surface as unhandled
      // while the test body awaits the fetch response first.
      loginPromise.catch(() => undefined);
      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      const response = await fetch(`${redirectUri}?${buildQuery(state)}`);
      return { response, loginPromise };
    }

    it("returns an HTML success page when no hook is configured and callback is valid", async () => {
      useTokenEndpoint();
      const auth = createTestAuth();

      const { response, loginPromise } = await triggerCallback(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe(
        "text/html; charset=utf-8"
      );
      const body = await response.text();
      expect(body).toContain("Authorization successful");
    });

    it("returns an HTML failure page on provider error callback (no hook)", async () => {
      const auth = createTestAuth();

      const { response, loginPromise } = await triggerCallback(
        auth,
        (state) =>
          `error=access_denied&error_description=User+denied&state=${state}`
      );
      await expect(loginPromise).rejects.toThrow();

      expect(response.status).toBe(400);
      expect(response.headers.get("content-type")).toBe(
        "text/html; charset=utf-8"
      );
      expect(await response.text()).toContain("Authorization failed");
    });

    it("returns an HTML failure page on state mismatch (no hook)", async () => {
      const auth = createTestAuth();

      const { response, loginPromise } = await triggerCallback(
        auth,
        () => `code=test-auth-code&state=tampered-state`
      );
      await expect(loginPromise).rejects.toThrow();

      expect(response.status).toBe(400);
      expect(response.headers.get("content-type")).toBe(
        "text/html; charset=utf-8"
      );
      expect(await response.text()).toContain("Authorization failed");
    });

    it("returns an HTML failure page when code and error are both missing (no hook)", async () => {
      const auth = createTestAuth();

      const { response, loginPromise } = await triggerCallback(
        auth,
        (state) => `state=${state}`
      );
      await expect(loginPromise).rejects.toThrow();

      expect(response.status).toBe(400);
      expect(response.headers.get("content-type")).toBe(
        "text/html; charset=utf-8"
      );
      expect(await response.text()).toContain("Authorization failed");
    });
  });

  describe("login — callbackSource hook", () => {
    async function triggerCallbackWithHook(
      auth: ReturnType<typeof createTestAuth>,
      buildQuery: (state: string) => string
    ) {
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });
      loginPromise.catch(() => undefined);
      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      const response = await fetch(`${redirectUri}?${buildQuery(state)}`);
      return { response, loginPromise };
    }

    function minimalWrite(res: ServerResponse) {
      res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
    }

    it("invokes hook with success=true and code-bearing callbackUrl on valid callback", async () => {
      useTokenEndpoint();
      const callbackSource = vi.fn(minimalWrite);
      const auth = createTestAuth({ callbackSource });

      const { loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(callbackSource).toHaveBeenCalledOnce();
      const call = callbackSource.mock.calls[0]!;
      const result = call[1] as CallbackResult;
      expect(result.success).toBe(true);
      expect(result.callbackUrl).toBeInstanceOf(URL);
      expect(result.callbackUrl.searchParams.get("code")).toBe(
        "test-auth-code"
      );
      expect(result.verifyError).toBeUndefined();
    });

    it("invokes hook with success=false and forwarded OAuth error on provider error callback", async () => {
      const callbackSource = vi.fn(minimalWrite);
      const auth = createTestAuth({ callbackSource });

      const { loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) =>
          `error=access_denied&error_description=User+denied&state=${state}`
      );
      await expect(loginPromise).rejects.toThrow(/access_denied/);

      expect(callbackSource).toHaveBeenCalledOnce();
      const result = callbackSource.mock.calls[0]![1] as CallbackResult;
      expect(result.success).toBe(false);
      expect(result.callbackUrl.searchParams.get("error")).toBe(
        "access_denied"
      );
      expect(result.callbackUrl.searchParams.get("error_description")).toBe(
        "User denied"
      );
      expect(result.verifyError).toBeUndefined();
    });

    it("invokes hook with verifyError='state_mismatch' when state does not match", async () => {
      const callbackSource = vi.fn(minimalWrite);
      const auth = createTestAuth({ callbackSource });

      const { loginPromise } = await triggerCallbackWithHook(
        auth,
        () => `code=test-auth-code&state=tampered-state`
      );
      await expect(loginPromise).rejects.toThrow();

      expect(callbackSource).toHaveBeenCalledOnce();
      const result = callbackSource.mock.calls[0]![1] as CallbackResult;
      expect(result.success).toBe(false);
      expect(result.verifyError).toBe("state_mismatch");
    });

    it("invokes hook with verifyError='missing_code' when code and error are both absent", async () => {
      const callbackSource = vi.fn(minimalWrite);
      const auth = createTestAuth({ callbackSource });

      const { loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) => `state=${state}`
      );
      await expect(loginPromise).rejects.toThrow();

      expect(callbackSource).toHaveBeenCalledOnce();
      const result = callbackSource.mock.calls[0]![1] as CallbackResult;
      expect(result.success).toBe(false);
      expect(result.verifyError).toBe("missing_code");
    });

    it("writes exactly the body and status the hook produced", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        callbackSource: (res) => {
          res
            .writeHead(201, { "Content-Type": "text/html; charset=utf-8" })
            .end("<h1>Hello from Acme</h1>");
        },
      });

      const { response, loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(response.status).toBe(201);
      expect(await response.text()).toBe("<h1>Hello from Acme</h1>");
    });

    it("supports redirecting the browser via the hook", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        callbackSource: (res) => {
          res
            .writeHead(302, { Location: "https://myapp.example/cli-success" })
            .end();
        },
      });

      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });
      loginPromise.catch(() => undefined);
      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      const response = await fetch(
        `${redirectUri}?code=test-auth-code&state=${state}`,
        { redirect: "manual" }
      );
      await loginPromise;

      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(
        "https://myapp.example/cli-success"
      );
    });

    it("awaits an async hook before resolving login", async () => {
      useTokenEndpoint();
      let asyncWorkDone = false;
      const auth = createTestAuth({
        callbackSource: async (res) => {
          await new Promise((r) => setTimeout(r, 30));
          asyncWorkDone = true;
          res
            .writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
            .end("<p>done</p>");
        },
      });

      const { response, loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(asyncWorkDone).toBe(true);
      expect(await response.text()).toBe("<p>done</p>");
    });

    it("passes through a developer-chosen Content-Type", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        callbackSource: (res) => {
          res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
          res.end("plain body");
        },
      });

      const { response, loginPromise } = await triggerCallbackWithHook(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(response.headers.get("content-type")).toBe(
        "text/plain; charset=utf-8"
      );
      expect(await response.text()).toBe("plain body");
    });
  });

  describe("login — callbackSource failure isolation", () => {
    async function runCallback(
      auth: ReturnType<typeof createTestAuth>,
      buildQuery: (state: string) => string
    ) {
      const onAuthorization = vi.fn();
      const loginPromise = auth.login({ onAuthorization });
      loginPromise.catch(() => undefined);
      await vi.waitFor(() => expect(onAuthorization).toHaveBeenCalled());

      const authUrl = new URL(onAuthorization.mock.calls[0]![0]);
      const redirectUri = authUrl.searchParams.get("redirect_uri")!;
      const state = authUrl.searchParams.get("state")!;

      const response = await fetch(`${redirectUri}?${buildQuery(state)}`);
      return { response, loginPromise };
    }

    it("sends 500 fallback and still resolves login when hook throws synchronously on success", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        callbackSource: () => {
          throw new Error("render bug");
        },
      });

      const { response, loginPromise } = await runCallback(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(response.status).toBe(500);
      expect(await auth.getToken()).toBe("test-token");
    });

    it("sends 500 fallback and still resolves login when hook rejects asynchronously on success", async () => {
      useTokenEndpoint();
      const auth = createTestAuth({
        callbackSource: async () => {
          await new Promise((r) => setTimeout(r, 10));
          throw new Error("async render bug");
        },
      });

      const { response, loginPromise } = await runCallback(
        auth,
        (state) => `code=test-auth-code&state=${state}`
      );
      await loginPromise;

      expect(response.status).toBe(500);
      expect(await auth.getToken()).toBe("test-token");
    });

    it("does not mask the original OAuth error when hook throws on error callback", async () => {
      const auth = createTestAuth({
        callbackSource: () => {
          throw new Error("this should not surface");
        },
      });

      const { response, loginPromise } = await runCallback(
        auth,
        (state) =>
          `error=access_denied&error_description=User+denied&state=${state}`
      );

      expect(response.status).toBe(500);
      await expect(loginPromise).rejects.toThrow(/access_denied/);
    });

    it("does not mask the original state-mismatch error when hook throws on state mismatch", async () => {
      const auth = createTestAuth({
        callbackSource: () => {
          throw new Error("this should not surface");
        },
      });

      const { response, loginPromise } = await runCallback(
        auth,
        () => `code=test-auth-code&state=tampered`
      );

      expect(response.status).toBe(500);
      await expect(loginPromise).rejects.toThrow(/State mismatch/);
    });
  });
});
