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
import { createServer } from "node:http";

const server = setupServer();

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const authorizationEndpoint = "https://auth.example.com/authorize";
const tokenEndpoint = "https://auth.example.com/token";

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
    provider: {
      authorizationEndpoint,
      tokenEndpoint,
      clientId: "my-client",
    },
    storage: {
      load: async () => undefined,
      save: async () => {},
      clear: async () => {},
    },
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
});
