import {
  describe,
  it,
  expect,
  vi,
  beforeAll,
  beforeEach,
  afterAll,
  afterEach,
} from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { createCliAuth } from "../index.js";
import { memoryStorage } from "../storage/memory.js";
import type { TokenSet } from "../types.js";

const server = setupServer();

beforeAll(() => server.listen());
beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

const deviceAuthEndpoint = "https://auth.example.com/device/authorize";
const tokenEndpoint = "https://auth.example.com/token";
const revocationEndpoint = "https://auth.example.com/revoke";

function useDeviceAuthMock(
  tokenHandler?: Parameters<typeof http.post>[1]
) {
  server.use(
    http.post(deviceAuthEndpoint, () =>
      HttpResponse.json({
        device_code: "dev-code",
        user_code: "ABCD-1234",
        verification_uri: "https://auth.example.com/verify",
        verification_uri_complete:
          "https://auth.example.com/verify?code=ABCD-1234",
        expires_in: 300,
        interval: 1,
      })
    ),
    http.post(
      tokenEndpoint,
      tokenHandler ??
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
    strategy: "device-code" as const,
    provider: { metadata: { tokenEndpoint, deviceAuthorizationEndpoint: deviceAuthEndpoint } },
    clientId: "my-client",
    storage: memoryStorage<TokenSet>(),
    ...overrides,
  });
}

async function loginWithFakeTimers(
  auth: ReturnType<typeof createTestAuth>,
  advanceMs = 1000
) {
  const loginPromise = auth.login({ onAuthorization: vi.fn() });
  await vi.advanceTimersByTimeAsync(advanceMs);
  await loginPromise;
}

describe("device-code", () => {
  describe("login", () => {
    it("initiates device code flow, calls onAuthorization, polls for token", async () => {
      useDeviceAuthMock(
        (() => {
          let pollCount = 0;
          return () => {
            pollCount++;
            if (pollCount === 1) {
              return HttpResponse.json(
                { error: "authorization_pending" },
                { status: 400 }
              );
            }
            return HttpResponse.json({
              access_token: "device-access-token",
              token_type: "Bearer",
              expires_in: 3600,
              refresh_token: "device-refresh-token",
            });
          };
        })()
      );

      const onAuthorization = vi.fn();
      const auth = createTestAuth({ scope: "openid" });

      const loginPromise = auth.login({ onAuthorization });
      // First poll: authorization_pending; second poll: success
      await vi.advanceTimersByTimeAsync(2000);
      await loginPromise;

      expect(onAuthorization).toHaveBeenCalledWith(
        expect.objectContaining({
          userCode: "ABCD-1234",
          verificationUri: "https://auth.example.com/verify",
          verificationUriComplete:
            "https://auth.example.com/verify?code=ABCD-1234",
          expiresIn: 300,
        })
      );

      expect(await auth.getToken()).toBe("device-access-token");
    });
  });

  describe("getToken", () => {
    it("refreshes using refresh_token when token expires", async () => {
      useDeviceAuthMock(async ({ request }) => {
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
          refresh_token: "device-refresh-token",
        });
      });

      const stored: Record<string, unknown> = {};
      const auth = createTestAuth({
        storage: {
          load: async () => stored.credential,
          save: async (credential: unknown) => {
            stored.credential = credential;
          },
          clear: async () => {
            delete stored.credential;
          },
        },
      });

      await loginWithFakeTimers(auth);
      expect(await auth.getToken()).toBe("initial-token");

      vi.advanceTimersByTime(3601 * 1000);
      expect(await auth.getToken()).toBe("refreshed-token");
    });
  });

  describe("error handling", () => {
    it("throws when device code expires (expired_token)", async () => {
      useDeviceAuthMock(() =>
        HttpResponse.json({ error: "expired_token" }, { status: 400 })
      );
      const auth = createTestAuth();

      const loginPromise = auth.login({ onAuthorization: vi.fn() });
      const expectation = expect(loginPromise).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(1000);
      await expectation;
    });

    it("throws when user denies access (access_denied)", async () => {
      useDeviceAuthMock(() =>
        HttpResponse.json({ error: "access_denied" }, { status: 400 })
      );
      const auth = createTestAuth();

      const loginPromise = auth.login({ onAuthorization: vi.fn() });
      const expectation = expect(loginPromise).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(1000);
      await expectation;
    });

    it("increases polling interval by 5 seconds on slow_down", async () => {
      const pollTimestamps: number[] = [];
      let pollCount = 0;

      useDeviceAuthMock(() => {
        pollCount++;
        pollTimestamps.push(Date.now());
        if (pollCount === 1) {
          return HttpResponse.json(
            { error: "slow_down" },
            { status: 400 }
          );
        }
        return HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      const auth = createTestAuth();
      const loginPromise = auth.login({ onAuthorization: vi.fn() });

      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(6000);
      await loginPromise;

      expect(pollCount).toBe(2);
      const gap = pollTimestamps[1]! - pollTimestamps[0]!;
      expect(gap).toBe(6000);
    });
  });

  describe("custom fetch", () => {
    it("uses config.fetch for device authorization and token polling", async () => {
      let callCount = 0;
      const fakeFetch = vi.fn<typeof fetch>().mockImplementation(async (input) => {
        callCount++;
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === deviceAuthEndpoint) {
          return Response.json({
            device_code: "dev-code",
            user_code: "ABCD-1234",
            verification_uri: "https://auth.example.com/verify",
            expires_in: 300,
            interval: 1,
          });
        }
        // Token endpoint — succeed immediately
        return Response.json({
          access_token: "custom-fetch-device-token",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      const auth = createTestAuth({ fetch: fakeFetch });
      const loginPromise = auth.login({ onAuthorization: vi.fn() });
      await vi.advanceTimersByTimeAsync(1000);
      await loginPromise;

      expect(await auth.getToken()).toBe("custom-fetch-device-token");
      // At least 2 calls: device auth + token poll
      expect(fakeFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe("request parameters", () => {
    function useCaptureEndpoints() {
      let capturedDeviceAuthBody: URLSearchParams;
      let capturedTokenBody: URLSearchParams;
      server.use(
        http.post(deviceAuthEndpoint, async ({ request }) => {
          capturedDeviceAuthBody = new URLSearchParams(await request.text());
          return HttpResponse.json({
            device_code: "dev-code",
            user_code: "CODE",
            verification_uri: "https://auth.example.com/verify",
            expires_in: 300,
            interval: 1,
          });
        }),
        http.post(tokenEndpoint, async ({ request }) => {
          capturedTokenBody = new URLSearchParams(await request.text());
          return HttpResponse.json({
            access_token: "tok",
            token_type: "Bearer",
            expires_in: 3600,
          });
        })
      );
      return {
        getDeviceAuthBody: () => capturedDeviceAuthBody,
        getTokenBody: () => capturedTokenBody,
      };
    }

    it("sends client_id and scope to device authorization endpoint", async () => {
      const { getDeviceAuthBody } = useCaptureEndpoints();
      const auth = createTestAuth({ scope: "openid offline_access" });
      await loginWithFakeTimers(auth);
      expect(getDeviceAuthBody().get("client_id")).toBe("my-client");
      expect(getDeviceAuthBody().get("scope")).toBe("openid offline_access");
    });

    it("sends resource to device authorization endpoint", async () => {
      const { getDeviceAuthBody } = useCaptureEndpoints();
      const auth = createTestAuth({ resource: "https://shopping.api" });
      await loginWithFakeTimers(auth);
      expect(getDeviceAuthBody().get("resource")).toBe("https://shopping.api");
    });

    it("sends resource to token endpoint", async () => {
      const { getTokenBody } = useCaptureEndpoints();
      const auth = createTestAuth({ resource: "https://shopping.api" });
      await loginWithFakeTimers(auth);
      expect(getTokenBody().get("resource")).toBe("https://shopping.api");
    });

    it("sends extraParams to device authorization endpoint", async () => {
      const { getDeviceAuthBody } = useCaptureEndpoints();
      const auth = createTestAuth({
        extraParams: { organization_id: "org_123", ui_locales: "zh-CN" },
      });
      await loginWithFakeTimers(auth);
      expect(getDeviceAuthBody().get("organization_id")).toBe("org_123");
      expect(getDeviceAuthBody().get("ui_locales")).toBe("zh-CN");
    });

    it("sends correct grant_type to token endpoint", async () => {
      const { getTokenBody } = useCaptureEndpoints();
      const auth = createTestAuth();
      await loginWithFakeTimers(auth);
      expect(getTokenBody().get("grant_type")).toBe(
        "urn:ietf:params:oauth:grant-type:device_code"
      );
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
      useDeviceAuthMock(() =>
        HttpResponse.json({
          access_token: "tok",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "device-rt",
        })
      );

      const auth = createTestAuth({
        provider: {
          metadata: { tokenEndpoint, deviceAuthorizationEndpoint: deviceAuthEndpoint, revocationEndpoint },
        },
      });
      await loginWithFakeTimers(auth);
      vi.useRealTimers();
      await auth.logout();

      expect(revokeBody).toBeDefined();
      expect(revokeBody!.get("client_id")).toBe("my-client");
      expect(revokeBody!.get("token")).toBe("device-rt");
    });
  });
});
