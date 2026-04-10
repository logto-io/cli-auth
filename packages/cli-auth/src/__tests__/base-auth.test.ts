import { describe, it, expect, vi, afterEach } from "vitest";
import { BaseAuth } from "../base-auth.js";
import type { Storage, TokenResponse } from "../types.js";

// Minimal concrete subclass for testing BaseAuth behaviors
class TestAuth extends BaseAuth<"test"> {
  readonly onRefresh = vi.fn<(refreshToken?: string) => Promise<TokenResponse | undefined>>();

  constructor(storage: Storage, tokenRefreshThreshold?: number) {
    super({ storage, strategy: "test", tokenRefreshThreshold });
  }

  async login(response: TokenResponse) {
    await this.applyTokenResponse(response);
  }
}

function createMockStorage(): Storage {
  return {
    load: vi.fn<() => Promise<unknown>>().mockResolvedValue(undefined),
    save: vi.fn<(credential: unknown) => Promise<void>>().mockResolvedValue(undefined),
    clear: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
  };
}

const sampleToken: TokenResponse = {
  access_token: "access-1",
  token_type: "Bearer",
  expires_in: 3600,
  refresh_token: "refresh-1",
};

describe("BaseAuth", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe("getToken", () => {
    it("throws 'Not logged in' before login", async () => {
      const auth = new TestAuth(createMockStorage());
      await expect(auth.getToken()).rejects.toThrow("Not logged in");
    });

    it("returns access token after login", async () => {
      const auth = new TestAuth(createMockStorage());
      await auth.login(sampleToken);
      expect(await auth.getToken()).toBe("access-1");
    });

    it("caches token — no re-fetch when not expired", async () => {
      const auth = new TestAuth(createMockStorage());
      auth.onRefresh.mockResolvedValue({
        access_token: "access-2",
        token_type: "Bearer",
        expires_in: 3600,
      });
      await auth.login(sampleToken);

      await auth.getToken();
      await auth.getToken();
      await auth.getToken();

      expect(auth.onRefresh).not.toHaveBeenCalled();
    });
  });

  describe("status", () => {
    it("returns unauthenticated before login", async () => {
      const auth = new TestAuth(createMockStorage());
      expect(await auth.status()).toEqual({
        authenticated: false,
        strategy: "test",
      });
    });

    it("returns authenticated after login", async () => {
      const auth = new TestAuth(createMockStorage());
      await auth.login(sampleToken);
      expect(await auth.status()).toEqual({
        authenticated: true,
        strategy: "test",
      });
    });
  });

  describe("logout", () => {
    it("clears state — getToken throws after logout", async () => {
      const auth = new TestAuth(createMockStorage());
      await auth.login(sampleToken);
      await auth.logout();
      await expect(auth.getToken()).rejects.toThrow("Not logged in");
    });

    it("clears state — status returns unauthenticated after logout", async () => {
      const auth = new TestAuth(createMockStorage());
      await auth.login(sampleToken);
      await auth.logout();
      expect(await auth.status()).toEqual({
        authenticated: false,
        strategy: "test",
      });
    });

    it("calls storage.clear", async () => {
      const storage = createMockStorage();
      const auth = new TestAuth(storage);
      await auth.login(sampleToken);
      await auth.logout();
      expect(storage.clear).toHaveBeenCalledOnce();
    });
  });

  describe("token expiry", () => {
    it("calls onRefresh when token is expired", async () => {
      vi.useFakeTimers();
      const auth = new TestAuth(createMockStorage());
      auth.onRefresh.mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      await auth.login(sampleToken);

      // Advance past the 3600s expiry
      vi.advanceTimersByTime(3601 * 1000);

      expect(await auth.getToken()).toBe("access-refreshed");
      expect(auth.onRefresh).toHaveBeenCalledOnce();
      expect(auth.onRefresh).toHaveBeenCalledWith("refresh-1");
    });

    it("does NOT call onRefresh when token is still valid", async () => {
      vi.useFakeTimers();
      const auth = new TestAuth(createMockStorage());
      auth.onRefresh.mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      await auth.login(sampleToken);

      // Advance to halfway — token should still be valid
      vi.advanceTimersByTime(1800 * 1000);

      expect(await auth.getToken()).toBe("access-1");
      expect(auth.onRefresh).not.toHaveBeenCalled();
    });
  });

  describe("tokenRefreshThreshold", () => {
    it("refreshes within configurable threshold", async () => {
      vi.useFakeTimers();
      const auth = new TestAuth(createMockStorage(), 300);
      auth.onRefresh.mockResolvedValue({
        access_token: "access-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      await auth.login(sampleToken);

      // Advance to 3301s — within the 300s threshold before 3600s expiry
      vi.advanceTimersByTime(3301 * 1000);

      expect(await auth.getToken()).toBe("access-threshold");
      expect(auth.onRefresh).toHaveBeenCalledOnce();
    });
  });

  describe("onRefresh returns undefined", () => {
    it("throws when token is expired and onRefresh returns undefined", async () => {
      vi.useFakeTimers();
      const auth = new TestAuth(createMockStorage());
      auth.onRefresh.mockResolvedValue(undefined);
      await auth.login(sampleToken);

      // Expire the token
      vi.advanceTimersByTime(3601 * 1000);

      await expect(auth.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
      expect(auth.onRefresh).toHaveBeenCalledOnce();
    });
  });

  describe("applyTokenResponse", () => {
    it("saves to storage", async () => {
      const storage = createMockStorage();
      const auth = new TestAuth(storage);
      await auth.login(sampleToken);
      expect(storage.save).toHaveBeenCalledOnce();
      expect(storage.save).toHaveBeenCalledWith(sampleToken);
    });
  });
});
