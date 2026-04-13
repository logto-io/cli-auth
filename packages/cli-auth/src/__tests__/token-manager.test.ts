import { describe, it, expect, vi, afterEach } from "vitest";
import { TokenManager } from "../token-manager.js";
import type { Storage, TokenResponse } from "../types.js";

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

describe("TokenManager", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe("getToken", () => {
    it("throws when no token available", async () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      await expect(manager.getToken()).rejects.toThrow("No token available.");
    });

    it("returns access token after save", async () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      await manager.save(sampleToken);
      expect(await manager.getToken()).toBe("access-1");
    });

    it("caches token — no refresh when not expired", async () => {
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>();
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      await manager.getToken();
      await manager.getToken();
      await manager.getToken();

      expect(refresh).not.toHaveBeenCalled();
    });
  });

  describe("token expiry", () => {
    it("calls refresh when token is expired", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      expect(await manager.getToken()).toBe("access-refreshed");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("passes current refresh token to refresh callback", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken?: string) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);
      await manager.getToken();

      expect(refresh).toHaveBeenCalledWith("refresh-1");
    });

    it("does NOT call refresh when token is still valid", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>();
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(1800 * 1000);

      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();
    });
  });

  describe("tokenRefreshThreshold", () => {
    it("defaults to 300 seconds when not configured", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-default-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      // At 3299s — outside the 300s default threshold, should NOT refresh
      vi.advanceTimersByTime(3299 * 1000);
      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();

      // At 3301s — within the 300s default threshold, should refresh
      vi.advanceTimersByTime(2 * 1000);
      expect(await manager.getToken()).toBe("access-default-threshold");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("refreshes within configurable threshold", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({
        storage: createMockStorage(),
        refresh,
        tokenRefreshThreshold: 600,
      });
      await manager.save(sampleToken);

      // Advance to 3001s — within the 600s threshold before 3600s expiry
      vi.advanceTimersByTime(3001 * 1000);

      expect(await manager.getToken()).toBe("access-threshold");
      expect(refresh).toHaveBeenCalledOnce();
    });
  });

  describe("refresh returns undefined", () => {
    it("throws when token is expired and refresh returns undefined", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<() => Promise<TokenResponse | undefined>>().mockResolvedValue(undefined);
      const manager = new TokenManager({ storage: createMockStorage(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("throws when token is expired and no refresh callback provided", async () => {
      vi.useFakeTimers();
      const manager = new TokenManager({ storage: createMockStorage() });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
    });
  });

  describe("save", () => {
    it("saves to storage", async () => {
      const storage = createMockStorage();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      expect(storage.save).toHaveBeenCalledOnce();
      expect(storage.save).toHaveBeenCalledWith(sampleToken);
    });
  });

  describe("clear", () => {
    it("clears state — getToken throws after clear", async () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      await manager.save(sampleToken);
      await manager.clear();
      await expect(manager.getToken()).rejects.toThrow("No token available.");
    });

    it("calls storage.clear", async () => {
      const storage = createMockStorage();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      await manager.clear();
      expect(storage.clear).toHaveBeenCalledOnce();
    });
  });

  describe("hasToken", () => {
    it("returns false before save", () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      expect(manager.hasToken).toBe(false);
    });

    it("returns true after save", async () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      await manager.save(sampleToken);
      expect(manager.hasToken).toBe(true);
    });

    it("returns false after clear", async () => {
      const manager = new TokenManager({ storage: createMockStorage() });
      await manager.save(sampleToken);
      await manager.clear();
      expect(manager.hasToken).toBe(false);
    });
  });
});
