import { describe, it, expect, vi, afterEach } from "vitest";
import { TokenManager } from "../token-manager.js";
import { memoryStorage } from "../storage/memory.js";
import type { GetTokenOptions, Storage, TokenResponse, TokenSet } from "../types.js";

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
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await expect(manager.getToken()).rejects.toThrow("No token available.");
    });

    it("returns access token after save", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      expect(await manager.getToken()).toBe("access-1");
    });

    it("caches token — no refresh when not expired", async () => {
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>();
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
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
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      expect(await manager.getToken()).toBe("access-refreshed");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("passes current refresh token to refresh callback", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);
      await manager.getToken();

      expect(refresh).toHaveBeenCalledWith("refresh-1", undefined);
    });

    it("does NOT call refresh when token is still valid", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>();
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(1800 * 1000);

      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();
    });
  });

  describe("tokenRefreshThreshold", () => {
    it("defaults to 300 seconds when not configured", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-default-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
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
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({
        storage: memoryStorage<TokenSet>(),
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
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue(undefined);
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("throws when token is expired and no refresh callback provided", async () => {
      vi.useFakeTimers();
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
    });
  });

  describe("save", () => {
    it("persists credential to storage as TokenSet", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      const stored = await storage.load();
      expect(stored?.refresh_token).toBe("refresh-1");
      expect(stored?.tokens[""]?.access_token).toBe("access-1");
      expect(stored?.tokens[""]?.expires_at).toBeGreaterThan(Date.now() - 1000);
    });
  });

  describe("clear", () => {
    it("clears state — getToken throws after clear", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      await manager.clear();
      await expect(manager.getToken()).rejects.toThrow("No token available.");
    });

    it("clears storage", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      await manager.clear();
      expect(await storage.load()).toBeUndefined();
    });
  });

  describe("lock integration", () => {
    it("concurrent getToken calls only refresh once when storage has lock", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });

      // In-process mutex: lock() acquires, returns release function
      let pending = Promise.resolve();
      const lock = async () => {
        const previous = pending;
        let release!: () => void;
        pending = new Promise<void>((r) => {
          release = r;
        });
        await previous;
        return async () => release();
      };

      const storage: Storage<TokenSet> = {
        ...memoryStorage<TokenSet>(),
        lock,
      };

      const manager = new TokenManager({ storage, refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      const [t1, t2] = await Promise.all([manager.getToken(), manager.getToken()]);

      expect(refresh).toHaveBeenCalledOnce();
      expect(t1).toBe("refreshed");
      expect(t2).toBe("refreshed");
    });

    it("refreshes without lock when storage does not provide it", async () => {
      vi.useFakeTimers();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed-no-lock",
        token_type: "Bearer",
        expires_in: 3600,
      });

      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save(sampleToken);

      vi.advanceTimersByTime(3601 * 1000);

      const token = await manager.getToken();
      expect(token).toBe("refreshed-no-lock");
      expect(refresh).toHaveBeenCalledOnce();
    });
  });

  describe("multi-token persistence", () => {
    it("persists multiple resource tokens to storage", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      await manager.save(
        { access_token: "res-token", token_type: "Bearer", expires_in: 3600 },
        { resource: "https://api.example.com" }
      );

      const stored = await storage.load();
      expect(stored?.tokens[""]?.access_token).toBe("access-1");
      expect(stored?.tokens["resource=https://api.example.com"]?.access_token).toBe("res-token");
      expect(stored?.refresh_token).toBe("refresh-1");
    });

    it("new instance restores tokens from storage", async () => {
      const storage = memoryStorage<TokenSet>();

      // Instance A saves tokens
      const managerA = new TokenManager({ storage });
      await managerA.save(sampleToken);
      await managerA.save(
        { access_token: "res-token", token_type: "Bearer", expires_in: 3600 },
        { resource: "https://api.example.com" }
      );

      // Instance B uses the same storage — should recover tokens
      const managerB = new TokenManager({ storage });
      await managerB.load();
      expect(await managerB.getToken()).toBe("access-1");
      expect(await managerB.getToken({ resource: "https://api.example.com" })).toBe("res-token");
    });

    it("new instance restores refresh token from storage", async () => {
      vi.useFakeTimers();
      const storage = memoryStorage<TokenSet>();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });

      // Instance A saves token with refresh_token
      const managerA = new TokenManager({ storage, refresh });
      await managerA.save(sampleToken);

      // Instance B loads from storage, expires, should use restored refresh_token
      const managerB = new TokenManager({ storage, refresh });
      await managerB.load();

      vi.advanceTimersByTime(3601 * 1000);

      await managerB.getToken();
      expect(refresh).toHaveBeenCalledWith("refresh-1", undefined);
      vi.useRealTimers();
    });

    it("load does nothing when storage is empty", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });
      await manager.load();
      expect(manager.hasToken).toBe(false);
    });

    it("clear removes all cached resource tokens", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });
      await manager.save(sampleToken);
      await manager.save(
        { access_token: "res-token", token_type: "Bearer", expires_in: 3600 },
        { resource: "https://api.example.com" }
      );

      await manager.clear();

      expect(await storage.load()).toBeUndefined();
      await expect(manager.getToken()).rejects.toThrow("No token available.");
      await expect(
        manager.getToken({ resource: "https://api.example.com" })
      ).rejects.toThrow("No token available.");
    });
  });

  describe("shared refresh token", () => {
    it("refresh token is shared: refreshing resource A updates the token used for resource B", async () => {
      vi.useFakeTimers();
      const refreshCalls: string[] = [];
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>()
        .mockImplementation(async (rt) => {
          refreshCalls.push(rt ?? "none");
          return {
            access_token: "refreshed",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: `rotated-${refreshCalls.length}`,
          };
        });

      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh });
      await manager.save({
        access_token: "default",
        token_type: "Bearer",
        expires_in: 1,
        refresh_token: "original-rt",
      });
      await manager.save(
        { access_token: "res-a", token_type: "Bearer", expires_in: 1 },
        { resource: "https://api-a.example.com" }
      );

      vi.advanceTimersByTime(2000);

      // Refresh resource A — uses original refresh token
      await manager.getToken({ resource: "https://api-a.example.com" });
      expect(refreshCalls[0]).toBe("original-rt");

      // Refresh default — should use the rotated refresh token
      await manager.getToken();
      expect(refreshCalls[1]).toBe("rotated-1");

      vi.useRealTimers();
    });

    it("throws when no refresh callback and no cached token for resource", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);

      await expect(
        manager.getToken({ resource: "https://api.example.com" })
      ).rejects.toThrow("Token expired and cannot be refreshed.");
    });
  });

  describe("hasToken", () => {
    it("returns false before save", () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      expect(manager.hasToken).toBe(false);
    });

    it("returns true after save", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      expect(manager.hasToken).toBe(true);
    });

    it("returns false after clear", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      await manager.clear();
      expect(manager.hasToken).toBe(false);
    });
  });
});
