import { describe, it, expect, vi } from "vitest";
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

    it("reads from storage — no refresh when not expired", async () => {
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
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;

      expect(await manager.getToken()).toBe("access-refreshed");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("passes current refresh token to refresh callback", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;
      await manager.getToken();

      expect(refresh).toHaveBeenCalledWith("refresh-1", undefined);
    });

    it("does NOT call refresh when token is still valid", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>();
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 1800 * 1000;

      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();
    });
  });

  describe("tokenRefreshThreshold", () => {
    it("defaults to 300 seconds when not configured", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-default-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      // Token saved at 1_000_000, expires_at = 4_600_000, threshold boundary = 4_300_000

      // At 3299s after save — outside the 300s default threshold, should NOT refresh
      currentTime = 1_000_000 + 3299 * 1000;
      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();

      // At 3301s after save — within the 300s default threshold, should refresh
      currentTime = 1_000_000 + 3301 * 1000;
      expect(await manager.getToken()).toBe("access-default-threshold");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("refreshes within configurable threshold", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "access-threshold",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({
        storage: memoryStorage<TokenSet>(),
        refresh,
        tokenRefreshThreshold: 600,
        now: () => currentTime,
      });
      await manager.save(sampleToken);

      // Token saved at 1_000_000, expires_at = 4_600_000, threshold 600s → boundary = 4_000_000
      currentTime = 1_000_000 + 3001 * 1000;

      expect(await manager.getToken()).toBe("access-threshold");
      expect(refresh).toHaveBeenCalledOnce();
    });
  });

  describe("refresh returns undefined", () => {
    it("throws when token is expired and refresh returns undefined", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue(undefined);
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("throws when token is expired and no refresh callback provided", async () => {
      let currentTime = 1_000_000;
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;

      await expect(manager.getToken()).rejects.toThrow("Token expired and cannot be refreshed.");
    });
  });

  describe("save", () => {
    it("persists credential to storage as TokenSet", async () => {
      const fixedTime = 1_000_000;
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage, now: () => fixedTime });
      await manager.save(sampleToken);
      const stored = await storage.load();
      expect(stored?.refresh_token).toBe("refresh-1");
      expect(stored?.tokens[""]?.access_token).toBe("access-1");
      expect(stored?.tokens[""]?.expires_at).toBe(fixedTime + 3600 * 1000);
    });

    it("preserves scope from previous entry when new response omits it", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });

      await manager.save({
        access_token: "a1",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile",
      });

      // Second save omits scope — previous scope should be preserved
      await manager.save({
        access_token: "a2",
        token_type: "Bearer",
        expires_in: 3600,
      });

      const stored = await storage.load();
      expect(stored?.tokens[""]?.access_token).toBe("a2");
      expect(stored?.tokens[""]?.scope).toBe("openid profile");
    });

    it("preserves id_token when new response omits it", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });

      await manager.save({
        access_token: "a1",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: "id-token-1",
      });

      // Second save omits id_token — previous id_token should be preserved
      await manager.save({
        access_token: "a2",
        token_type: "Bearer",
        expires_in: 3600,
      });

      const stored = await storage.load();
      expect(stored?.tokens[""]?.access_token).toBe("a2");
      expect(stored?.id_token).toBe("id-token-1");
    });

    it("overwrites scope when new response provides it", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });

      await manager.save({
        access_token: "a1",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile",
      });

      await manager.save({
        access_token: "a2",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile email",
      });

      const stored = await storage.load();
      expect(stored?.tokens[""]?.scope).toBe("openid profile email");
    });

    it("overwrites id_token when new response provides it", async () => {
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage });

      await manager.save({
        access_token: "a1",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: "id-token-1",
      });

      await manager.save({
        access_token: "a2",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: "id-token-2",
      });

      const stored = await storage.load();
      expect(stored?.id_token).toBe("id-token-2");
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

    it("calls revoke with refresh token before clearing storage", async () => {
      const revoke = vi.fn<(token: string) => Promise<void>>().mockResolvedValue(undefined);
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage, revoke });
      await manager.save(sampleToken);

      await manager.clear();

      expect(revoke).toHaveBeenCalledWith("refresh-1");
      expect(await storage.load()).toBeUndefined();
    });

    it("skips revoke when no refresh token is stored", async () => {
      const revoke = vi.fn<(token: string) => Promise<void>>().mockResolvedValue(undefined);
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage, revoke });
      await manager.save({
        access_token: "access-only",
        token_type: "Bearer",
        expires_in: 3600,
      });

      await manager.clear();

      expect(revoke).not.toHaveBeenCalled();
      expect(await storage.load()).toBeUndefined();
    });

    it("clears storage even when revoke fails", async () => {
      const revoke = vi.fn<(token: string) => Promise<void>>().mockRejectedValue(new Error("network error"));
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({ storage, revoke });
      await manager.save(sampleToken);

      await manager.clear();

      expect(revoke).toHaveBeenCalledWith("refresh-1");
      expect(await storage.load()).toBeUndefined();
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

    it("new instance reads tokens from shared storage without load()", async () => {
      const storage = memoryStorage<TokenSet>();

      // Instance A saves tokens
      const managerA = new TokenManager({ storage });
      await managerA.save(sampleToken);
      await managerA.save(
        { access_token: "res-token", token_type: "Bearer", expires_in: 3600 },
        { resource: "https://api.example.com" }
      );

      // Instance B uses the same storage — should read tokens directly, no load() needed
      const managerB = new TokenManager({ storage });
      expect(await managerB.getToken()).toBe("access-1");
      expect(await managerB.getToken({ resource: "https://api.example.com" })).toBe("res-token");
    });

    it("new instance uses refresh token from shared storage", async () => {
      let currentTime = 1_000_000;
      const now = () => currentTime;
      const storage = memoryStorage<TokenSet>();
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });

      // Instance A saves token with refresh_token
      const managerA = new TokenManager({ storage, refresh, now });
      await managerA.save(sampleToken);

      // Instance B uses same storage, expires, should use refresh_token from storage
      const managerB = new TokenManager({ storage, refresh, now });

      currentTime += 3601 * 1000;

      await managerB.getToken();
      expect(refresh).toHaveBeenCalledWith("refresh-1", undefined);
    });

    it("clear removes all resource tokens", async () => {
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
      let currentTime = 1_000_000;
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

      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
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

      currentTime += 2000;

      // Refresh resource A — uses original refresh token
      await manager.getToken({ resource: "https://api-a.example.com" });
      expect(refreshCalls[0]).toBe("original-rt");

      // Refresh default — should use the rotated refresh token
      await manager.getToken();
      expect(refreshCalls[1]).toBe("rotated-1");
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
    it("returns false before save", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      expect(await manager.hasToken()).toBe(false);
    });

    it("returns true after save", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      expect(await manager.hasToken()).toBe(true);
    });

    it("returns false after clear", async () => {
      const manager = new TokenManager({ storage: memoryStorage<TokenSet>() });
      await manager.save(sampleToken);
      await manager.clear();
      expect(await manager.hasToken()).toBe(false);
    });
  });

  describe("lock integration", () => {
    it("concurrent getToken calls only refresh once when storage has lock", async () => {
      let currentTime = 1_000_000;
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

      const manager = new TokenManager({ storage, refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;

      const [t1, t2] = await Promise.all([manager.getToken(), manager.getToken()]);

      expect(refresh).toHaveBeenCalledOnce();
      expect(t1).toBe("refreshed");
      expect(t2).toBe("refreshed");
    });

    it("cross-process: second instance sees token refreshed by first via shared storage", async () => {
      let currentTime = 1_000_000;
      const now = () => currentTime;
      const storage = memoryStorage<TokenSet>();

      const managerA = new TokenManager({
        storage,
        refresh: async () => ({
          access_token: "refreshed-by-A",
          token_type: "Bearer",
          expires_in: 3600,
        }),
        now,
      });
      await managerA.save(sampleToken);

      currentTime += 3601 * 1000;

      // Process A refreshes the token
      await managerA.getToken();

      // Process B (new instance, same storage) should see the refreshed token
      const managerB = new TokenManager({ storage, now });
      expect(await managerB.getToken()).toBe("refreshed-by-A");
    });

    it("refreshes without lock when storage does not provide it", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed-no-lock",
        token_type: "Bearer",
        expires_in: 3600,
      });

      const manager = new TokenManager({ storage: memoryStorage<TokenSet>(), refresh, now: () => currentTime });
      await manager.save(sampleToken);

      currentTime += 3601 * 1000;

      const token = await manager.getToken();
      expect(token).toBe("refreshed-no-lock");
      expect(refresh).toHaveBeenCalledOnce();
    });
  });

  describe("injectable now (pure time)", () => {
    it("uses injected now for expiry check — refreshes when now is past expiry", async () => {
      let currentTime = 1_000_000;
      const refresh = vi.fn<(refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>>().mockResolvedValue({
        access_token: "refreshed",
        token_type: "Bearer",
        expires_in: 3600,
      });
      const manager = new TokenManager({
        storage: memoryStorage<TokenSet>(),
        refresh,
        now: () => currentTime,
      });
      await manager.save(sampleToken);

      // Token was saved at currentTime=1_000_000, expires_at = 1_000_000 + 3600*1000
      // Default threshold = 300s. So token is "expired" when now >= expires_at - 300_000
      // expires_at = 4_600_000, threshold boundary = 4_300_000

      // Still valid
      currentTime = 4_299_999;
      expect(await manager.getToken()).toBe("access-1");
      expect(refresh).not.toHaveBeenCalled();

      // Past threshold — should refresh
      currentTime = 4_300_001;
      expect(await manager.getToken()).toBe("refreshed");
      expect(refresh).toHaveBeenCalledOnce();
    });

    it("uses injected now for save — expires_at is computed from injected time", async () => {
      const fixedTime = 2_000_000;
      const storage = memoryStorage<TokenSet>();
      const manager = new TokenManager({
        storage,
        now: () => fixedTime,
      });
      await manager.save(sampleToken);

      const stored = await storage.load();
      // expires_at = fixedTime + expires_in * 1000 = 2_000_000 + 3_600_000
      expect(stored?.tokens[""]?.expires_at).toBe(5_600_000);
    });
  });
});
