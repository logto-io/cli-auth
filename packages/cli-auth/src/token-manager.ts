import type { CachedToken, GetTokenOptions, Storage, TokenResponse, TokenSet } from "./types.js";
import { buildTokenCacheKey } from "./utils.js";

export type TokenManagerConfig = {
  storage: Storage<TokenSet>;
  refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  tokenRefreshThreshold?: number;
};

export class TokenManager {
  private readonly storage: Storage<TokenSet>;
  private readonly refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  private readonly tokenRefreshThreshold?: number;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
  }

  async hasToken(): Promise<boolean> {
    const stored = await this.storage.load();
    return stored !== undefined && Object.keys(stored.tokens).length > 0;
  }

  async save(data: TokenResponse, options?: GetTokenOptions): Promise<void> {
    const key = buildTokenCacheKey(options);
    const stored = await this.storage.load();
    const tokens = { ...stored?.tokens };
    tokens[key] = {
      access_token: data.access_token,
      expires_at: Date.now() + data.expires_in * 1000,
      scope: data.scope,
    };
    await this.storage.save({
      refresh_token: data.refresh_token ?? stored?.refresh_token,
      tokens,
    });
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    const key = buildTokenCacheKey(options);
    const stored = await this.storage.load();
    const cached = stored?.tokens[key];

    // If no cached token for this key but we can refresh, try to fetch
    if (!cached && (stored?.refresh_token || this.refresh)) {
      return this.refreshForKey(key, stored?.refresh_token, options);
    }

    if (!cached) {
      throw new Error("No token available.");
    }

    if (this.isExpired(cached)) {
      const release = await this.storage.lock?.();
      try {
        // Re-read from storage after acquiring lock — another process may have refreshed
        const rechecked = await this.storage.load();
        const recheckedToken = rechecked?.tokens[key];
        if (!recheckedToken || this.isExpired(recheckedToken)) {
          return this.refreshForKey(key, rechecked?.refresh_token, options);
        }
        return recheckedToken.access_token;
      } finally {
        await release?.();
      }
    }

    return cached.access_token;
  }

  async clear(): Promise<void> {
    await this.storage.clear();
  }

  private isExpired(cached: CachedToken): boolean {
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    return Date.now() >= cached.expires_at - threshold;
  }

  private async refreshForKey(key: string, refreshToken: string | undefined, options?: GetTokenOptions): Promise<string> {
    const data = await this.refresh?.(refreshToken, options);
    if (!data) {
      throw new Error("Token expired and cannot be refreshed.");
    }
    await this.save(data, options);
    return data.access_token;
  }
}
