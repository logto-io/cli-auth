import type { CachedToken, GetTokenOptions, Storage, TokenResponse, TokenSet } from "./types.js";
import { buildTokenCacheKey } from "./utils.js";

export type TokenManagerConfig = {
  storage: Storage<TokenSet>;
  refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  tokenRefreshThreshold?: number;
};

export class TokenManager {
  private refreshToken: string | undefined;
  private readonly tokenCache = new Map<string, CachedToken>();

  private readonly storage: Storage<TokenSet>;
  private readonly refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  private readonly tokenRefreshThreshold?: number;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
  }

  get hasToken(): boolean {
    return this.tokenCache.size > 0;
  }

  async load(): Promise<void> {
    const stored = await this.storage.load();
    if (!stored) {
      return;
    }
    this.refreshToken = stored.refresh_token;
    this.tokenCache.clear();
    for (const [key, cached] of Object.entries(stored.tokens)) {
      this.tokenCache.set(key, cached);
    }
  }

  async save(data: TokenResponse, options?: GetTokenOptions): Promise<void> {
    const key = buildTokenCacheKey(options);
    this.tokenCache.set(key, {
      access_token: data.access_token,
      expires_at: Date.now() + data.expires_in * 1000,
      scope: data.scope,
    });
    if (data.refresh_token) {
      this.refreshToken = data.refresh_token;
    }
    await this.persistTokenSet();
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    const key = buildTokenCacheKey(options);
    const cached = this.tokenCache.get(key);

    // If no cached token for this key but we can refresh, try to fetch
    if (!cached && (this.refreshToken || this.refresh)) {
      return this.refreshForKey(key, options);
    }

    if (!cached) {
      throw new Error("No token available.");
    }

    if (this.isExpired(cached)) {
      const release = await this.storage.lock?.();
      try {
        const rechecked = this.tokenCache.get(key);
        if (rechecked && this.isExpired(rechecked)) {
          return this.refreshForKey(key, options);
        }
        // Another caller already refreshed
        return this.tokenCache.get(key)!.access_token;
      } finally {
        await release?.();
      }
    }

    return cached.access_token;
  }

  async clear(): Promise<void> {
    this.refreshToken = undefined;
    this.tokenCache.clear();
    await this.storage.clear();
  }

  private isExpired(cached: CachedToken): boolean {
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    return Date.now() >= cached.expires_at - threshold;
  }

  private async refreshForKey(key: string, options?: GetTokenOptions): Promise<string> {
    const data = await this.refresh?.(this.refreshToken, options);
    if (!data) {
      throw new Error("Token expired and cannot be refreshed.");
    }
    await this.save(data, options);
    return data.access_token;
  }

  private async persistTokenSet(): Promise<void> {
    const tokens: Record<string, CachedToken> = {};
    for (const [key, cached] of this.tokenCache.entries()) {
      tokens[key] = cached;
    }
    await this.storage.save({
      refresh_token: this.refreshToken,
      tokens,
    });
  }
}
