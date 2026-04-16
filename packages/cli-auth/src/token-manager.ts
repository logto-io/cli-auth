import type { CachedToken, GetTokenOptions, Storage, TokenResponse, TokenSession, TokenSet } from "./types.js";
import { buildTokenCacheKey } from "./utils.js";

export function resolveSession(stored: TokenSet | undefined, key: string): TokenSession {
  const cached = stored?.tokens[key];
  if (cached) {
    return { type: "active", cached };
  }
  if (stored?.refresh_token) {
    return { type: "refresh-only", refreshToken: stored.refresh_token };
  }
  return { type: "empty" };
}

export type TokenManagerConfig = {
  storage: Storage<TokenSet>;
  refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  tokenRefreshThreshold?: number;
  /** Clock source for computing expiry. Defaults to Date.now. */
  now?: () => number;
};

export class TokenManager {
  private readonly storage: Storage<TokenSet>;
  private readonly refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  private readonly tokenRefreshThreshold?: number;
  private readonly now: () => number;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
    this.now = config.now ?? Date.now;
  }

  async hasToken(): Promise<boolean> {
    const stored = await this.storage.load();
    return stored !== undefined && Object.keys(stored.tokens).length > 0;
  }

  async save(data: TokenResponse, options?: GetTokenOptions): Promise<void> {
    const key = buildTokenCacheKey(options);
    const stored = await this.storage.load();
    const tokens = { ...stored?.tokens };
    const previous = tokens[key];
    tokens[key] = {
      access_token: data.access_token,
      expires_at: this.now() + data.expires_in * 1000,
      scope: data.scope ?? previous?.scope,
    };
    await this.storage.save({
      refresh_token: data.refresh_token ?? stored?.refresh_token,
      id_token: data.id_token ?? stored?.id_token,
      tokens,
    });
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    const key = buildTokenCacheKey(options);
    const stored = await this.storage.load();
    const session = resolveSession(stored, key);

    switch (session.type) {
      case "empty": {
        if (this.refresh) {
          return this.refreshForKey(key, undefined, options);
        }
        throw new Error("No token available.");
      }
      case "refresh-only": {
        return this.refreshForKey(key, session.refreshToken, options);
      }
      case "active": {
        if (this.isExpired(session.cached)) {
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
        return session.cached.access_token;
      }
    }
  }

  async clear(): Promise<void> {
    await this.storage.clear();
  }

  private isExpired(cached: CachedToken): boolean {
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    return this.now() >= cached.expires_at - threshold;
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
