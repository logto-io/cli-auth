import type { CachedToken, GetTokenOptions, Storage, TokenResponse, TokenSession, TokenSet } from "./types.js";
import { CliAuthError } from "./errors.js";
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

/**
 * Configuration for a {@link TokenManager}.
 *
 * Each built-in strategy constructs a `TokenManager` with its own
 * `refresh`/`revoke` callbacks; advanced consumers can construct one
 * directly to implement a custom flow while reusing the caching, locking,
 * and revocation logic.
 */
export type TokenManagerConfig = {
  /** Backing persistence for the token set. */
  storage: Storage<TokenSet>;
  /**
   * Hook that acquires a fresh token set, either by exchanging a refresh
   * token or by re-running whichever grant fits the strategy.
   *
   * Return `undefined` to signal "no token can be obtained right now" — the
   * caller will receive an error from {@link TokenManager.getToken}.
   */
  refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  /**
   * Hook that revokes the given token at the provider. Invoked on
   * {@link TokenManager.clear} with the stored refresh token. Exceptions
   * thrown here are swallowed so local cleanup always succeeds.
   */
  revoke?: (token: string) => Promise<void>;
  /**
   * Seconds of remaining lifetime below which a cached access token is
   * considered expired. Defaults to `300`.
   */
  tokenRefreshThreshold?: number;
  /** Clock source for computing expiry. Defaults to `Date.now`. */
  now?: () => number;
};

/**
 * Caches access tokens and orchestrates refresh/revocation on top of a
 * {@link Storage}.
 *
 * Most consumers never touch this class directly — the strategy classes
 * wire it up internally. It is exported for advanced use cases that want to
 * reuse the caching/locking logic from a custom grant implementation.
 */
export class TokenManager {
  private readonly storage: Storage<TokenSet>;
  private readonly refresh?: (refreshToken: string | undefined, options?: GetTokenOptions) => Promise<TokenResponse | undefined>;
  private readonly revoke?: (token: string) => Promise<void>;
  private readonly tokenRefreshThreshold?: number;
  private readonly now: () => number;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.revoke = config.revoke;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
    this.now = config.now ?? Date.now;
  }

  /**
   * Returns `true` when the backing storage holds at least one cached access
   * token. Presence is not validated with the provider.
   */
  async hasToken(): Promise<boolean> {
    const stored = await this.storage.load();
    return stored !== undefined && Object.keys(stored.tokens).length > 0;
  }

  /**
   * Persists a fresh token response into the cache entry identified by
   * `options` (via `resource`/`extraParams`). Merges `refresh_token` and
   * `id_token` from previously stored values when the response omits them.
   */
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

  /**
   * Returns a valid access token for the cache entry identified by `options`.
   *
   * Serves the cached token when it is still fresh, otherwise invokes the
   * configured `refresh` hook. When {@link Storage.lock | storage.lock} is
   * provided, concurrent refreshes across processes are serialized and the
   * token is re-read after acquiring the lock to benefit from work done by
   * another process.
   *
   * @throws If no cached token exists and the `refresh` hook was not
   *   configured, or if the hook returns `undefined`.
   */
  async getToken(options?: GetTokenOptions): Promise<string> {
    const key = buildTokenCacheKey(options);
    const stored = await this.storage.load();
    const session = resolveSession(stored, key);

    switch (session.type) {
      case "empty": {
        if (this.refresh) {
          return this.refreshForKey(key, undefined, options);
        }
        throw new CliAuthError("token.unavailable", "No token available.");
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

  /**
   * Clears all persisted tokens. When a `revoke` hook is configured and a
   * refresh token is present, best-effort revokes it first; revocation
   * failures are swallowed so local cleanup always succeeds.
   */
  async clear(): Promise<void> {
    if (this.revoke) {
      const stored = await this.storage.load();
      if (stored?.refresh_token) {
        try {
          await this.revoke(stored.refresh_token);
        } catch {
          // Revoke failure should not block logout
        }
      }
    }
    await this.storage.clear();
  }

  private isExpired(cached: CachedToken): boolean {
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    return this.now() >= cached.expires_at - threshold;
  }

  private async refreshForKey(key: string, refreshToken: string | undefined, options?: GetTokenOptions): Promise<string> {
    const data = await this.refresh?.(refreshToken, options);
    if (!data) {
      throw new CliAuthError(
        "token.refresh_failed",
        "Token expired and cannot be refreshed."
      );
    }
    await this.save(data, options);
    return data.access_token;
  }
}
