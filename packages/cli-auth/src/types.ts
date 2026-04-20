/**
 * Per-request overrides that influence how a token is acquired and cached.
 *
 * The same options object also acts as the cache key: two calls with the same
 * `resource` and `extraParams` share a cached access token, while different
 * values fetch and store separate tokens. This lets a single authenticated
 * session manage multiple downstream resources or tenants.
 */
export type GetTokenOptions = {
  /**
   * RFC 8707 resource indicator. Identifies the target API the access token
   * is intended for, and is forwarded to the authorization server verbatim.
   *
   * When omitted, the `resource` from the strategy config (if any) is used.
   */
  resource?: string;
  /**
   * Provider-specific extra token-endpoint parameters
   * (e.g. `organization_id`, `audience`). Merged on top of any `extraParams`
   * set on the strategy config, with per-request values winning on conflict.
   */
  extraParams?: Record<string, string>;
};

/**
 * A single cached access token, keyed by the `resource`/`extraParams`
 * combination that produced it. Persisted as part of {@link TokenSet}.
 */
export type CachedToken = {
  /** The raw access token string. Treat as a secret. */
  access_token: string;
  /** Absolute expiry time, in milliseconds since the Unix epoch. */
  expires_at: number;
  /** The scope string granted for this token, if the provider returned one. */
  scope?: string;
};

/**
 * The full on-disk (or in-memory) shape persisted by a {@link Storage}.
 *
 * A single `TokenSet` groups the long-lived refresh/id tokens with a map of
 * short-lived access tokens — one per `resource`/`extraParams` combination —
 * so a single authenticated session can service multiple downstream APIs.
 */
export type TokenSet = {
  /** Refresh token shared across all cached access tokens in this set. */
  refresh_token?: string;
  /** ID token from the most recent successful login, if any. */
  id_token?: string;
  /**
   * Map from an internal cache key (derived from `resource`/`extraParams`) to
   * the cached access token for that key.
   */
  tokens: Record<string, CachedToken>;
};

/**
 * Internal classification of what the storage currently contains for a given
 * cache key. Used by {@link TokenManager} to decide whether to return a
 * cached token, refresh, or fail.
 *
 * @internal
 */
export type TokenSession =
  | { type: "empty" }
  | { type: "refresh-only"; refreshToken: string }
  | { type: "active"; cached: CachedToken };

/**
 * Pluggable persistence layer for tokens.
 *
 * Implementations decide *where* credentials live (in memory, on disk, in an
 * OS keyring, ...) while the library owns the lifecycle (load/save/clear).
 * Built-in implementations are exposed as {@link memoryStorage},
 * {@link fileStorage}, and {@link keyringStorage}; custom backends can be
 * supplied by conforming to this shape.
 *
 * @typeParam T - The persisted payload type. Defaults to {@link TokenSet}
 *   when used with the built-in strategies; may be narrowed for custom use.
 */
export type Storage<T = TokenResponse> = {
  /** Load the persisted credential, or `undefined` if none is stored yet. */
  load: () => Promise<T | undefined>;
  /** Atomically replace the persisted credential with `credential`. */
  save: (credential: T) => Promise<void>;
  /** Remove the persisted credential, if any. No-op when already empty. */
  clear: () => Promise<void>;
  /**
   * Optional cross-process exclusive lock used to serialize token refreshes.
   *
   * When provided, the library calls `lock()` before a refresh and invokes
   * the returned release function after saving. Without it, concurrent CLI
   * invocations may race and each perform a refresh.
   */
  lock?: () => Promise<() => Promise<void>>;
};

/**
 * The raw token response from an OAuth 2.0 token endpoint (RFC 6749 §5.1),
 * plus the OpenID Connect `id_token` extension. Field names use the
 * snake_case form defined by the specs.
 */
export type TokenResponse = {
  /** The access token issued by the authorization server. */
  access_token: string;
  /** Token type (e.g. `Bearer`). */
  token_type: string;
  /** Lifetime of the access token in seconds. */
  expires_in: number;
  /** Long-lived refresh token, if the authorization server issued one. */
  refresh_token?: string;
  /** OpenID Connect ID token, if requested and issued. */
  id_token?: string;
  /** Space-delimited list of scopes actually granted. */
  scope?: string;
};
