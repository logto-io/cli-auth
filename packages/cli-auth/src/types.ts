export type GetTokenOptions = {
  /** RFC 8707 resource indicator */
  resource?: string;
  /** Provider-specific extra parameters (e.g. organization_id) */
  extraParams?: Record<string, string>;
};

export type CachedToken = {
  access_token: string;
  /** Absolute timestamp in ms */
  expires_at: number;
  scope?: string;
};

export type TokenSet = {
  refresh_token?: string;
  id_token?: string;
  tokens: Record<string, CachedToken>;
};

export type TokenSession =
  | { type: "empty" }
  | { type: "refresh-only"; refreshToken: string }
  | { type: "active"; cached: CachedToken };

export type Storage<T = TokenResponse> = {
  load: () => Promise<T | undefined>;
  save: (credential: T) => Promise<void>;
  clear: () => Promise<void>;
  /** Acquire exclusive lock. Call the returned function to release. */
  lock?: () => Promise<() => Promise<void>>;
};

export type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
};
