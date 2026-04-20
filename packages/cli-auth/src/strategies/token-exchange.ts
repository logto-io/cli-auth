import type { TokenExchangeConfig } from "../config.js";
import type { GetTokenOptions } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse, refreshTokenGrant, revokeToken } from "../utils.js";

/**
 * Strategy descriptor linking {@link TokenExchangeConfig} to its
 * {@link TokenExchangeAuth} implementation. Used by {@link createCliAuth} for
 * type-level strategy selection.
 *
 * @internal
 */
export type TokenExchangeStrategy = { config: TokenExchangeConfig; auth: TokenExchangeAuth };

/**
 * OAuth 2.0 Token Exchange grant (RFC 8693).
 *
 * Swaps an existing credential (e.g. a platform-issued identity token, a
 * SAML assertion) for an access token from the configured provider. Common
 * use cases include bootstrapping a CLI session from an upstream auth system
 * without prompting the user again, or impersonation/delegation scenarios
 * via `actor_token`.
 *
 * When the provider issues a refresh token, subsequent
 * {@link TokenExchangeAuth.getToken | getToken()} calls use the standard
 * refresh grant; otherwise a fresh exchange is performed on expiry.
 *
 * Construct via {@link createCliAuth} with `strategy: "token-exchange"`.
 */
export class TokenExchangeAuth {
  private readonly config: TokenExchangeConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  /** Literal strategy discriminator returned by {@link status}. */
  readonly strategy = "token-exchange" as const;

  /**
   * Creates a new strategy instance. Prefer {@link createCliAuth} over calling
   * this directly.
   */
  constructor(config: TokenExchangeConfig) {
    this.config = config;
    this.fetch = config.fetch ?? globalThis.fetch;
    this.tokenManager = new TokenManager({
      storage: config.storage,
      tokenRefreshThreshold: config.tokenRefreshThreshold,
      refresh: (refreshToken, options) => this.onRefresh(refreshToken, options),
      revoke: config.provider.metadata.revocationEndpoint
        ? (token) => revokeToken({ endpoint: config.provider.metadata.revocationEndpoint!, clientId: config.clientId, token, fetch: this.fetch })
        : undefined,
    });
  }

  private async onRefresh(refreshToken: string | undefined, options?: GetTokenOptions) {
    if (refreshToken) {
      return refreshTokenGrant({ tokenEndpoint: this.config.provider.metadata.tokenEndpoint, clientId: this.config.clientId, refreshToken, options, fetch: this.fetch });
    }
    return this.exchangeToken();
  }

  private async exchangeToken() {
    const { clientId, clientSecret, tokenEndpointAuthMethod, subjectToken, subjectTokenType, actorToken, actorTokenType, provider, resource, scope, extraParams } = this.config;

    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      subject_token_type: subjectTokenType,
    });

    const extraHeaders: Record<string, string> = {};
    const authMethod = tokenEndpointAuthMethod ?? "client_secret_post";

    if (clientSecret && authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    } else if (clientSecret) {
      body.set("client_id", clientId);
      body.set("client_secret", clientSecret);
    } else {
      body.set("client_id", clientId);
    }

    if (actorToken) {
      body.set("actor_token", actorToken);
      if (actorTokenType) {
        body.set("actor_token_type", actorTokenType);
      }
    }

    if (resource) body.set("resource", resource);
    if (scope) body.set("scope", scope);
    if (extraParams) {
      for (const [key, value] of Object.entries(extraParams)) {
        body.set(key, value);
      }
    }

    return fetchTokenResponse({ endpoint: provider.metadata.tokenEndpoint, body, headers: extraHeaders, fetch: this.fetch });
  }

  /**
   * Performs the token exchange immediately and persists the resulting
   * tokens. Useful to fail fast at CLI startup; {@link getToken} will also
   * trigger the exchange lazily.
   */
  async login() {
    await this.tokenManager.save(await this.exchangeToken());
  }

  /**
   * Returns a valid access token for the given `options` key. Refreshes via
   * the refresh token when available, otherwise re-runs the token exchange.
   */
  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  /**
   * Clears all persisted tokens. Best-effort revokes the stored refresh
   * token when the provider exposes a revocation endpoint.
   */
  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  /**
   * Reports whether any tokens are currently persisted. Does not validate
   * them with the provider.
   */
  async status(): Promise<{ authenticated: boolean; strategy: "token-exchange" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
