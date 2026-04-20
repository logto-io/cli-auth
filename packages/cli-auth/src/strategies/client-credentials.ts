import type { ClientCredentialsConfig } from "../config.js";
import type { GetTokenOptions, TokenResponse } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse } from "../utils.js";

/**
 * Strategy descriptor linking {@link ClientCredentialsConfig} to its
 * {@link ClientCredentialsAuth} implementation. Used by {@link createCliAuth}
 * for type-level strategy selection.
 *
 * @internal
 */
export type ClientCredentialsStrategy = { config: ClientCredentialsConfig; auth: ClientCredentialsAuth };

/**
 * OAuth 2.0 Client Credentials grant (RFC 6749 §4.4).
 *
 * Intended for machine-to-machine CLI flows where the CLI itself owns a
 * client secret — no interactive user login takes place. Since no refresh
 * token is issued, {@link ClientCredentialsAuth.getToken | getToken()}
 * transparently re-runs the grant when the cached token expires.
 *
 * Construct via {@link createCliAuth} with `strategy: "client-credentials"`.
 */
export class ClientCredentialsAuth {
  private readonly config: ClientCredentialsConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  /** Literal strategy discriminator returned by {@link status}. */
  readonly strategy = "client-credentials" as const;

  /**
   * Creates a new strategy instance. Prefer {@link createCliAuth} over calling
   * this directly.
   */
  constructor(config: ClientCredentialsConfig) {
    this.config = config;
    this.fetch = config.fetch ?? globalThis.fetch;
    this.tokenManager = new TokenManager({
      storage: config.storage,
      tokenRefreshThreshold: config.tokenRefreshThreshold,
      refresh: (_refreshToken, options) => this.fetchToken(options),
    });
  }

  private async fetchToken(options?: GetTokenOptions): Promise<TokenResponse> {
    const { clientId, clientSecret, tokenEndpointAuthMethod, provider, resource, scope, extraParams } = this.config;
    const authMethod = tokenEndpointAuthMethod ?? "client_secret_post";
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const extraHeaders: Record<string, string> = {};

    if (authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    } else {
      body.set("client_id", clientId);
      body.set("client_secret", clientSecret);
    }

    // Use resource from options (per-request) or config (default)
    const effectiveResource = options?.resource ?? resource;
    if (effectiveResource) body.set("resource", effectiveResource);
    if (scope) body.set("scope", scope);
    if (extraParams) {
      for (const [key, value] of Object.entries(extraParams)) {
        body.set(key, value);
      }
    }
    if (options?.extraParams) {
      for (const [key, value] of Object.entries(options.extraParams)) {
        body.set(key, value);
      }
    }

    return fetchTokenResponse({ endpoint: provider.metadata.tokenEndpoint, body, headers: extraHeaders, fetch: this.fetch });
  }

  /**
   * Performs the client credentials grant immediately and persists the
   * resulting access token. Usually unnecessary — {@link getToken} will
   * acquire one on demand — but useful to fail fast at CLI startup.
   */
  async login() {
    await this.tokenManager.save(await this.fetchToken());
  }

  /**
   * Returns a valid access token for the given `options` key. Runs the
   * client credentials grant automatically when no cached token is present
   * or the cached one is close to expiry.
   */
  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  /**
   * Clears all persisted tokens. There is no refresh token for this
   * strategy, so revocation is not attempted.
   */
  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  /**
   * Reports whether any tokens are currently persisted. Does not validate
   * them with the provider.
   */
  async status(): Promise<{ authenticated: boolean; strategy: "client-credentials" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
