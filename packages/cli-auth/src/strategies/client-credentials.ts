import type { ClientCredentialsConfig } from "../config.js";
import type { GetTokenOptions, TokenResponse } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse } from "../utils.js";

export type ClientCredentialsStrategy = { config: ClientCredentialsConfig; auth: ClientCredentialsAuth };

export class ClientCredentialsAuth {
  private readonly config: ClientCredentialsConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  readonly strategy = "client-credentials" as const;

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

  async login() {
    await this.tokenManager.save(await this.fetchToken());
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: "client-credentials" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
