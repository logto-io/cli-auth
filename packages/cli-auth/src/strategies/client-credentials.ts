import type { ClientCredentialsConfig } from "../config.js";
import type { TokenResponse } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse } from "../utils.js";

export type ClientCredentialsStrategy = { config: ClientCredentialsConfig; auth: ClientCredentialsAuth };

export class ClientCredentialsAuth {
  private readonly config: ClientCredentialsConfig;
  private readonly tokenManager: TokenManager;

  readonly strategy = "client-credentials" as const;

  constructor(config: ClientCredentialsConfig) {
    this.config = config;
    this.tokenManager = new TokenManager({
      storage: config.storage,
      tokenRefreshThreshold: config.tokenRefreshThreshold,
      refresh: () => this.fetchToken(),
    });
  }

  private async fetchToken(): Promise<TokenResponse> {
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

    if (resource) body.set("resource", resource);
    if (scope) body.set("scope", scope);
    if (extraParams) {
      for (const [key, value] of Object.entries(extraParams)) {
        body.set(key, value);
      }
    }

    return fetchTokenResponse(provider.metadata.tokenEndpoint, body, extraHeaders);
  }

  async login() {
    await this.tokenManager.save(await this.fetchToken());
  }

  async getToken(): Promise<string> {
    return this.tokenManager.getToken();
  }

  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: "client-credentials" }> {
    return { authenticated: this.tokenManager.hasToken, strategy: this.strategy };
  }
}
