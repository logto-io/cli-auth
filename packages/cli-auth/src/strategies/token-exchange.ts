import type { TokenExchangeConfig } from "../config.js";
import type { GetTokenOptions } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse, refreshTokenGrant, revokeToken } from "../utils.js";

export type TokenExchangeStrategy = { config: TokenExchangeConfig; auth: TokenExchangeAuth };

export class TokenExchangeAuth {
  private readonly config: TokenExchangeConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  readonly strategy = "token-exchange" as const;

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

  async login() {
    await this.tokenManager.save(await this.exchangeToken());
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: "token-exchange" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
