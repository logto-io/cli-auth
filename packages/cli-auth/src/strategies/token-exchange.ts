import type { TokenExchangeConfig } from "../config.js";
import { BaseAuth, fetchTokenResponse, refreshTokenGrant } from "../base-auth.js";

export type TokenExchangeStrategy = { config: TokenExchangeConfig; auth: TokenExchangeAuth };

export class TokenExchangeAuth extends BaseAuth<"token-exchange"> {
  private readonly subjectToken: string;
  private readonly subjectTokenType: string;
  private readonly actorToken?: string;
  private readonly actorTokenType?: string;
  private readonly clientSecret?: string;
  private readonly tokenEndpointAuthMethod: TokenExchangeConfig["tokenEndpointAuthMethod"];

  constructor(config: TokenExchangeConfig) {
    const { provider, clientId, storage, tokenRefreshThreshold, resource, scope, extraParams } = config;
    super({ provider, clientId, storage, strategy: "token-exchange", tokenRefreshThreshold, resource, scope, extraParams });
    this.subjectToken = config.subjectToken;
    this.subjectTokenType = config.subjectTokenType;
    this.actorToken = config.actorToken;
    this.actorTokenType = config.actorTokenType;
    this.clientSecret = config.clientSecret;
    this.tokenEndpointAuthMethod = config.tokenEndpointAuthMethod;
  }

  protected async onRefresh(currentRefreshToken?: string) {
    if (currentRefreshToken) {
      return refreshTokenGrant(this.provider.metadata.tokenEndpoint, this.clientId, currentRefreshToken);
    }
    return this.exchangeToken();
  }

  private async exchangeToken() {
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: this.subjectToken,
      subject_token_type: this.subjectTokenType,
    });

    const extraHeaders: Record<string, string> = {};
    const authMethod = this.tokenEndpointAuthMethod ?? "client_secret_post";

    if (this.clientSecret && authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`;
    } else if (this.clientSecret) {
      body.set("client_id", this.clientId);
      body.set("client_secret", this.clientSecret);
    } else {
      body.set("client_id", this.clientId);
    }

    if (this.actorToken) {
      body.set("actor_token", this.actorToken);
      if (this.actorTokenType) {
        body.set("actor_token_type", this.actorTokenType);
      }
    }

    this.applyOptionalParams(body);

    return fetchTokenResponse(this.provider.metadata.tokenEndpoint, body, extraHeaders);
  }

  async login() {
    await this.applyTokenResponse(await this.exchangeToken());
  }
}
