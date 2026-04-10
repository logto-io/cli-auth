import type { Storage } from "../types.js";
import { BaseAuth, fetchTokenResponse, refreshTokenGrant } from "../base-auth.js";

export const tokenTypeIdentifiers = {
  accessToken: "urn:ietf:params:oauth:token-type:access_token",
  refreshToken: "urn:ietf:params:oauth:token-type:refresh_token",
  idToken: "urn:ietf:params:oauth:token-type:id_token",
  saml1: "urn:ietf:params:oauth:token-type:saml1",
  saml2: "urn:ietf:params:oauth:token-type:saml2",
  jwt: "urn:ietf:params:oauth:token-type:jwt",
} as const;

export type TokenExchangeConfig = {
  strategy: "token-exchange";
  provider: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret?: string;
    tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
  };
  subjectToken: string;
  subjectTokenType: string;
  actorToken?: string;
  actorTokenType?: string;
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

export type TokenExchangeStrategy = { config: TokenExchangeConfig; auth: TokenExchangeAuth };

export class TokenExchangeAuth extends BaseAuth<"token-exchange"> {
  private readonly provider: TokenExchangeConfig["provider"];
  private readonly subjectToken: string;
  private readonly subjectTokenType: string;
  private readonly actorToken?: string;
  private readonly actorTokenType?: string;

  constructor(config: TokenExchangeConfig) {
    const { storage, tokenRefreshThreshold, resource, scope, extraParams } = config;
    super({ storage, strategy: "token-exchange", tokenRefreshThreshold, resource, scope, extraParams });
    this.provider = config.provider;
    this.subjectToken = config.subjectToken;
    this.subjectTokenType = config.subjectTokenType;
    this.actorToken = config.actorToken;
    this.actorTokenType = config.actorTokenType;
  }

  protected async onRefresh(currentRefreshToken?: string) {
    if (!currentRefreshToken) return undefined;
    return refreshTokenGrant(this.provider.tokenEndpoint, this.provider.clientId, currentRefreshToken);
  }

  async login() {
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: this.subjectToken,
      subject_token_type: this.subjectTokenType,
    });

    const extraHeaders: Record<string, string> = {};
    const authMethod = this.provider.tokenEndpointAuthMethod ?? "client_secret_post";

    if (this.provider.clientSecret && authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${this.provider.clientId}:${this.provider.clientSecret}`)}`;
    } else if (this.provider.clientSecret) {
      body.set("client_id", this.provider.clientId);
      body.set("client_secret", this.provider.clientSecret);
    } else {
      body.set("client_id", this.provider.clientId);
    }

    if (this.actorToken) {
      body.set("actor_token", this.actorToken);
      if (this.actorTokenType) {
        body.set("actor_token_type", this.actorTokenType);
      }
    }

    this.applyOptionalParams(body);

    const data = await fetchTokenResponse(this.provider.tokenEndpoint, body, extraHeaders);
    await this.applyTokenResponse(data);
  }
}
