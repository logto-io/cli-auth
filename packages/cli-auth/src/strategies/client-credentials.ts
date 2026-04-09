import type { Storage, TokenResponse } from "../types.js";
import { BaseAuth, fetchTokenResponse } from "../base-auth.js";

export type ClientCredentialsConfig = {
  strategy: "client-credentials";
  provider: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

export type ClientCredentialsStrategy = { config: ClientCredentialsConfig; auth: ClientCredentialsAuth };

export class ClientCredentialsAuth extends BaseAuth<"client-credentials"> {
  private readonly provider: ClientCredentialsConfig["provider"];

  constructor(config: ClientCredentialsConfig) {
    super(config.storage, "client-credentials", config.tokenRefreshThreshold, config.resource, config.scope, config.extraParams);
    this.provider = config.provider;
  }

  protected async onRefresh() {
    return this.fetchToken();
  }

  private async fetchToken(): Promise<TokenResponse> {
    const authMethod = this.provider.tokenEndpointAuthMethod ?? "client_secret_post";
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const extraHeaders: Record<string, string> = {};

    if (authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${this.provider.clientId}:${this.provider.clientSecret}`)}`;
    } else {
      body.set("client_id", this.provider.clientId);
      body.set("client_secret", this.provider.clientSecret);
    }

    this.applyOptionalParams(body);

    return fetchTokenResponse(this.provider.tokenEndpoint, body, extraHeaders);
  }

  async login() {
    await this.applyTokenResponse(await this.fetchToken());
  }
}
