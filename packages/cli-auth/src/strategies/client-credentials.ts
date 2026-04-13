import type { ClientCredentialsConfig } from "../config.js";
import type { TokenResponse } from "../types.js";
import { BaseAuth, fetchTokenResponse } from "../base-auth.js";

export type ClientCredentialsStrategy = { config: ClientCredentialsConfig; auth: ClientCredentialsAuth };

export class ClientCredentialsAuth extends BaseAuth<"client-credentials"> {
  private readonly clientSecret: string;
  private readonly tokenEndpointAuthMethod: ClientCredentialsConfig["tokenEndpointAuthMethod"];

  constructor(config: ClientCredentialsConfig) {
    const { provider, clientId, storage, tokenRefreshThreshold, resource, scope, extraParams } = config;
    super({ provider, clientId, storage, strategy: "client-credentials", tokenRefreshThreshold, resource, scope, extraParams });
    this.clientSecret = config.clientSecret;
    this.tokenEndpointAuthMethod = config.tokenEndpointAuthMethod;
  }

  protected async onRefresh() {
    return this.fetchToken();
  }

  private async fetchToken(): Promise<TokenResponse> {
    const authMethod = this.tokenEndpointAuthMethod ?? "client_secret_post";
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const extraHeaders: Record<string, string> = {};

    if (authMethod === "client_secret_basic") {
      extraHeaders["Authorization"] =
        `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`;
    } else {
      body.set("client_id", this.clientId);
      body.set("client_secret", this.clientSecret);
    }

    this.applyOptionalParams(body);

    return fetchTokenResponse(this.provider.metadata.tokenEndpoint, body, extraHeaders);
  }

  async login() {
    await this.applyTokenResponse(await this.fetchToken());
  }
}
