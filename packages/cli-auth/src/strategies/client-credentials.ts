import type { Storage, TokenResponse } from "../types.js";
import { BaseAuth } from "../base-auth.js";

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
  private readonly resource?: string;
  private readonly scope?: string;
  private readonly extraParams?: Record<string, string>;

  constructor(config: ClientCredentialsConfig) {
    super(config.storage, "client-credentials", config.tokenRefreshThreshold);
    this.provider = config.provider;
    this.resource = config.resource;
    this.scope = config.scope;
    this.extraParams = config.extraParams;
  }

  protected async onRefresh() {
    return this.fetchToken();
  }

  private async fetchToken(): Promise<TokenResponse> {
    const authMethod = this.provider.tokenEndpointAuthMethod ?? "client_secret_post";
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (authMethod === "client_secret_basic") {
      headers["Authorization"] =
        `Basic ${btoa(`${this.provider.clientId}:${this.provider.clientSecret}`)}`;
    } else {
      body.set("client_id", this.provider.clientId);
      body.set("client_secret", this.provider.clientSecret);
    }

    if (this.resource) {
      body.set("resource", this.resource);
    }
    if (this.scope) {
      body.set("scope", this.scope);
    }
    if (this.extraParams) {
      for (const [key, value] of Object.entries(this.extraParams)) {
        body.set(key, value);
      }
    }

    const response = await fetch(this.provider.tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });

    if (!response.ok) {
      throw new Error(`Token request failed with status ${response.status}`);
    }

    return (await response.json()) as TokenResponse;
  }

  async login() {
    await this.applyTokenResponse(await this.fetchToken());
  }
}
