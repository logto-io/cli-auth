import type { ClientCredentialsConfig, ClientCredentialsAuth, TokenResponse } from "../types.js";
import { createTokenManager } from "../token-manager.js";

export function createClientCredentialsAuth(config: ClientCredentialsConfig): ClientCredentialsAuth {
  const { provider, storage, resource, scope, extraParams, tokenRefreshThreshold } = config;

  async function fetchToken(): Promise<TokenResponse> {
    const authMethod = provider.tokenEndpointAuthMethod ?? "client_secret_post";
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (authMethod === "client_secret_basic") {
      headers["Authorization"] =
        `Basic ${btoa(`${provider.clientId}:${provider.clientSecret}`)}`;
    } else {
      body.set("client_id", provider.clientId);
      body.set("client_secret", provider.clientSecret);
    }

    if (resource) {
      body.set("resource", resource);
    }
    if (scope) {
      body.set("scope", scope);
    }
    if (extraParams) {
      for (const [key, value] of Object.entries(extraParams)) {
        body.set(key, value);
      }
    }

    const response = await fetch(provider.tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });

    if (!response.ok) {
      throw new Error(`Token request failed with status ${response.status}`);
    }

    return (await response.json()) as TokenResponse;
  }

  const tokenManager = createTokenManager({
    storage,
    strategy: "client-credentials",
    tokenRefreshThreshold,
    onRefresh: async () => fetchToken(),
  });

  return {
    async login() {
      await tokenManager.applyTokenResponse(await fetchToken());
    },
    getToken: tokenManager.getToken,
    logout: tokenManager.logout,
    status: tokenManager.status,
  };
}
