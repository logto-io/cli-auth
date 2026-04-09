type StaticTokenConfig = {
  strategy: "static-token";
  token: string;
};

type ClientCredentialsConfig = {
  strategy: "client-credentials";
  provider: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
  };
  storage: {
    load: () => Promise<unknown>;
    save: (credential: unknown) => Promise<void>;
    clear: () => Promise<void>;
  };
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

type CliAuthConfig = StaticTokenConfig | ClientCredentialsConfig;

export function createCliAuth(config: CliAuthConfig) {
  if (config.strategy === "static-token") {
    return {
      async login() {},
      async getToken() {
        return config.token;
      },
      async logout() {},
      async status() {
        return { authenticated: true, strategy: "static-token" as const };
      },
    };
  }

  const { provider, storage, resource, scope, extraParams, tokenRefreshThreshold } = config;

  let accessToken: string | undefined;
  let expiresAt: number | undefined;

  async function fetchToken() {
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

    const data = (await response.json()) as { access_token: string; expires_in: number };
    accessToken = data.access_token;
    expiresAt = Date.now() + data.expires_in * 1000;
    await storage.save(data);
  }

  return {
    async login() {
      await fetchToken();
    },
    async getToken() {
      if (!accessToken || expiresAt === undefined) {
        throw new Error("Not logged in. Call login() first.");
      }
      const threshold = (tokenRefreshThreshold ?? 0) * 1000;
      if (Date.now() >= expiresAt - threshold) {
        await fetchToken();
      }
      return accessToken;
    },
    async logout() {
      accessToken = undefined;
      await storage.clear();
    },
    async status() {
      return {
        authenticated: accessToken !== undefined,
        strategy: "client-credentials" as const,
      };
    },
  };
}
