type Storage = {
  load: () => Promise<unknown>;
  save: (credential: unknown) => Promise<void>;
  clear: () => Promise<void>;
};

type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
};

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
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

type DeviceCodeConfig = {
  strategy: "device-code";
  provider: {
    deviceAuthorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

type CliAuthConfig = StaticTokenConfig | ClientCredentialsConfig | DeviceCodeConfig;

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

  if (config.strategy === "device-code") {
    const { provider, storage, resource, scope, extraParams, tokenRefreshThreshold } = config;

    let accessToken: string | undefined;
    let refreshToken: string | undefined;
    let expiresAt: number | undefined;

    return {
      async login(options?: {
        onAuthorization?: (authorization: {
          userCode: string;
          verificationUri: string;
          verificationUriComplete?: string;
          expiresIn: number;
        }) => void;
      }) {
        // Step 1: Request device authorization
        const deviceAuthBody = new URLSearchParams({
          client_id: provider.clientId,
        });
        if (scope) {
          deviceAuthBody.set("scope", scope);
        }
        if (resource) {
          deviceAuthBody.set("resource", resource);
        }
        if (extraParams) {
          for (const [key, value] of Object.entries(extraParams)) {
            deviceAuthBody.set(key, value);
          }
        }

        const deviceAuthResponse = await fetch(
          provider.deviceAuthorizationEndpoint,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: deviceAuthBody.toString(),
          }
        );

        if (!deviceAuthResponse.ok) {
          throw new Error(
            `Device authorization request failed with status ${deviceAuthResponse.status}`
          );
        }

        const deviceAuth = (await deviceAuthResponse.json()) as {
          device_code: string;
          user_code: string;
          verification_uri: string;
          verification_uri_complete?: string;
          expires_in: number;
          interval?: number;
        };

        // Step 2: Call onAuthorization
        options?.onAuthorization?.({
          userCode: deviceAuth.user_code,
          verificationUri: deviceAuth.verification_uri,
          verificationUriComplete: deviceAuth.verification_uri_complete,
          expiresIn: deviceAuth.expires_in,
        });

        // Step 3: Poll token endpoint
        let pollInterval = (deviceAuth.interval ?? 5) * 1000;
        const deadline = Date.now() + deviceAuth.expires_in * 1000;

        while (Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));

          const tokenBody = new URLSearchParams({
            client_id: provider.clientId,
            device_code: deviceAuth.device_code,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          });
          if (resource) {
            tokenBody.set("resource", resource);
          }

          const tokenResponse = await fetch(provider.tokenEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: tokenBody.toString(),
          });

          if (tokenResponse.ok) {
            const data = (await tokenResponse.json()) as TokenResponse;
            accessToken = data.access_token;
            expiresAt = Date.now() + data.expires_in * 1000;
            refreshToken = data.refresh_token;
            await storage.save(data);
            return;
          }

          const error = (await tokenResponse.json()) as { error: string };
          if (error.error === "authorization_pending") {
            continue;
          }
          if (error.error === "slow_down") {
            pollInterval += 5000;
            continue;
          }
          throw new Error(`Device code flow failed: ${error.error}`);
        }

        throw new Error("Device code expired");
      },
      async getToken() {
        if (!accessToken || expiresAt === undefined) {
          throw new Error("Not logged in. Call login() first.");
        }
        const threshold = (tokenRefreshThreshold ?? 0) * 1000;
        if (Date.now() >= expiresAt - threshold) {
          if (refreshToken) {
            const body = new URLSearchParams({
              client_id: provider.clientId,
              grant_type: "refresh_token",
              refresh_token: refreshToken,
            });
            const response = await fetch(provider.tokenEndpoint, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: body.toString(),
            });
            if (!response.ok) {
              throw new Error(
                `Token refresh failed with status ${response.status}`
              );
            }
            const data = (await response.json()) as TokenResponse;
            accessToken = data.access_token;
            expiresAt = Date.now() + data.expires_in * 1000;
            refreshToken = data.refresh_token;
            await storage.save(data);
          }
        }
        return accessToken;
      },
      async logout() {
        accessToken = undefined;
        refreshToken = undefined;
        expiresAt = undefined;
        await storage.clear();
      },
      async status() {
        return {
          authenticated: accessToken !== undefined,
          strategy: "device-code" as const,
        };
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

    const data = (await response.json()) as TokenResponse;
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
