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
  id_token?: string;
  scope?: string;
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

type AuthorizationCodeConfig = {
  strategy: "authorization-code";
  provider: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  callbackPort?: number;
  tokenRefreshThreshold?: number;
};

type CliAuthConfig = StaticTokenConfig | ClientCredentialsConfig | DeviceCodeConfig | AuthorizationCodeConfig;

type BaseAuth = {
  getToken: () => Promise<string | undefined>;
  logout: () => Promise<void>;
  status: () => Promise<{ authenticated: boolean; strategy: string }>;
};

type StaticTokenAuth = BaseAuth & {
  login: () => Promise<void>;
};

type ClientCredentialsAuth = BaseAuth & {
  login: () => Promise<void>;
};

type DeviceCodeAuth = BaseAuth & {
  login: (options?: {
    onAuthorization?: (authorization: {
      userCode: string;
      verificationUri: string;
      verificationUriComplete?: string;
      expiresIn: number;
    }) => void;
  }) => Promise<void>;
};

type AuthorizationCodeAuth = BaseAuth & {
  login: (options?: {
    onAuthorization?: (url: string) => void;
  }) => Promise<void>;
};

export function createCliAuth(config: StaticTokenConfig): StaticTokenAuth;
export function createCliAuth(config: ClientCredentialsConfig): ClientCredentialsAuth;
export function createCliAuth(config: DeviceCodeConfig): DeviceCodeAuth;
export function createCliAuth(config: AuthorizationCodeConfig): AuthorizationCodeAuth;
export function createCliAuth(config: CliAuthConfig): StaticTokenAuth | ClientCredentialsAuth | DeviceCodeAuth | AuthorizationCodeAuth {
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

  if (config.strategy === "authorization-code") {
    const { provider, storage, resource, scope, extraParams, callbackPort, tokenRefreshThreshold } = config;

    let accessToken: string | undefined;
    let refreshToken: string | undefined;
    let expiresAt: number | undefined;

    return {
      async login(options?: {
        onAuthorization?: (url: string) => void;
      }) {
        const { randomBytes, createHash } = await import("node:crypto");
        const { createServer } = await import("node:http");

        // Generate PKCE pair
        const codeVerifier = randomBytes(32).toString("base64url");
        const codeChallenge = createHash("sha256")
          .update(codeVerifier)
          .digest("base64url");

        // Generate state
        const state = randomBytes(16).toString("base64url");

        // Start loopback server
        const callbackServer = createServer();

        const { port } = await new Promise<{ port: number }>(
          (resolve, reject) => {
            callbackServer.on("error", reject);
            callbackServer.listen(
              callbackPort ?? 0,
              "127.0.0.1",
              () => {
                const addr = callbackServer.address() as { port: number };
                resolve({ port: addr.port });
              }
            );
          }
        );

        const redirectUri = `http://127.0.0.1:${port}/callback`;

        // Build authorization URL
        const authUrl = new URL(provider.authorizationEndpoint);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("client_id", provider.clientId);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("code_challenge", codeChallenge);
        authUrl.searchParams.set("code_challenge_method", "S256");
        authUrl.searchParams.set("state", state);
        if (scope) {
          authUrl.searchParams.set("scope", scope);
        }
        if (extraParams) {
          for (const [key, value] of Object.entries(extraParams)) {
            authUrl.searchParams.set(key, value);
          }
        }

        options?.onAuthorization?.(authUrl.toString());

        // Wait for callback, exchange token, always close server
        const closeServer = () =>
          new Promise<void>((resolve) => callbackServer.close(() => resolve()));

        let code: string;
        try {
          code = await new Promise<string>((resolve, reject) => {
            callbackServer.on("request", (req, res) => {
              const url = new URL(req.url!, `http://127.0.0.1:${port}`);

              if (url.pathname !== "/callback") {
                res.writeHead(404).end();
                return;
              }

              const error = url.searchParams.get("error");
              if (error) {
                const description = url.searchParams.get("error_description") ?? error;
                res.writeHead(400).end(`Authorization failed: ${description}`);
                reject(new Error(`Authorization failed: ${description}`));
                return;
              }

              const callbackState = url.searchParams.get("state");
              if (callbackState !== state) {
                res.writeHead(400).end("State mismatch");
                reject(new Error("State mismatch"));
                return;
              }

              const callbackCode = url.searchParams.get("code");
              if (!callbackCode) {
                res.writeHead(400).end("Missing authorization code");
                reject(new Error("Missing authorization code"));
                return;
              }

              res.writeHead(200).end("Authorization successful. You can close this tab.");
              resolve(callbackCode);
            });
          });
        } catch (error) {
          await closeServer();
          throw error;
        }

        await closeServer();

        // Exchange code for token
        const tokenBody = new URLSearchParams({
          grant_type: "authorization_code",
          code,
          code_verifier: codeVerifier,
          client_id: provider.clientId,
          redirect_uri: redirectUri,
        });
        if (resource) {
          tokenBody.set("resource", resource);
        }

        const tokenResponse = await fetch(provider.tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: tokenBody.toString(),
        });

        if (!tokenResponse.ok) {
          throw new Error(
            `Token request failed with status ${tokenResponse.status}`
          );
        }

        const data = (await tokenResponse.json()) as TokenResponse;
        accessToken = data.access_token;
        expiresAt = Date.now() + data.expires_in * 1000;
        refreshToken = data.refresh_token;
        await storage.save(data);
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
          strategy: "authorization-code" as const,
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
