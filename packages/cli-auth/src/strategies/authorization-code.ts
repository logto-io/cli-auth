import type { AuthorizationCodeConfig } from "../config.js";
import type { GetTokenOptions } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse, refreshTokenGrant, revokeToken } from "../utils.js";

export type AuthorizationCodeStrategy = { config: AuthorizationCodeConfig; auth: AuthorizationCodeAuth };

export class AuthorizationCodeAuth {
  private readonly config: AuthorizationCodeConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  readonly strategy = "authorization-code" as const;

  constructor(config: AuthorizationCodeConfig) {
    this.config = config;
    this.fetch = config.fetch ?? globalThis.fetch;
    this.tokenManager = new TokenManager({
      storage: config.storage,
      tokenRefreshThreshold: config.tokenRefreshThreshold,
      refresh: (refreshToken, options) => {
        if (!refreshToken) return Promise.resolve(undefined);
        return refreshTokenGrant({ tokenEndpoint: config.provider.metadata.tokenEndpoint, clientId: config.clientId, refreshToken, options, fetch: this.fetch });
      },
      revoke: config.provider.metadata.revocationEndpoint
        ? (token) => revokeToken({ endpoint: config.provider.metadata.revocationEndpoint!, clientId: config.clientId, token, fetch: this.fetch })
        : undefined,
    });
  }

  async login(options: {
    onAuthorization: (url: string) => void;
  }) {
    const { clientId, provider, scope, extraParams, resource, callbackPort } = this.config;
    const { authorizationEndpoint } = provider.metadata;
    if (!authorizationEndpoint) {
      throw new Error("authorizationEndpoint is required for authorization-code strategy");
    }

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
    const authUrl = new URL(authorizationEndpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", clientId);
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

    options.onAuthorization(authUrl.toString());

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
      client_id: clientId,
      redirect_uri: redirectUri,
    });
    if (resource) {
      tokenBody.set("resource", resource);
    }

    const data = await fetchTokenResponse({ endpoint: provider.metadata.tokenEndpoint, body: tokenBody, fetch: this.fetch });
    await this.tokenManager.save(data);
  }

  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: "authorization-code" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
