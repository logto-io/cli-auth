import type { Storage } from "../types.js";
import { BaseAuth, refreshTokenGrant, fetchTokenResponse } from "../base-auth.js";

export type AuthorizationCodeConfig = {
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

export type AuthorizationCodeStrategy = { config: AuthorizationCodeConfig; auth: AuthorizationCodeAuth };

export class AuthorizationCodeAuth extends BaseAuth<"authorization-code"> {
  private readonly provider: AuthorizationCodeConfig["provider"];
  private readonly callbackPort?: number;

  constructor(config: AuthorizationCodeConfig) {
    const { storage, tokenRefreshThreshold, resource, scope, extraParams } = config;
    super({ storage, strategy: "authorization-code", tokenRefreshThreshold, resource, scope, extraParams });
    this.provider = config.provider;
    this.callbackPort = config.callbackPort;
  }

  protected async onRefresh(currentRefreshToken?: string) {
    if (!currentRefreshToken) return undefined;
    return refreshTokenGrant(this.provider.tokenEndpoint, this.provider.clientId, currentRefreshToken);
  }

  async login(options: {
    onAuthorization: (url: string) => void;
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
          this.callbackPort ?? 0,
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
    const authUrl = new URL(this.provider.authorizationEndpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", this.provider.clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("state", state);
    if (this.scope) {
      authUrl.searchParams.set("scope", this.scope);
    }
    if (this.extraParams) {
      for (const [key, value] of Object.entries(this.extraParams)) {
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
      client_id: this.provider.clientId,
      redirect_uri: redirectUri,
    });
    if (this.resource) {
      tokenBody.set("resource", this.resource);
    }

    const data = await fetchTokenResponse(this.provider.tokenEndpoint, tokenBody);
    await this.applyTokenResponse(data);
  }
}
