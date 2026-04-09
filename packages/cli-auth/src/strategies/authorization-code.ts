import type { AuthorizationCodeConfig, AuthorizationCodeAuth, TokenResponse } from "../types.js";
import { createTokenManager, refreshTokenGrant } from "../token-manager.js";

export function createAuthorizationCodeAuth(config: AuthorizationCodeConfig): AuthorizationCodeAuth {
  const { provider, storage, resource, scope, extraParams, callbackPort, tokenRefreshThreshold } = config;

  const tokenManager = createTokenManager({
    storage,
    strategy: "authorization-code",
    tokenRefreshThreshold,
    onRefresh: async (currentRefreshToken) => {
      if (!currentRefreshToken) return undefined;
      return refreshTokenGrant(provider.tokenEndpoint, provider.clientId, currentRefreshToken);
    },
  });

  return {
    async login(options) {
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
      await tokenManager.applyTokenResponse(data);
    },
    getToken: tokenManager.getToken,
    logout: tokenManager.logout,
    status: tokenManager.status,
  };
}
