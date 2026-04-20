import type { ServerResponse } from "node:http";

import type { AuthorizationCodeConfig, CallbackResult } from "../config.js";
import type { GetTokenOptions } from "../types.js";
import { CliAuthError } from "../errors.js";
import { TokenManager } from "../token-manager.js";
import { fetchTokenResponse, refreshTokenGrant, revokeToken } from "../utils.js";

const DEFAULT_SUCCESS_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Authorization successful</title></head><body><h1>Authorization successful</h1><p>You can close this tab and return to your terminal.</p></body></html>`;

const DEFAULT_FAILURE_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Authorization failed</title></head><body><h1>Authorization failed</h1><p>You can close this tab and return to your terminal.</p></body></html>`;

function classify(url: URL, expectedState: string): CallbackResult {
  if (url.searchParams.get("error")) {
    return { success: false, callbackUrl: url };
  }
  if (url.searchParams.get("state") !== expectedState) {
    return { success: false, callbackUrl: url, verifyError: "state_mismatch" };
  }
  if (!url.searchParams.get("code")) {
    return { success: false, callbackUrl: url, verifyError: "missing_code" };
  }
  return { success: true, callbackUrl: url };
}

function writeDefault(res: ServerResponse, result: CallbackResult): void {
  res
    .writeHead(result.success ? 200 : 400, {
      "Content-Type": "text/html; charset=utf-8",
    })
    .end(result.success ? DEFAULT_SUCCESS_HTML : DEFAULT_FAILURE_HTML);
}

function errorFromResult(result: CallbackResult): CliAuthError {
  if (result.verifyError === "state_mismatch") {
    return new CliAuthError("callback.state_mismatch", "State mismatch");
  }
  if (result.verifyError === "missing_code") {
    return new CliAuthError("callback.missing_code", "Missing authorization code");
  }
  const err = result.callbackUrl.searchParams.get("error") ?? "unknown";
  const desc = result.callbackUrl.searchParams.get("error_description") ?? undefined;
  return new CliAuthError(
    "provider.rejected",
    desc ? `Authorization failed: ${err} (${desc})` : `Authorization failed: ${err}`,
    { endpoint: "authorization", error: err, errorDescription: desc }
  );
}

/**
 * Strategy descriptor linking {@link AuthorizationCodeConfig} to its
 * {@link AuthorizationCodeAuth} implementation. Used by {@link createCliAuth}
 * for type-level strategy selection.
 *
 * @internal
 */
export type AuthorizationCodeStrategy = { config: AuthorizationCodeConfig; auth: AuthorizationCodeAuth };

/**
 * OAuth 2.0 Authorization Code + PKCE flow (RFC 6749 §4.1 + RFC 7636).
 *
 * Intended for interactive CLI logins on a workstation with a browser. On
 * {@link AuthorizationCodeAuth.login | login()} the instance:
 *
 * 1. Generates a PKCE verifier/challenge and random `state`.
 * 2. Starts a loopback HTTP server on `127.0.0.1` (random port by default).
 * 3. Invokes the provided `onAuthorization` callback with the authorization
 *    URL for the caller to open in the user's browser.
 * 4. Waits for the provider to redirect back to the loopback callback, then
 *    exchanges the authorization code for a token set and persists it.
 *
 * Construct via {@link createCliAuth} with `strategy: "authorization-code"`.
 */
export class AuthorizationCodeAuth {
  private readonly config: AuthorizationCodeConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  /** Literal strategy discriminator returned by {@link status}. */
  readonly strategy = "authorization-code" as const;

  /**
   * Creates a new strategy instance. Prefer {@link createCliAuth} over calling
   * this directly; the factory picks the right class for your config.
   *
   * @throws If `callbackPath` is set but does not start with `/` or contains a
   *   query string / fragment.
   */
  constructor(config: AuthorizationCodeConfig) {
    if (
      config.callbackPath !== undefined &&
      (!config.callbackPath.startsWith("/") ||
        config.callbackPath.includes("?") ||
        config.callbackPath.includes("#"))
    ) {
      throw new CliAuthError(
        "config.invalid",
        "callbackPath must start with '/' and contain no query or fragment",
        { field: "callbackPath" }
      );
    }
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

  /**
   * Runs the interactive login flow end-to-end and persists the resulting
   * tokens via the configured {@link Storage}.
   *
   * The call resolves once the token exchange succeeds. It rejects if the
   * authorization server returns an error, the `state` parameter mismatches,
   * or the callback URL is missing an authorization code.
   *
   * The loopback server is started on entry and always closed before this
   * method returns (successfully or not).
   *
   * @param options.onAuthorization - Invoked once with the fully-built
   *   authorization URL. The caller is expected to open it in the user's
   *   browser (e.g. via `open` or a printed instruction).
   */
  async login(options: {
    /** Invoked with the authorization URL to open in the user's browser. */
    onAuthorization: (url: string) => void;
  }) {
    const { clientId, provider, scope, extraParams, resource, callbackPort, callbackPath = "/callback" } = this.config;
    const { authorizationEndpoint } = provider.metadata;
    if (!authorizationEndpoint) {
      throw new CliAuthError(
        "config.invalid",
        "authorizationEndpoint is required for authorization-code strategy",
        { field: "authorizationEndpoint" }
      );
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

    const redirectUri = `http://127.0.0.1:${port}${callbackPath}`;

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

    const callbackSource = this.config.callbackSource;

    let code: string;
    try {
      code = await new Promise<string>((resolve, reject) => {
        callbackServer.on("request", (req, res) => {
          const url = new URL(req.url!, `http://127.0.0.1:${port}`);

          if (url.pathname !== callbackPath) {
            res.writeHead(404).end();
            return;
          }

          const result = classify(url, state);

          void (async () => {
            try {
              if (callbackSource) {
                await callbackSource(res, result);
              } else {
                writeDefault(res, result);
              }
            } catch {
              // The developer's hook threw. Write a best-effort 500 so the
              // browser tab does not hang, but never let a rendering bug
              // change the CLI-side resolve/reject decision below.
              try {
                res
                  .writeHead(500, {
                    "Content-Type": "text/html; charset=utf-8",
                  })
                  .end("<h1>Internal error</h1>");
              } catch {
                // Headers may already be sent; nothing more we can do.
              }
            }

            if (result.success) {
              resolve(result.callbackUrl.searchParams.get("code")!);
            } else {
              reject(errorFromResult(result));
            }
          })();
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

  /**
   * Returns a valid access token for the given `options` key.
   *
   * Serves a cached token when one is fresh; otherwise refreshes using the
   * stored refresh token. Concurrent refreshes across processes are
   * serialized when the configured {@link Storage} provides `lock()`.
   *
   * @throws If no token is available and no refresh is possible. Call
   *   {@link login} first.
   */
  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  /**
   * Clears all persisted tokens. When the provider exposes a revocation
   * endpoint, best-effort revokes the stored refresh token first — revocation
   * failures are swallowed so local cleanup always succeeds.
   */
  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  /**
   * Reports whether any tokens are currently persisted. Does not verify the
   * token with the provider — for that, call {@link getToken} and handle
   * failures.
   */
  async status(): Promise<{ authenticated: boolean; strategy: "authorization-code" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
