import type { DeviceCodeConfig } from "../config.js";
import type { GetTokenOptions, TokenResponse } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { refreshTokenGrant, revokeToken } from "../utils.js";

/**
 * Strategy descriptor linking {@link DeviceCodeConfig} to its
 * {@link DeviceCodeAuth} implementation. Used by {@link createCliAuth} for
 * type-level strategy selection.
 *
 * @internal
 */
export type DeviceCodeStrategy = { config: DeviceCodeConfig; auth: DeviceCodeAuth };

/**
 * OAuth 2.0 Device Authorization grant (RFC 8628).
 *
 * Intended for CLIs running in environments where opening a browser is
 * impractical (SSH sessions, containers, headless servers). On
 * {@link DeviceCodeAuth.login | login()} the instance:
 *
 * 1. Requests a device + user code from the provider.
 * 2. Invokes the caller-supplied `onAuthorization` callback with the user
 *    code and verification URL so the caller can display them.
 * 3. Polls the token endpoint until the user approves, the code expires, or
 *    the provider returns a terminal error.
 *
 * Construct via {@link createCliAuth} with `strategy: "device-code"`.
 */
export class DeviceCodeAuth {
  private readonly config: DeviceCodeConfig;
  private readonly tokenManager: TokenManager;
  private readonly fetch: typeof fetch;

  /** Literal strategy discriminator returned by {@link status}. */
  readonly strategy = "device-code" as const;

  /**
   * Creates a new strategy instance. Prefer {@link createCliAuth} over calling
   * this directly.
   */
  constructor(config: DeviceCodeConfig) {
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
   * Runs the device code flow end-to-end and persists the resulting tokens
   * via the configured {@link Storage}.
   *
   * Resolves once the user approves on a separate device. Rejects if the
   * device code expires, or the provider returns a terminal error during
   * polling.
   *
   * @param options.onAuthorization - Invoked once, as soon as the device code
   *   is obtained, with the user-facing strings the caller should display
   *   (typically the `userCode` and `verificationUri`, or the single
   *   pre-filled `verificationUriComplete` if the provider returns one).
   */
  async login(options: {
    /**
     * Invoked once with the strings the user needs to complete the flow on a
     * separate device.
     */
    onAuthorization: (authorization: {
      /** Short code the user types at `verificationUri`. */
      userCode: string;
      /** URL the user visits to enter `userCode`. */
      verificationUri: string;
      /**
       * URL that pre-fills the user code when opened. Not all providers
       * return this.
       */
      verificationUriComplete?: string;
      /** Remaining validity of the device code, in seconds. */
      expiresIn: number;
    }) => void;
  }) {
    const { clientId, provider, resource, scope, extraParams } = this.config;
    const { deviceAuthorizationEndpoint } = provider.metadata;
    if (!deviceAuthorizationEndpoint) {
      throw new Error("deviceAuthorizationEndpoint is required for device-code strategy");
    }

    // Step 1: Request device authorization
    const deviceAuthBody = new URLSearchParams({
      client_id: clientId,
    });
    if (resource) deviceAuthBody.set("resource", resource);
    if (scope) deviceAuthBody.set("scope", scope);
    if (extraParams) {
      for (const [key, value] of Object.entries(extraParams)) {
        deviceAuthBody.set(key, value);
      }
    }

    const deviceAuthResponse = await this.fetch(
      deviceAuthorizationEndpoint,
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
    options.onAuthorization({
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
        client_id: clientId,
        device_code: deviceAuth.device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      });
      if (resource) {
        tokenBody.set("resource", resource);
      }

      const tokenResponse = await this.fetch(provider.metadata.tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString(),
      });

      if (tokenResponse.ok) {
        const data = (await tokenResponse.json()) as TokenResponse;
        await this.tokenManager.save(data);
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
  }

  /**
   * Returns a valid access token for the given `options` key, refreshing in
   * the background when the cached token is close to expiry.
   *
   * @throws If no token is available and no refresh is possible. Call
   *   {@link login} first.
   */
  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  /**
   * Clears all persisted tokens. Best-effort revokes the stored refresh
   * token when the provider exposes a revocation endpoint.
   */
  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  /**
   * Reports whether any tokens are currently persisted. Does not validate
   * them with the provider.
   */
  async status(): Promise<{ authenticated: boolean; strategy: "device-code" }> {
    return { authenticated: await this.tokenManager.hasToken(), strategy: this.strategy };
  }
}
