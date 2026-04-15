import type { DeviceCodeConfig } from "../config.js";
import type { GetTokenOptions, TokenResponse } from "../types.js";
import { TokenManager } from "../token-manager.js";
import { refreshTokenGrant } from "../utils.js";

export type DeviceCodeStrategy = { config: DeviceCodeConfig; auth: DeviceCodeAuth };

export class DeviceCodeAuth {
  private readonly config: DeviceCodeConfig;
  private readonly tokenManager: TokenManager;

  readonly strategy = "device-code" as const;

  constructor(config: DeviceCodeConfig) {
    this.config = config;
    this.tokenManager = new TokenManager({
      storage: config.storage,
      tokenRefreshThreshold: config.tokenRefreshThreshold,
      refresh: (refreshToken, options) => {
        if (!refreshToken) return Promise.resolve(undefined);
        return refreshTokenGrant(config.provider.metadata.tokenEndpoint, config.clientId, refreshToken, options);
      },
    });
  }

  async login(options: {
    onAuthorization: (authorization: {
      userCode: string;
      verificationUri: string;
      verificationUriComplete?: string;
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

    const deviceAuthResponse = await fetch(
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

      const tokenResponse = await fetch(provider.metadata.tokenEndpoint, {
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

  async getToken(options?: GetTokenOptions): Promise<string> {
    return this.tokenManager.getToken(options);
  }

  async logout(): Promise<void> {
    return this.tokenManager.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: "device-code" }> {
    return { authenticated: this.tokenManager.hasToken, strategy: this.strategy };
  }
}
