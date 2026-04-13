import type { DeviceCodeConfig } from "../config.js";
import type { TokenResponse } from "../types.js";
import { BaseAuth, refreshTokenGrant } from "../base-auth.js";

export type DeviceCodeStrategy = { config: DeviceCodeConfig; auth: DeviceCodeAuth };

export class DeviceCodeAuth extends BaseAuth<"device-code"> {
  constructor(config: DeviceCodeConfig) {
    const { provider, clientId, storage, tokenRefreshThreshold, resource, scope, extraParams } = config;
    super({ provider, clientId, storage, strategy: "device-code", tokenRefreshThreshold, resource, scope, extraParams });
  }

  protected async onRefresh(currentRefreshToken?: string) {
    if (!currentRefreshToken) return undefined;
    return refreshTokenGrant(this.provider.metadata.tokenEndpoint, this.clientId, currentRefreshToken);
  }

  async login(options: {
    onAuthorization: (authorization: {
      userCode: string;
      verificationUri: string;
      verificationUriComplete?: string;
      expiresIn: number;
    }) => void;
  }) {
    const { deviceAuthorizationEndpoint } = this.provider.metadata;
    if (!deviceAuthorizationEndpoint) {
      throw new Error("deviceAuthorizationEndpoint is required for device-code strategy");
    }

    // Step 1: Request device authorization
    const deviceAuthBody = new URLSearchParams({
      client_id: this.clientId,
    });
    this.applyOptionalParams(deviceAuthBody);

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
        client_id: this.clientId,
        device_code: deviceAuth.device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      });
      if (this.resource) {
        tokenBody.set("resource", this.resource);
      }

      const tokenResponse = await fetch(this.provider.metadata.tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString(),
      });

      if (tokenResponse.ok) {
        const data = (await tokenResponse.json()) as TokenResponse;
        await this.applyTokenResponse(data);
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
}
