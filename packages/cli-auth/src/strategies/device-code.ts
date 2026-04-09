import type { DeviceCodeConfig, DeviceCodeAuth, TokenResponse } from "../types.js";
import { createTokenManager, refreshTokenGrant } from "../token-manager.js";

export function createDeviceCodeAuth(config: DeviceCodeConfig): DeviceCodeAuth {
  const { provider, storage, resource, scope, extraParams, tokenRefreshThreshold } = config;

  const tokenManager = createTokenManager({
    storage,
    strategy: "device-code",
    tokenRefreshThreshold,
    onRefresh: async (currentRefreshToken) => {
      if (!currentRefreshToken) return undefined;
      return refreshTokenGrant(provider.tokenEndpoint, provider.clientId, currentRefreshToken);
    },
  });

  return {
    async login(options) {
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
          await tokenManager.applyTokenResponse(data);
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
    getToken: tokenManager.getToken,
    logout: tokenManager.logout,
    status: tokenManager.status,
  };
}
