import type { Storage, TokenResponse } from "./types.js";

export function createTokenManager<TStrategy extends string>(config: {
  storage: Storage;
  strategy: TStrategy;
  tokenRefreshThreshold?: number;
  onRefresh: (refreshToken?: string) => Promise<TokenResponse | undefined>;
}) {
  let accessToken: string | undefined;
  let refreshToken: string | undefined;
  let expiresAt: number | undefined;

  async function applyTokenResponse(data: TokenResponse) {
    accessToken = data.access_token;
    expiresAt = Date.now() + data.expires_in * 1000;
    refreshToken = data.refresh_token;
    await config.storage.save(data);
  }

  return {
    applyTokenResponse,
    async getToken() {
      if (!accessToken || expiresAt === undefined) {
        throw new Error("Not logged in. Call login() first.");
      }
      const threshold = (config.tokenRefreshThreshold ?? 0) * 1000;
      if (Date.now() >= expiresAt - threshold) {
        const data = await config.onRefresh(refreshToken);
        if (data) {
          await applyTokenResponse(data);
        }
      }
      return accessToken;
    },
    async logout() {
      accessToken = undefined;
      refreshToken = undefined;
      expiresAt = undefined;
      await config.storage.clear();
    },
    async status() {
      return {
        authenticated: accessToken !== undefined,
        strategy: config.strategy,
      };
    },
  };
}

export async function refreshTokenGrant(
  tokenEndpoint: string,
  clientId: string,
  refreshToken: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new Error(
      `Token refresh failed with status ${response.status}`
    );
  }
  return (await response.json()) as TokenResponse;
}
