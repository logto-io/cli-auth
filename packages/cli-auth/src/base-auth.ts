import type { Storage, TokenResponse } from "./types.js";

export abstract class BaseAuth<TStrategy extends string> {
  private accessToken: string | undefined;
  private refreshToken: string | undefined;
  private expiresAt: number | undefined;

  constructor(
    protected readonly storage: Storage,
    readonly strategy: TStrategy,
    protected readonly tokenRefreshThreshold?: number,
  ) {}

  protected abstract onRefresh(refreshToken?: string): Promise<TokenResponse | undefined>;

  protected async applyTokenResponse(data: TokenResponse) {
    this.accessToken = data.access_token;
    this.expiresAt = Date.now() + data.expires_in * 1000;
    this.refreshToken = data.refresh_token;
    await this.storage.save(data);
  }

  async getToken(): Promise<string | undefined> {
    if (!this.accessToken || this.expiresAt === undefined) {
      throw new Error("Not logged in. Call login() first.");
    }
    const threshold = (this.tokenRefreshThreshold ?? 0) * 1000;
    if (Date.now() >= this.expiresAt - threshold) {
      const data = await this.onRefresh(this.refreshToken);
      if (data) {
        await this.applyTokenResponse(data);
      }
    }
    return this.accessToken;
  }

  async logout(): Promise<void> {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.expiresAt = undefined;
    await this.storage.clear();
  }

  async status(): Promise<{ authenticated: boolean; strategy: TStrategy }> {
    return {
      authenticated: this.accessToken !== undefined,
      strategy: this.strategy,
    };
  }
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
