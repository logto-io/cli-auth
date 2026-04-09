import type { Storage, TokenResponse } from "./types.js";

export abstract class BaseAuth<TStrategy extends string> {
  private accessToken: string | undefined;
  private refreshToken: string | undefined;
  private expiresAt: number | undefined;

  constructor(
    protected readonly storage: Storage,
    readonly strategy: TStrategy,
    protected readonly tokenRefreshThreshold?: number,
    protected readonly resource?: string,
    protected readonly scope?: string,
    protected readonly extraParams?: Record<string, string>,
  ) {}

  protected async onRefresh(_refreshToken?: string): Promise<TokenResponse | undefined> {
    return undefined;
  }

  protected async applyTokenResponse(data: TokenResponse) {
    this.accessToken = data.access_token;
    this.expiresAt = Date.now() + data.expires_in * 1000;
    this.refreshToken = data.refresh_token;
    await this.storage.save(data);
  }

  async getToken(): Promise<string> {
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

  protected applyOptionalParams(params: { set(key: string, value: string): void }) {
    if (this.resource) params.set("resource", this.resource);
    if (this.scope) params.set("scope", this.scope);
    if (this.extraParams) {
      for (const [key, value] of Object.entries(this.extraParams)) {
        params.set(key, value);
      }
    }
  }

  async status(): Promise<{ authenticated: boolean; strategy: TStrategy }> {
    return {
      authenticated: this.accessToken !== undefined,
      strategy: this.strategy,
    };
  }
}

export async function fetchTokenResponse(
  endpoint: string,
  body: URLSearchParams,
  headers?: Record<string, string>,
): Promise<TokenResponse> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new Error(`Token request failed with status ${response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

export async function refreshTokenGrant(
  tokenEndpoint: string,
  clientId: string,
  refreshToken: string,
): Promise<TokenResponse> {
  return fetchTokenResponse(
    tokenEndpoint,
    new URLSearchParams({
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  );
}
