import type { Storage, TokenResponse } from "./types.js";

export type TokenManagerConfig = {
  storage: Storage;
  refresh?: (refreshToken?: string) => Promise<TokenResponse | undefined>;
  tokenRefreshThreshold?: number;
};

export class TokenManager {
  private accessToken: string | undefined;
  private refreshToken: string | undefined;
  private expiresAt: number | undefined;

  private readonly storage: Storage;
  private readonly refresh?: (refreshToken?: string) => Promise<TokenResponse | undefined>;
  private readonly tokenRefreshThreshold?: number;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
  }

  get hasToken(): boolean {
    return this.accessToken !== undefined;
  }

  async save(data: TokenResponse): Promise<void> {
    this.accessToken = data.access_token;
    this.expiresAt = Date.now() + data.expires_in * 1000;
    this.refreshToken = data.refresh_token;
    await this.storage.save(data);
  }

  async getToken(): Promise<string> {
    if (!this.accessToken || this.expiresAt === undefined) {
      throw new Error("No token available.");
    }
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    if (Date.now() >= this.expiresAt - threshold) {
      const data = await this.refresh?.(this.refreshToken);
      if (data) {
        await this.save(data);
      } else {
        throw new Error("Token expired and cannot be refreshed.");
      }
    }
    return this.accessToken;
  }

  async clear(): Promise<void> {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.expiresAt = undefined;
    await this.storage.clear();
  }
}
