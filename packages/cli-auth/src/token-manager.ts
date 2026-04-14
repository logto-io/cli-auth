import type { Storage, TokenResponse } from "./types.js";

export type TokenManagerConfig<T extends TokenResponse = TokenResponse> = {
  storage: Storage<T>;
  refresh?: (refreshToken?: string) => Promise<T | undefined>;
  tokenRefreshThreshold?: number;
};

export class TokenManager<T extends TokenResponse = TokenResponse> {
  private accessToken: string | undefined;
  private refreshToken: string | undefined;
  private expiresAt: number | undefined;

  private readonly storage: Storage<T>;
  private readonly refresh?: (refreshToken?: string) => Promise<T | undefined>;
  private readonly tokenRefreshThreshold?: number;

  constructor(config: TokenManagerConfig<T>) {
    this.storage = config.storage;
    this.refresh = config.refresh;
    this.tokenRefreshThreshold = config.tokenRefreshThreshold;
  }

  get hasToken(): boolean {
    return this.accessToken !== undefined;
  }

  async save(data: T): Promise<void> {
    this.accessToken = data.access_token;
    this.expiresAt = Date.now() + data.expires_in * 1000;
    this.refreshToken = data.refresh_token;
    await this.storage.save(data);
  }

  async getToken(): Promise<string> {
    if (!this.accessToken || this.expiresAt === undefined) {
      throw new Error("No token available.");
    }
    if (this.isExpired()) {
      const release = await this.storage.lock?.();
      try {
        if (this.isExpired()) {
          await this.doRefresh();
        }
      } finally {
        await release?.();
      }
    }
    return this.accessToken;
  }

  private isExpired(): boolean {
    const threshold = (this.tokenRefreshThreshold ?? 300) * 1000;
    return this.expiresAt !== undefined && Date.now() >= this.expiresAt - threshold;
  }

  private async doRefresh(): Promise<void> {
    const data = await this.refresh?.(this.refreshToken);
    if (data) {
      await this.save(data);
    } else {
      throw new Error("Token expired and cannot be refreshed.");
    }
  }

  async clear(): Promise<void> {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.expiresAt = undefined;
    await this.storage.clear();
  }
}
