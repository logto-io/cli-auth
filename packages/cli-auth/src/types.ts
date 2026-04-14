export type Storage<T = TokenResponse> = {
  load: () => Promise<T | undefined>;
  save: (credential: T) => Promise<void>;
  clear: () => Promise<void>;
};

export type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
};
