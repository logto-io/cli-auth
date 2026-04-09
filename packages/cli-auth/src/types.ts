export type Storage = {
  load: () => Promise<unknown>;
  save: (credential: unknown) => Promise<void>;
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

export type ClientCredentialsConfig = {
  strategy: "client-credentials";
  provider: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

export type DeviceCodeConfig = {
  strategy: "device-code";
  provider: {
    deviceAuthorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
};

export type AuthorizationCodeConfig = {
  strategy: "authorization-code";
  provider: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
  };
  storage: Storage;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  callbackPort?: number;
  tokenRefreshThreshold?: number;
};

export type CliAuthConfig = ClientCredentialsConfig | DeviceCodeConfig | AuthorizationCodeConfig;

type BaseAuth<TStrategy extends string> = {
  getToken: () => Promise<string | undefined>;
  logout: () => Promise<void>;
  status: () => Promise<{ authenticated: boolean; strategy: TStrategy }>;
};

export type ClientCredentialsAuth = BaseAuth<"client-credentials"> & {
  login: () => Promise<void>;
};

export type DeviceCodeAuth = BaseAuth<"device-code"> & {
  login: (options?: {
    onAuthorization?: (authorization: {
      userCode: string;
      verificationUri: string;
      verificationUriComplete?: string;
      expiresIn: number;
    }) => void;
  }) => Promise<void>;
};

export type AuthorizationCodeAuth = BaseAuth<"authorization-code"> & {
  login: (options?: {
    onAuthorization?: (url: string) => void;
  }) => Promise<void>;
};
