import type { Storage, TokenSet } from "./types.js";

// === Provider ===

export type ProviderMetadata = {
  tokenEndpoint: string;
  authorizationEndpoint?: string;
  deviceAuthorizationEndpoint?: string;
  revocationEndpoint?: string;
};

export type ProviderConfig = {
  metadata: ProviderMetadata;
};

// === Base config (shared by all strategies) ===

export type BaseConfig = {
  provider: ProviderConfig;
  clientId: string;
  storage: Storage<TokenSet>;
  resource?: string;
  scope?: string;
  extraParams?: Record<string, string>;
  tokenRefreshThreshold?: number;
  fetch?: typeof fetch;
};

// === Strategy configs ===

export type ClientCredentialsConfig = BaseConfig & {
  strategy: "client-credentials";
  clientSecret: string;
  tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
};

export type DeviceCodeConfig = BaseConfig & {
  strategy: "device-code";
};

export type AuthorizationCodeConfig = BaseConfig & {
  strategy: "authorization-code";
  callbackPort?: number;
  callbackPath?: string;
};

export type TokenExchangeConfig = BaseConfig & {
  strategy: "token-exchange";
  subjectToken: string;
  subjectTokenType: string;
  actorToken?: string;
  actorTokenType?: string;
  clientSecret?: string;
  tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
};
