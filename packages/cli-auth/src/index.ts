import type { DeviceCodeStrategy } from "./strategies/device-code.js";
import type { AuthorizationCodeStrategy } from "./strategies/authorization-code.js";
import type { ClientCredentialsStrategy } from "./strategies/client-credentials.js";
import type { TokenExchangeStrategy } from "./strategies/token-exchange.js";
import { DeviceCodeAuth } from "./strategies/device-code.js";
import { AuthorizationCodeAuth } from "./strategies/authorization-code.js";
import { ClientCredentialsAuth } from "./strategies/client-credentials.js";
import { TokenExchangeAuth } from "./strategies/token-exchange.js";

export type { Storage, TokenResponse } from "./types.js";
export type {
  ProviderType,
  ProviderMetadata,
  ProviderConfig,
  BaseConfig,
  ClientCredentialsConfig,
  DeviceCodeConfig,
  AuthorizationCodeConfig,
  TokenExchangeConfig,
} from "./config.js";
export {
  providerTypeSchema,
  providerMetadataSchema,
  providerConfigSchema,
  baseConfigSchema,
  clientCredentialsConfigSchema,
  deviceCodeConfigSchema,
  authorizationCodeConfigSchema,
  tokenExchangeConfigSchema,
} from "./config.js";
export { BaseAuth } from "./base-auth.js";
export { DeviceCodeAuth } from "./strategies/device-code.js";
export { AuthorizationCodeAuth } from "./strategies/authorization-code.js";
export { ClientCredentialsAuth } from "./strategies/client-credentials.js";
export { TokenExchangeAuth } from "./strategies/token-exchange.js";

export type CliAuthConfig =
  | DeviceCodeStrategy["config"]
  | AuthorizationCodeStrategy["config"]
  | ClientCredentialsStrategy["config"]
  | TokenExchangeStrategy["config"];

type StrategyMap = {
  "device-code": DeviceCodeStrategy;
  "authorization-code": AuthorizationCodeStrategy;
  "client-credentials": ClientCredentialsStrategy;
  "token-exchange": TokenExchangeStrategy;
};

const strategies: { [K in keyof StrategyMap]: new (config: StrategyMap[K]["config"]) => StrategyMap[K]["auth"] } = {
  "device-code": DeviceCodeAuth,
  "authorization-code": AuthorizationCodeAuth,
  "client-credentials": ClientCredentialsAuth,
  "token-exchange": TokenExchangeAuth,
};

export function createCliAuth<K extends keyof StrategyMap>(
  config: StrategyMap[K]["config"] & { strategy: K }
): StrategyMap[K]["auth"] {
  return new strategies[config.strategy](config);
}
