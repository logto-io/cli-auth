import type { DeviceCodeStrategy } from "./strategies/device-code.js";
import type { AuthorizationCodeStrategy } from "./strategies/authorization-code.js";
import type { ClientCredentialsStrategy } from "./strategies/client-credentials.js";
import { DeviceCodeAuth } from "./strategies/device-code.js";
import { AuthorizationCodeAuth } from "./strategies/authorization-code.js";
import { ClientCredentialsAuth } from "./strategies/client-credentials.js";

export type { Storage, TokenResponse } from "./types.js";
export { BaseAuth } from "./base-auth.js";
export { DeviceCodeAuth, type DeviceCodeConfig } from "./strategies/device-code.js";
export { AuthorizationCodeAuth, type AuthorizationCodeConfig } from "./strategies/authorization-code.js";
export { ClientCredentialsAuth, type ClientCredentialsConfig } from "./strategies/client-credentials.js";

export type CliAuthConfig =
  | DeviceCodeStrategy["config"]
  | AuthorizationCodeStrategy["config"]
  | ClientCredentialsStrategy["config"];

type StrategyMap = {
  "device-code": DeviceCodeStrategy;
  "authorization-code": AuthorizationCodeStrategy;
  "client-credentials": ClientCredentialsStrategy;
};

const strategies: { [K in keyof StrategyMap]: new (config: StrategyMap[K]["config"]) => StrategyMap[K]["auth"] } = {
  "device-code": DeviceCodeAuth,
  "authorization-code": AuthorizationCodeAuth,
  "client-credentials": ClientCredentialsAuth,
};

export function createCliAuth<K extends keyof StrategyMap>(
  config: StrategyMap[K]["config"] & { strategy: K }
): StrategyMap[K]["auth"] {
  return new strategies[config.strategy](config);
}
