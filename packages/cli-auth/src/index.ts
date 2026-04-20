import type { DeviceCodeStrategy } from "./strategies/device-code.js";
import type { AuthorizationCodeStrategy } from "./strategies/authorization-code.js";
import type { ClientCredentialsStrategy } from "./strategies/client-credentials.js";
import type { TokenExchangeStrategy } from "./strategies/token-exchange.js";
import { DeviceCodeAuth } from "./strategies/device-code.js";
import { AuthorizationCodeAuth } from "./strategies/authorization-code.js";
import { ClientCredentialsAuth } from "./strategies/client-credentials.js";
import { TokenExchangeAuth } from "./strategies/token-exchange.js";

export type { Storage, TokenResponse, GetTokenOptions, TokenSet } from "./types.js";
export type {
  ProviderMetadata,
  ProviderConfig,
  BaseConfig,
  ClientCredentialsConfig,
  DeviceCodeConfig,
  AuthorizationCodeConfig,
  TokenExchangeConfig,
  CallbackResult,
  CallbackSource,
} from "./config.js";
export { TokenManager } from "./token-manager.js";
export type { TokenManagerConfig } from "./token-manager.js";
export { CliAuthError } from "./errors.js";
export type { CliAuthErrorCode } from "./errors.js";
export { memoryStorage } from "./storage/memory.js";
export { fileStorage } from "./storage/file.js";
export { fileLock } from "./storage/file-lock.js";
export { keyringStorage } from "./storage/keyring.js";
export type { KeyringEntry } from "./storage/keyring.js";

/**
 * Discriminated union of every supported strategy config. Narrow on
 * `strategy` to get the strategy-specific fields.
 */
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

/**
 * Creates an authentication client for the strategy declared on `config`.
 *
 * The return type is inferred from `config.strategy`, so each call yields the
 * strategy-specific class ({@link AuthorizationCodeAuth},
 * {@link DeviceCodeAuth}, {@link ClientCredentialsAuth}, or
 * {@link TokenExchangeAuth}) with the methods that strategy supports.
 *
 * @example Authorization code + PKCE in a desktop CLI
 * ```ts
 * import { createCliAuth, fileStorage } from "cli-auth";
 *
 * const auth = createCliAuth({
 *   strategy: "authorization-code",
 *   provider: { metadata: {
 *     authorizationEndpoint: "https://issuer.example.com/authorize",
 *     tokenEndpoint: "https://issuer.example.com/token",
 *   }},
 *   clientId: "my-cli",
 *   scope: "openid profile offline_access",
 *   storage: fileStorage({ dir: `${process.env.HOME}/.my-cli` }),
 * });
 *
 * await auth.login({ onAuthorization: (url) => console.log(`Open ${url}`) });
 * const accessToken = await auth.getToken();
 * ```
 */
export function createCliAuth<K extends keyof StrategyMap>(
  config: StrategyMap[K]["config"] & { strategy: K }
): StrategyMap[K]["auth"] {
  return new strategies[config.strategy](config);
}
