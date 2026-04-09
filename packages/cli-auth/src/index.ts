import type {
  CliAuthConfig,
  ClientCredentialsConfig,
  ClientCredentialsAuth,
  DeviceCodeConfig,
  DeviceCodeAuth,
  AuthorizationCodeConfig,
  AuthorizationCodeAuth,
} from "./types.js";
import { createDeviceCodeAuth } from "./strategies/device-code.js";
import { createAuthorizationCodeAuth } from "./strategies/authorization-code.js";
import { createClientCredentialsAuth } from "./strategies/client-credentials.js";

export type {
  Storage,
  TokenResponse,
  CliAuthConfig,
  ClientCredentialsConfig,
  ClientCredentialsAuth,
  DeviceCodeConfig,
  DeviceCodeAuth,
  AuthorizationCodeConfig,
  AuthorizationCodeAuth,
} from "./types.js";

export function createCliAuth(config: ClientCredentialsConfig): ClientCredentialsAuth;
export function createCliAuth(config: DeviceCodeConfig): DeviceCodeAuth;
export function createCliAuth(config: AuthorizationCodeConfig): AuthorizationCodeAuth;
export function createCliAuth(config: CliAuthConfig): ClientCredentialsAuth | DeviceCodeAuth | AuthorizationCodeAuth {
  if (config.strategy === "device-code") {
    return createDeviceCodeAuth(config);
  }

  if (config.strategy === "authorization-code") {
    return createAuthorizationCodeAuth(config);
  }

  return createClientCredentialsAuth(config);
}
