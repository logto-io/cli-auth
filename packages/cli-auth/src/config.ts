import { z } from "zod/v4";

import type { Storage, TokenSet } from "./types.js";

// === Provider ===

export const providerMetadataSchema = z.object({
  tokenEndpoint: z.string(),
  authorizationEndpoint: z.string().optional(),
  deviceAuthorizationEndpoint: z.string().optional(),
  revocationEndpoint: z.string().optional(),
});

export const providerConfigSchema = z.object({
  metadata: providerMetadataSchema,
});

// === Base config (shared by all strategies) ===

export const baseConfigSchema = z.object({
  provider: providerConfigSchema,
  clientId: z.string(),
  storage: z.custom<Storage<TokenSet>>(),
  resource: z.string().optional(),
  scope: z.string().optional(),
  extraParams: z.record(z.string(), z.string()).optional(),
  tokenRefreshThreshold: z.number().optional(),
  fetch: z.custom<typeof fetch>().optional(),
});

// === Strategy configs ===

export const clientCredentialsConfigSchema = baseConfigSchema.extend({
  strategy: z.literal("client-credentials"),
  clientSecret: z.string(),
  tokenEndpointAuthMethod: z
    .enum(["client_secret_post", "client_secret_basic"])
    .optional(),
});

export const deviceCodeConfigSchema = baseConfigSchema.extend({
  strategy: z.literal("device-code"),
});

export const authorizationCodeConfigSchema = baseConfigSchema.extend({
  strategy: z.literal("authorization-code"),
  callbackPort: z.number().optional(),
});

export const tokenExchangeConfigSchema = baseConfigSchema.extend({
  strategy: z.literal("token-exchange"),
  subjectToken: z.string(),
  subjectTokenType: z.string(),
  actorToken: z.string().optional(),
  actorTokenType: z.string().optional(),
  clientSecret: z.string().optional(),
  tokenEndpointAuthMethod: z
    .enum(["client_secret_post", "client_secret_basic"])
    .optional(),
});

// === Inferred types ===

export type ProviderMetadata = z.infer<typeof providerMetadataSchema>;
export type ProviderConfig = z.infer<typeof providerConfigSchema>;
export type BaseConfig = z.infer<typeof baseConfigSchema>;
export type ClientCredentialsConfig = z.infer<
  typeof clientCredentialsConfigSchema
>;
export type DeviceCodeConfig = z.infer<typeof deviceCodeConfigSchema>;
export type AuthorizationCodeConfig = z.infer<
  typeof authorizationCodeConfigSchema
>;
export type TokenExchangeConfig = z.infer<typeof tokenExchangeConfigSchema>;
