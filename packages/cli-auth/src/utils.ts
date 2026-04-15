import type { GetTokenOptions, TokenResponse } from "./types.js";

export function buildTokenCacheKey(options?: GetTokenOptions): string {
  const parts: string[] = [];
  if (options?.resource) {
    parts.push(`resource=${options.resource}`);
  }
  if (options?.extraParams) {
    for (const [key, value] of Object.entries(options.extraParams).sort(([a], [b]) => a.localeCompare(b))) {
      parts.push(`${key}=${value}`);
    }
  }
  return parts.join("&");
}

export async function fetchTokenResponse(
  endpoint: string,
  body: URLSearchParams,
  headers?: Record<string, string>,
): Promise<TokenResponse> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new Error(`Token request failed with status ${response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

export async function refreshTokenGrant(
  tokenEndpoint: string,
  clientId: string,
  refreshToken: string,
  options?: GetTokenOptions,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  if (options?.resource) {
    body.set("resource", options.resource);
  }
  if (options?.extraParams) {
    for (const [key, value] of Object.entries(options.extraParams)) {
      body.set(key, value);
    }
  }
  return fetchTokenResponse(tokenEndpoint, body);
}
