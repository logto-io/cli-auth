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

export async function fetchTokenResponse(params: {
  endpoint: string;
  body: URLSearchParams;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
}): Promise<TokenResponse> {
  const fetchFn = params.fetch ?? globalThis.fetch;
  const response = await fetchFn(params.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...params.headers },
    body: params.body.toString(),
  });
  if (!response.ok) {
    throw new Error(`Token request failed with status ${response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

export async function refreshTokenGrant(params: {
  tokenEndpoint: string;
  clientId: string;
  refreshToken: string;
  options?: GetTokenOptions;
  fetch?: typeof fetch;
}): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: params.clientId,
    grant_type: "refresh_token",
    refresh_token: params.refreshToken,
  });
  if (params.options?.resource) {
    body.set("resource", params.options.resource);
  }
  if (params.options?.extraParams) {
    for (const [key, value] of Object.entries(params.options.extraParams)) {
      body.set(key, value);
    }
  }
  return fetchTokenResponse({ endpoint: params.tokenEndpoint, body, fetch: params.fetch });
}
