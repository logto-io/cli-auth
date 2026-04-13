import type { TokenResponse } from "./types.js";

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
): Promise<TokenResponse> {
  return fetchTokenResponse(
    tokenEndpoint,
    new URLSearchParams({
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  );
}
