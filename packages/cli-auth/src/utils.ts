import type { GetTokenOptions, TokenResponse } from "./types.js";
import { CliAuthError } from "./errors.js";

/**
 * Tries to read an RFC 6749 §5.2 error response body from `response`.
 * Returns the parsed `{error, error_description?}` on match, or `undefined`
 * if the body is missing, not JSON, or doesn't carry a string `error`.
 */
export async function tryParseOAuthError(
  response: Response
): Promise<{ error: string; error_description?: string } | undefined> {
  const body = await response.json().catch(() => undefined);
  if (
    body !== null &&
    typeof body === "object" &&
    typeof (body as { error?: unknown }).error === "string"
  ) {
    return body as { error: string; error_description?: string };
  }
  return undefined;
}

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
    const oauthError = await tryParseOAuthError(response);
    if (oauthError) {
      throw new CliAuthError(
        "provider.rejected",
        oauthError.error_description
          ? `Token request failed: ${oauthError.error} (${oauthError.error_description})`
          : `Token request failed: ${oauthError.error}`,
        {
          endpoint: "token",
          error: oauthError.error,
          errorDescription: oauthError.error_description,
        }
      );
    }
    throw new CliAuthError(
      "request.failed",
      `Token request failed with status ${response.status}`,
      { endpoint: "token", status: response.status }
    );
  }
  return (await response.json()) as TokenResponse;
}

export async function revokeToken(params: {
  endpoint: string;
  clientId: string;
  token: string;
  fetch?: typeof fetch;
}): Promise<void> {
  const fetchFn = params.fetch ?? globalThis.fetch;
  const response = await fetchFn(params.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: params.clientId,
      token: params.token,
    }).toString(),
  });
  if (!response.ok) {
    throw new CliAuthError(
      "request.failed",
      `Token revocation failed with status ${response.status}`,
      { endpoint: "revocation", status: response.status }
    );
  }
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
