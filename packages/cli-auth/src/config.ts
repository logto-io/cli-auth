import type { ServerResponse } from "node:http";

import type { Storage, TokenSet } from "./types.js";

// === Authorization-code callback response ===

/**
 * The result of processing an OAuth authorization-code callback, passed to
 * {@link AuthorizationCodeConfig.callbackSource} so the developer can render
 * an appropriate response body.
 */
export type CallbackResult = {
  /**
   * Whether the library considers this callback successful and will proceed
   * to exchange the authorization code for tokens.
   *
   * `true` means the callback carried a valid `code`, the `state` matched,
   * and no OAuth `error` was present.
   *
   * `false` means one of:
   *  - the authorization server returned an `error` in the query string
   *    (read `callbackUrl.searchParams.get("error")` for the code and
   *    `callbackUrl.searchParams.get("error_description")` for the message), or
   *  - a local integrity check failed (see {@link verifyError}).
   *
   * Use this as the primary branching signal. It keeps the browser UI in
   * sync with the CLI-side `login()` result even when the callback URL
   * looks superficially successful (e.g. a forged `code` with the wrong
   * `state`).
   */
  success: boolean;

  /**
   * The full callback URL as received from the authorization server, parsed
   * into a `URL` object. Query parameters (`code`, `state`, `error`,
   * `error_description`, etc.) can be read from `callbackUrl.searchParams`.
   *
   * The object is untouched — nothing has been normalized or redacted.
   * Note that `code` is included here; treat it as you would any secret
   * (do not log verbatim).
   */
  callbackUrl: URL;

  /**
   * If the callback failed because of a *local* integrity check performed by
   * the library (not because the authorization server returned an error),
   * this identifies which check failed:
   *
   *  - `"state_mismatch"` — the `state` parameter did not match the one the
   *    library generated when starting the flow. Usually indicates a CSRF
   *    attempt or that a stale callback link was opened.
   *  - `"missing_code"` — the callback URL contained neither a `code` nor an
   *    `error` parameter. Usually indicates a malformed or tampered URL.
   *
   * `undefined` when either:
   *  - the callback was successful, or
   *  - the failure came from the authorization server; read
   *    `callbackUrl.searchParams.get("error")` for that case.
   */
  verifyError?: "state_mismatch" | "missing_code";
};

/**
 * A function that writes the HTTP response returned to the browser after the
 * authorization server redirects back to the loopback callback URL.
 *
 * Invoked for every callback — successful and failed alike — with the raw
 * Node {@link ServerResponse} and a {@link CallbackResult} describing what
 * the library determined about this callback. Writing to `res`
 * (`res.writeHead`, `res.end`, etc.) is the developer's responsibility.
 *
 * If the hook throws (synchronously or asynchronously), a minimal `500`
 * fallback page is written to the browser, but the CLI-side `login()`
 * result is unaffected: the library always makes the final success/failure
 * decision independently based on `result.success`.
 */
export type CallbackSource = (
  res: ServerResponse,
  result: CallbackResult
) => void | Promise<void>;

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
  /**
   * Customize the HTTP response returned to the browser after the
   * authorization server redirects back to the loopback callback URL.
   *
   * When omitted, the library renders a minimal built-in HTML page
   * (`text/html; charset=utf-8`, status `200` on success / `400` on
   * failure).
   *
   * See {@link CallbackSource} for the full hook contract and failure
   * semantics.
   *
   * @example Custom success copy
   * ```ts
   * callbackSource: (res, { success, callbackUrl }) => {
   *   res.writeHead(success ? 200 : 400, {
   *     "Content-Type": "text/html; charset=utf-8",
   *   });
   *   res.end(success
   *     ? "<h1>Logged into Acme</h1><p>You can close this tab.</p>"
   *     : `<h1>Failed</h1><p>${callbackUrl.searchParams.get("error") ?? "unknown"}</p>`);
   * }
   * ```
   *
   * @example Redirect to a hosted landing page on success
   * ```ts
   * callbackSource: (res, { success }) => {
   *   if (success) {
   *     res.writeHead(302, { Location: "https://myapp.com/cli-success" });
   *     res.end();
   *   } else {
   *     res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
   *     res.end("<h1>Login failed</h1>");
   *   }
   * }
   * ```
   *
   * @example Distinguish OAuth errors from local verification errors
   * ```ts
   * callbackSource: (res, { success, callbackUrl, verifyError }) => {
   *   res.writeHead(success ? 200 : 400, {
   *     "Content-Type": "text/html; charset=utf-8",
   *   });
   *   if (success) return res.end("<h1>Logged in</h1>");
   *   if (verifyError) return res.end("<h1>Login link expired or tampered</h1>");
   *   const err = callbackUrl.searchParams.get("error");
   *   res.end(`<h1>Authorization failed</h1><p>${err ?? "unknown"}</p>`);
   * }
   * ```
   */
  callbackSource?: CallbackSource;
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
