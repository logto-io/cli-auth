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

/**
 * OAuth 2.0 / OIDC endpoint URLs used by the library.
 *
 * Normally populated from the provider's
 * [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) discovery
 * document (`.well-known/openid-configuration`), but may be set manually for
 * providers that do not publish discovery metadata.
 */
export type ProviderMetadata = {
  /** Token endpoint. Required by every strategy. */
  tokenEndpoint: string;
  /**
   * Authorization endpoint. Required by the `authorization-code` strategy;
   * unused by the others.
   */
  authorizationEndpoint?: string;
  /**
   * Device authorization endpoint (RFC 8628). Required by the `device-code`
   * strategy; unused by the others.
   */
  deviceAuthorizationEndpoint?: string;
  /**
   * Token revocation endpoint (RFC 7009). When present, the library will
   * best-effort revoke the refresh token on `logout()`. Revocation failures
   * do not block local cleanup.
   */
  revocationEndpoint?: string;
};

/**
 * Identifies the authorization server the library should talk to.
 *
 * Currently a thin wrapper around {@link ProviderMetadata}; kept as its own
 * type so additional provider-level fields (e.g. issuer) can be added without
 * breaking existing call sites.
 */
export type ProviderConfig = {
  /** Endpoint URLs for this provider. */
  metadata: ProviderMetadata;
};

// === Base config (shared by all strategies) ===

/**
 * Configuration fields shared by every strategy. Each strategy's config
 * extends this with its own `strategy` discriminator and any strategy-specific
 * fields.
 */
export type BaseConfig = {
  /** The authorization server to use. */
  provider: ProviderConfig;
  /** OAuth 2.0 client identifier registered with the provider. */
  clientId: string;
  /**
   * Where tokens are persisted between CLI invocations. Pick one of the
   * built-in storage factories ({@link memoryStorage}, {@link fileStorage},
   * {@link keyringStorage}) or supply a custom {@link Storage}.
   */
  storage: Storage<TokenSet>;
  /**
   * Default RFC 8707 resource indicator, forwarded to the authorization
   * server on every token request unless overridden per-call via
   * {@link GetTokenOptions.resource}.
   */
  resource?: string;
  /** Default space-delimited scope string requested during login. */
  scope?: string;
  /**
   * Default provider-specific extra parameters forwarded on every token
   * request. Per-call {@link GetTokenOptions.extraParams} is merged on top
   * and wins on conflict.
   */
  extraParams?: Record<string, string>;
  /**
   * Seconds of remaining lifetime below which a cached access token is
   * considered expired and proactively refreshed. Defaults to `300` (5
   * minutes).
   */
  tokenRefreshThreshold?: number;
  /**
   * Custom `fetch` implementation. Defaults to `globalThis.fetch`. Useful for
   * routing through a proxy, injecting tracing headers, or testing with a
   * mock.
   */
  fetch?: typeof fetch;
};

// === Strategy configs ===

/**
 * Config for the OAuth 2.0 Client Credentials grant (RFC 6749 §4.4).
 *
 * Use for machine-to-machine CLI flows where the CLI itself owns a client
 * secret — no interactive user login takes place.
 */
export type ClientCredentialsConfig = BaseConfig & {
  /** Discriminator selecting this strategy. */
  strategy: "client-credentials";
  /** Client secret paired with `clientId`. */
  clientSecret: string;
  /**
   * How client credentials are presented to the token endpoint. Defaults to
   * `"client_secret_post"` (body fields); switch to `"client_secret_basic"`
   * to send them in the HTTP `Authorization` header.
   */
  tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
};

/**
 * Config for the OAuth 2.0 Device Authorization grant (RFC 8628).
 *
 * Use for CLIs running in environments without a browser (SSH sessions,
 * containers, headless servers): the user completes the login on a separate
 * device by visiting a verification URL and entering the displayed user code.
 */
export type DeviceCodeConfig = BaseConfig & {
  /** Discriminator selecting this strategy. */
  strategy: "device-code";
};

/**
 * Config for the OAuth 2.0 Authorization Code grant with PKCE (RFC 7636).
 *
 * Use for interactive CLI logins on a workstation with a browser: the library
 * starts a short-lived loopback HTTP server on `127.0.0.1`, opens the
 * authorization URL, and exchanges the returned authorization code for
 * tokens. The loopback server only binds to the loopback interface and uses
 * a random port by default.
 */
export type AuthorizationCodeConfig = BaseConfig & {
  /** Discriminator selecting this strategy. */
  strategy: "authorization-code";
  /**
   * Port for the local loopback callback server. Defaults to `0`, which
   * lets the OS pick an available port on each login. Set a fixed port only
   * if your OAuth client has a hardcoded redirect URI the provider requires
   * you to match.
   */
  callbackPort?: number;
  /**
   * Path for the callback URL, used to build the `redirect_uri` the
   * authorization server redirects to. Defaults to `"/callback"`. Must begin
   * with `/` and contain no query string or fragment.
   */
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

/**
 * Config for the OAuth 2.0 Token Exchange grant (RFC 8693).
 *
 * Use to swap an existing credential (e.g. a platform-issued identity token,
 * a SAML assertion) for an access token from the configured provider. A
 * common use case is bootstrapping a CLI session from an upstream auth
 * system without prompting the user again.
 */
export type TokenExchangeConfig = BaseConfig & {
  /** Discriminator selecting this strategy. */
  strategy: "token-exchange";
  /** Value of the `subject_token` parameter sent to the token endpoint. */
  subjectToken: string;
  /**
   * Identifier of the `subject_token` type, typically a URI such as
   * `"urn:ietf:params:oauth:token-type:id_token"`.
   */
  subjectTokenType: string;
  /** Optional `actor_token` for delegation scenarios. */
  actorToken?: string;
  /** Identifier of the `actor_token` type. Required whenever `actorToken` is set. */
  actorTokenType?: string;
  /**
   * Client secret. Optional — public clients that identify themselves only
   * by `clientId` may omit it.
   */
  clientSecret?: string;
  /**
   * How client credentials are presented to the token endpoint when
   * `clientSecret` is set. Defaults to `"client_secret_post"`.
   */
  tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
};
