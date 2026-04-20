/**
 * Structured diagnostic payload associated with each
 * {@link CliAuthErrorCode}. Keys are codes; values are the exact shape of
 * `error.data` when that code is thrown. Codes whose value is `undefined`
 * carry no payload.
 *
 * Consumers do not usually reference this map directly — narrowing on
 * `error.code` propagates the correct `error.data` type automatically (see
 * {@link CliAuthError}).
 */
export type CliAuthErrorData = {
  "config.invalid": { field: string };
  "callback.state_mismatch": undefined;
  "callback.missing_code": undefined;
  "provider.rejected": {
    endpoint: "authorization" | "token" | "device_authorization";
    error: string;
    errorDescription?: string;
  };
  "request.failed": {
    endpoint: "token" | "device_authorization" | "revocation";
    status: number;
  };
  "token.unavailable": undefined;
  "token.refresh_failed": undefined;
  "device_code.expired": undefined;
};

/**
 * Discriminator identifying what went wrong in a {@link CliAuthError}.
 *
 * Codes are grouped by origin so consumers can branch on the prefix:
 *
 *  - `config.*` — library-level misuse detected at construction time.
 *  - `callback.*` — local integrity check on the authorization-code
 *    callback URL failed (e.g. CSRF / tampered link).
 *  - `provider.*` — the authorization server returned a formal error
 *    response per RFC 6749 §5.2 (authorization endpoint, token endpoint,
 *    or device authorization endpoint).
 *  - `request.*` — a request to the authorization server failed at the
 *    HTTP layer without a standard OAuth error body (network failure,
 *    5xx, malformed response, etc.).
 *  - `token.*` — no token is available locally and none can be obtained.
 *  - `device_code.*` — the device-code grant failed for a reason local
 *    to the client (e.g. polling deadline reached).
 */
export type CliAuthErrorCode = keyof CliAuthErrorData;

// Discriminated-union view over {code, data} used to intersect with the
// class below, so `if (err.code === X)` narrows `err.data` automatically.
type CliAuthErrorShape = {
  [K in CliAuthErrorCode]: { readonly code: K; readonly data: CliAuthErrorData[K] };
}[CliAuthErrorCode];

class CliAuthErrorBase extends Error {
  override name = "CliAuthError";

  constructor(
    public readonly code: CliAuthErrorCode,
    message?: string,
    public readonly data?: unknown
  ) {
    super(message ?? code);
  }
}

/**
 * The only error class thrown by this library. Use `error.code` to branch on
 * the failure mode; `error.data` is automatically narrowed to the matching
 * payload shape inside the branch (no `as` cast required).
 *
 * @example Handle user-denied consent specifically
 * ```ts
 * try {
 *   await auth.login({ onAuthorization: (url) => console.log(url) });
 * } catch (error) {
 *   if (
 *     error instanceof CliAuthError &&
 *     error.code === "provider.rejected" &&
 *     error.data.error === "access_denied"
 *   ) {
 *     console.log("You declined. Exiting.");
 *     process.exit(0);
 *   }
 *   throw error;
 * }
 * ```
 *
 * @example Distinguish protocol error from transport failure
 * ```ts
 * catch (error) {
 *   if (!(error instanceof CliAuthError)) throw error;
 *   switch (error.code) {
 *     case "provider.rejected":
 *       // error.data: { endpoint, error, errorDescription? }
 *       console.error(`Server rejected: ${error.data.error}`);
 *       break;
 *     case "request.failed":
 *       // error.data: { endpoint, status }
 *       console.error(`Network/5xx on ${error.data.endpoint}`);
 *       break;
 *   }
 * }
 * ```
 */
export type CliAuthError = CliAuthErrorBase & CliAuthErrorShape;

// Conditional rest tuple: codes with `data: undefined` accept an optional
// message only; codes with structured data require both message and data.
type CliAuthErrorArgs<C extends CliAuthErrorCode> = CliAuthErrorData[C] extends undefined
  ? [message?: string]
  : [message: string | undefined, data: CliAuthErrorData[C]];

type CliAuthErrorConstructor = {
  new <C extends CliAuthErrorCode>(code: C, ...args: CliAuthErrorArgs<C>): CliAuthError;
  readonly prototype: CliAuthError;
};

export const CliAuthError = CliAuthErrorBase as unknown as CliAuthErrorConstructor;
