/**
 * Discriminator identifying what went wrong in a {@link CliAuthError}.
 *
 * Codes are grouped by origin so consumers can branch on the prefix:
 *
 *  - `config.*` — library-level misuse detected at construction time.
 *  - `callback.*` — local integrity check on the authorization-code
 *    callback URL failed (e.g. CSRF / tampered link).
 *  - `provider.*` — the authorization server returned a formal error
 *    response per RFC 6749 §5.2 (either at the authorization endpoint, the
 *    token endpoint, or the device code polling endpoint).
 *  - `request.*` — a request to the authorization server failed at the
 *    HTTP layer without a standard OAuth error body (network failure,
 *    5xx, malformed response, etc.).
 *  - `token.*` — no token is available locally and none can be obtained.
 *  - `device_code.*` — the device-code grant failed for a reason local
 *    to the client (e.g. polling deadline reached).
 */
export type CliAuthErrorCode =
  | "config.invalid"
  | "callback.state_mismatch"
  | "callback.missing_code"
  | "provider.rejected"
  | "request.failed"
  | "token.unavailable"
  | "token.refresh_failed"
  | "device_code.expired";

/**
 * The only error class thrown by this library. Use `error.code` to branch on
 * the failure mode, and `error.data` for the structured diagnostic payload
 * associated with that code.
 *
 * Expected `data` shapes per code:
 *
 *  - `config.invalid` → `{ field: string }`
 *  - `callback.state_mismatch` / `callback.missing_code` → `undefined`
 *  - `provider.rejected` →
 *      `{ endpoint: "authorization" | "token"; error: string;
 *         errorDescription?: string }`
 *  - `request.failed` →
 *      `{ endpoint: "token" | "device_authorization" | "revocation";
 *         status: number }`
 *  - `token.unavailable` / `token.refresh_failed` → `undefined`
 *  - `device_code.expired` → `undefined`
 *
 * @example Handle user-denied consent specifically
 * ```ts
 * try {
 *   await auth.login({ onAuthorization: (url) => console.log(url) });
 * } catch (error) {
 *   if (
 *     error instanceof CliAuthError &&
 *     error.code === "provider.rejected" &&
 *     (error.data as { error: string }).error === "access_denied"
 *   ) {
 *     console.log("You declined. Exiting.");
 *     process.exit(0);
 *   }
 *   throw error;
 * }
 * ```
 */
export class CliAuthError extends Error {
  override name = "CliAuthError";

  constructor(
    /** Machine-readable failure identifier. See {@link CliAuthErrorCode}. */
    public readonly code: CliAuthErrorCode,
    /**
     * Human-readable message. Defaults to `code` when omitted. Messages are
     * not a stable contract — prefer branching on `code` and `data`.
     */
    message?: string,
    /**
     * Structured diagnostic data. The shape depends on `code`; see the class
     * docs above for the per-code mapping.
     */
    public readonly data?: unknown
  ) {
    super(message ?? code);
  }
}
