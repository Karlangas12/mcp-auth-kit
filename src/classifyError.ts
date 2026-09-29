import {
  InvalidClientError,
  InvalidGrantError,
  OAuthError,
  ServerError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
  UnauthorizedClientError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';

/**
 * Whether a failed OAuth HTTP call (registration, token exchange) is worth
 * retrying. A definitive rejection — bad client metadata, invalid client,
 * access denied — will fail again identically no matter how many times we
 * retry it, so retrying only wastes time and hammers the authorization
 * server. Only network failures (no `OAuthError` at all — DNS, connection
 * reset, our own timeout abort) and the authorization server's own signals
 * that the failure is transient (`server_error`, `temporarily_unavailable`,
 * `429`) are retried.
 */
export function isRetryableOAuthError(error: unknown): boolean {
  if (error instanceof OAuthError) {
    return (
      error instanceof ServerError ||
      error instanceof TemporarilyUnavailableError ||
      error instanceof TooManyRequestsError
    );
  }
  // Not a parsed OAuth error response at all: network error, abort/timeout,
  // or a non-OAuth-shaped 5xx — treat as transient.
  return true;
}

/**
 * Whether a request was aborted — either by mcp-auth-kit's own `timeoutMs`
 * or by an `AbortSignal` the caller supplied. Both surface as an error named
 * `AbortError` (a `DOMException` under a real `fetch`); `TimeoutError` is the
 * name `AbortSignal.timeout()` uses, included for completeness.
 */
export function isAbortError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    ((error as { name?: unknown }).name === 'AbortError' ||
      (error as { name?: unknown }).name === 'TimeoutError')
  );
}

/**
 * Retry policy for RFC 7591 dynamic client registration specifically.
 *
 * A6: registration is a NON-IDEMPOTENT POST. When mcp-auth-kit's own timeout
 * aborts it, the authorization server may already have created the client —
 * we simply never saw the response. Retrying then produces a second, distinct
 * client registration (each with its own `client_secret`), which is precisely
 * the duplicate-registration failure the retry classification exists to
 * avoid. An abort is therefore treated as definitive here: mcp-auth-kit
 * surfaces the timeout rather than risk registering twice.
 *
 * This is deliberately NOT applied to the refresh path, which has no retry
 * loop at all and whose (different, documented) timeout trade-off was settled
 * separately — see the `timeoutMs` option docs.
 */
export function isRetryableRegistrationError(error: unknown): boolean {
  if (isAbortError(error)) return false;
  return isRetryableOAuthError(error);
}

/**
 * Whether the SDK's own `auth()` orchestrator recognises this error type and
 * recovers from it by itself.
 *
 * `auth()` wraps `authInternal` in a catch that matches exactly three classes
 * (verified against the installed SDK, `client/auth.js`):
 *
 * ```js
 * if (error instanceof InvalidClientError || error instanceof UnauthorizedClientError) {
 *     await provider.invalidateCredentials?.('all');
 *     return await authInternal(provider, options);
 * } else if (error instanceof InvalidGrantError) {
 *     await provider.invalidateCredentials?.('tokens');
 *     return await authInternal(provider, options);
 * }
 * throw error;
 * ```
 *
 * The retry then finds no usable credentials and falls through to
 * `startAuthorization()` + `redirectToAuthorization()`, i.e. the user is sent
 * to re-authorize instead of being handed a hard failure.
 *
 * Because `auth()` calls `provider.tokens()` (this package's wrapper) BEFORE
 * reaching its own refresh logic, a refresh failure raised from inside
 * `tokens()` is what `auth()` sees. Wrapping these three classes in a
 * `McpAuthKitError` — which extends `Error`, not `OAuthError` — makes the
 * match fail and silently disables that recovery. So for these three, and
 * only these three, mcp-auth-kit rethrows the original error unwrapped.
 */
export function isSdkRecoverableOAuthError(error: unknown): boolean {
  return (
    error instanceof InvalidGrantError ||
    error instanceof InvalidClientError ||
    error instanceof UnauthorizedClientError
  );
}
