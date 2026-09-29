import {
  OAuthError,
  ServerError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
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
