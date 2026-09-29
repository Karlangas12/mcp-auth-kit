/**
 * Strips ASCII control characters (including newlines/CR) from
 * server-supplied text before it is ever interpolated into an error message
 * or a `cause` chain. Without this, a malicious or misconfigured
 * authorization server can plant newline sequences in `error_description`
 * (or the `resource` we echo back) to forge log lines once the error is
 * logged.
 */
export function sanitizeForMessage(value: string, maxLength = 300): string {
  const controlCharPattern = new RegExp('[\\u0000-\\u001F\\u007F]+', 'g');
  const stripped = value.replace(controlCharPattern, ' ').trim();
  return stripped.length > maxLength ? `${stripped.slice(0, maxLength)}…` : stripped;
}

/**
 * Sanitizes a caught value for use as `McpAuthKitError.cause`, WITHOUT
 * discarding its concrete type. `error.message` (which, for the SDK's own
 * `OAuthError` subclasses, is exactly the authorization server's
 * `error_description`) is the one field that can carry untrusted,
 * attacker-controlled text — so only that field is rewritten in place. The
 * original error object (and its prototype chain) is returned unchanged
 * otherwise, so callers can still do `err.cause instanceof InvalidGrantError`
 * to distinguish "refresh token revoked, re-authorize" from "transient
 * failure, retry later".
 */
export function sanitizedCause(error: unknown): unknown {
  if (error instanceof Error) {
    try {
      error.message = sanitizeForMessage(error.message);
    } catch {
      // Some exotic error subclass might have a read-only `message` — leave
      // it as-is rather than losing the typed error entirely.
    }
    return error;
  }
  return new Error(sanitizeForMessage(String(error)));
}
