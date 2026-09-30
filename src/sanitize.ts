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
    // BAJO-1: `error_uri` is the other server-controlled string the SDK carries
    // on an OAuthError (`errorUri`, parsed from the token response as a free
    // `z.string()`, not a validated URL). It matters more now than it used to:
    // since recoverable OAuth errors are rethrown unwrapped, this object is the
    // one that surfaces at the top level rather than sitting inside `.cause`.
    const withUri = error as { errorUri?: unknown };
    if (typeof withUri.errorUri === 'string') {
      try {
        withUri.errorUri = sanitizeForMessage(withUri.errorUri);
      } catch {
        // Read-only on some subclass — same reasoning as `message` above.
      }
    }
    return error;
  }
  return new Error(sanitizeForMessage(String(error)));
}
