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
 * Wraps an arbitrary caught value as an `Error` whose message has been
 * sanitized, safe to use as `McpAuthKitError.cause` without leaking
 * unsanitized server-controlled text through the cause chain.
 */
export function sanitizedCause(error: unknown): Error {
  if (error instanceof Error) {
    const sanitized = new Error(sanitizeForMessage(error.message));
    sanitized.name = error.name;
    return sanitized;
  }
  return new Error(sanitizeForMessage(String(error)));
}
