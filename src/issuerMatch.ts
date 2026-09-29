/**
 * Replicates `@modelcontextprotocol/sdk`'s own issuer-comparison logic
 * exactly. The SDK has this behavior in `client/auth.js` as a private,
 * non-exported function (`issuersMatch`) — verified against the installed
 * package: it has no entry in `client/auth.d.ts` and cannot be imported.
 * Two issuer identifiers are compared as parsed URLs (so scheme casing,
 * default ports, and a stray trailing slash on either side don't cause a
 * false mismatch — e.g. the fallback authorization server URL the SDK
 * itself derives via `String(new URL('/', serverUrl))` when RFC 9728
 * discovery isn't available is always slash-suffixed), falling back to a
 * literal string comparison if either side isn't a valid URL.
 */
export function issuersMatch(a: string, b: string): boolean {
  let x = a;
  let y = b;
  try {
    x = new URL(a).href;
    y = new URL(b).href;
  } catch {
    // Not two URLs: compared as written.
  }
  return x === y || (x.endsWith('/') && x.slice(0, -1) === y) || (y.endsWith('/') && y.slice(0, -1) === x);
}
