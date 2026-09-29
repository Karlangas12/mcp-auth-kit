/**
 * Replicates `@modelcontextprotocol/sdk`'s own issuer-comparison logic.
 *
 * The SDK has this behavior in `client/auth.js` as a private, non-exported
 * function (`issuersMatch`): it has no entry in `client/auth.d.ts`, is not
 * in the module's export list, and therefore cannot be imported — hence the
 * copy. Two issuer identifiers are compared as parsed URLs (so scheme
 * casing, default ports, and a stray trailing slash on either side don't
 * cause a false mismatch — e.g. the fallback authorization server URL the
 * SDK itself derives via `String(new URL('/', serverUrl))` when RFC 9728
 * discovery isn't available is always slash-suffixed), falling back to a
 * literal string comparison if either side isn't a valid URL.
 *
 * ---------------------------------------------------------------------------
 * THIS IS A FORK. RE-VERIFY ON EVERY `@modelcontextprotocol/sdk` BUMP.
 * ---------------------------------------------------------------------------
 * Verified equivalent against SDK **1.31.0** (`dist/esm/client/auth.js`).
 *
 * Note on how young the upstream original is: `issuersMatch`,
 * `discardIfIssuerMismatch` and the `issuer` field on `OAuthTokensSchema` do
 * not exist in ANY SDK release up to and including 1.30.1 — verified by
 * inspecting the published tarballs for 1.15.0, 1.20.0, 1.25.0, 1.28.0,
 * 1.29.0, 1.30.0 and 1.30.1. The whole issuer-binding mechanism landed in
 * 1.31.0, so at the time of writing this fork tracks code that has existed
 * upstream for exactly ONE release. Brand-new code of this kind is far more
 * likely to be reshaped than a long-stable helper, which makes the drift test
 * below load-bearing rather than defensive-just-in-case: it is the only thing
 * that will tell you the copy has gone stale.
 * `tests/issuer-match.test.ts` enforces this automatically: it extracts the
 * real `issuersMatch` source from the installed SDK at test time, executes
 * it, and differentially fuzzes it against this implementation. If upstream
 * changes the logic, that test fails — it is the only thing standing between
 * this copy and a silent divergence, so do not weaken or skip it.
 *
 * Note one deliberate structural difference: the SDK assigns via destructuring
 * (`[x, y] = [new URL(a).href, new URL(b).href]`, atomic — if the second
 * `new URL` throws, neither side is assigned), whereas this assigns
 * sequentially (leaving `x` normalized and `y` raw in that case). That mixed
 * state is unobservable: flipping a result would require an unparseable `b`
 * equal to a normalized `href` modulo one trailing slash, and any string
 * equal to a normalized `href` is itself parseable. The differential fuzz in
 * the test above covers this; don't "simplify" this function without it.
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
