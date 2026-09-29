# mcp-auth-kit

A drop-in wrapper for `@modelcontextprotocol/sdk`'s `OAuthClientProvider` that
fixes four OAuth token-lifecycle bugs currently open, unresolved, and older
than 30 days across **six independent MCP client codebases** (verified
2026-09-29):

| # | Bug | Real, open issue |
|---|-----|-------------------|
| a | Token expires silently — no `refresh_token`/`expires_in` handling | [anthropics/claude-code#26281](https://github.com/anthropics/claude-code/issues/26281) |
| b | "Dynamic client registration not supported" — no retry on transient failure | [openai/codex#13200](https://github.com/openai/codex/issues/13200) |
| c | Trailing slash on the `resource` param breaks auth with Microsoft Entra ID | [anthropics/claude-code#52871](https://github.com/anthropics/claude-code/issues/52871) |
| d | Client has a valid `refresh_token` but never uses it to renew MCP OAuth tokens | [openai/codex#17265](https://github.com/openai/codex/issues/17265) |

(The same class of bug — MCP client OAuth token lifecycle — has also been
reported against `anthropics/claude-ai-mcp`, `supabase/supabase`,
`lmstudio-ai/lmstudio-bug-tracker`, and `RooCodeInc/Roo-Code`.)

If you're searching for **"MCP OAuth trailing slash"**, **"mcp dynamic client
registration retry"**, **"MCP token expires_in missing"**, or **"MCP client
refresh_token not used"** — this package exists because of exactly those
bugs, reproduced as unit tests in [`tests/`](./tests).

## What it does

`wrapOAuthClientProvider` wraps any object implementing the SDK's
[`OAuthClientProvider`](https://github.com/modelcontextprotocol/typescript-sdk)
interface and returns another one — same interface, same call sites — with:

1. **Proactive refresh with a TTL fallback.** If the authorization server's
   token response omits `expires_in`, mcp-auth-kit still tracks an expiry
   using a configurable fallback TTL, instead of holding onto a token that
   silently goes stale. A server-supplied `expires_in` is clamped to a sane
   range (configurable `minExpiresInSeconds`/`maxExpiresInSeconds`) before
   it's trusted.
2. **Real refresh-token usage, bound to the right issuer.** Once the access
   token is due to expire, mcp-auth-kit calls the `refresh_token` grant
   automatically — it doesn't just store the refresh token and never touch
   it, and it re-stamps the `issuer` on every token/client-information it
   saves (the token endpoint response never includes one — it's a
   client-side-only field). Before sending it, mcp-auth-kit checks the
   stored client/token `issuer` (when stamped) against the configured
   `authorizationServerUrl` — using the same trailing-slash-tolerant
   comparison the SDK itself uses for this, not raw string equality — and
   refuses to refresh on a mismatch, so a refresh token and client
   credentials are never sent to the wrong authorization server. Concurrent
   `tokens()` calls during expiry share a single in-flight refresh request,
   and every HTTP call mcp-auth-kit makes is bounded by a configurable
   timeout (`timeoutMs`, default 30s) so a hung authorization server can't
   block the client forever.
   >
   > **Known limitation:** the refresh call is a non-idempotent POST. If the
   > authorization server actually completes the refresh (and rotates the
   > refresh token) but the response doesn't arrive before `timeoutMs`
   > elapses, mcp-auth-kit aborts having never seen the new refresh token.
   > The next refresh attempt then fails (the old refresh token is already
   > invalidated server-side) and forces a full re-login. This is not
   > retried — retrying a possibly-already-applied mutation would reopen the
   > double-registration risk the registration-retry classification below
   > exists to avoid. If your authorization server is known to be slow,
   > raise `timeoutMs`.
3. **Retried dynamic client registration — only when it's worth retrying.**
   If the wrapped provider has no stored client information and you opt in
   via the `registration` option, mcp-auth-kit performs RFC 7591 dynamic
   client registration itself, with exponential backoff and jitter — but
   only for transient failures (network errors, `server_error`,
   `temporarily_unavailable`, `429`). A definitive rejection like
   `invalid_client_metadata` fails immediately instead of retrying a request
   that will never succeed. Registration is refused outright, at wrap time,
   if the wrapped provider has no `saveClientInformation` to persist the
   result into.
4. **Normalized `resource` indicator — for the one call mcp-auth-kit actually
   controls.** `options.resource` is stripped of a spurious trailing slash
   before mcp-auth-kit's own refresh call sends it. This does **not** cover
   every path a trailing slash could enter through — see [Resource
   normalization: what this does and doesn't cover](#resource-normalization-what-this-does-and-doesnt-cover)
   below, it matters and the honest scope is narrower than "fixes the
   trailing-slash bug everywhere."
5. **Typed, actionable errors — never silent failure.** Every failure mode
   above throws `McpAuthKitError` with a `phase` (`token_refresh`,
   `client_registration`, `resource_validation`, `authorization`) and a
   concrete remediation string, instead of a bare "unauthorized." The
   underlying error is preserved as `.cause` with its real type intact — you
   can still do `err.cause instanceof InvalidGrantError` to tell "refresh
   token revoked, re-authorize" apart from "transient failure, retry later" —
   only its `.message` (the one field that can carry the authorization
   server's own untrusted `error_description`) is stripped of control
   characters, so a malicious authorization server can't forge log lines
   through it.

## Install

```bash
npm install mcp-auth-kit @modelcontextprotocol/sdk
```

(Not yet published — see [Status](#status) below.)

### Supported `@modelcontextprotocol/sdk` versions

**`^1.31.0`.** That floor is deliberate and narrower than it may look — it is
the version the test suite actually runs against, and the package genuinely
cannot work below it:

**The binding reason is the issuer-binding mechanism.** `issuersMatch`,
`discardIfIssuerMismatch` and the `issuer` field on `OAuthTokensSchema` /
`OAuthClientInformationSchema` **do not exist in any SDK release up to and
including 1.30.1** — verified by inspecting the published tarballs for 1.15.0,
1.20.0, 1.25.0, 1.28.0, 1.29.0, 1.30.0 and 1.30.1. They landed in 1.31.0.

Three of this package's core security behaviours are built directly on that
field and would become **silent no-ops** below 1.31.0:

- the issuer-binding check that refuses to send a `refresh_token` or client
  credentials to an authorization server other than the one that issued them
  (it reads `tokens.issuer` / `clientInformation.issuer`);
- the re-stamping of `issuer` on every refresh, without which the check above
  disables itself the first time mcp-auth-kit refreshes;
- the trailing-slash-tolerant issuer comparison, which mirrors the SDK's own
  `issuersMatch`.

"Silently degrades to a no-op" is the worst possible failure mode for a
security check, which is why the floor is a hard `^1.31.0` rather than a
best-effort range.

For completeness, two things that are **not** the reason, despite an earlier
version of this README claiming otherwise:

- The subpath export `@modelcontextprotocol/sdk/server/auth/errors.js` resolves
  through the `"./*"` wildcard in the SDK's export map — but that wildcard has
  been present since at least 1.15.0, so it constrains nothing here.
- Of the recent optional `OAuthClientProvider` members the conditional
  delegation forwards, `prepareTokenRequest` arrived by 1.25.0 and
  `discoveryState` by 1.28.0 — both below the floor, so neither sets it either.

An earlier release declared `>=1.0.0`, which was a compatibility claim nobody
had verified and which the evidence above shows was false by roughly thirty
minor versions. `tests/package-manifest.test.ts` pins this down: it fails if
the declared peer floor drops below the verified one, if the dev dependency
drifts below the peer floor, or if the features the floor exists for stop being
present in the installed SDK. If you re-verify against a different SDK version,
update the range, the `VERIFIED_FLOOR` constant in that test, and the version
noted in `src/issuerMatch.ts` together.

## Usage

```ts
import { wrapOAuthClientProvider } from 'mcp-auth-kit';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

// `myProvider` is whatever OAuthClientProvider you already have —
// in-memory, filesystem-backed, keychain-backed, etc.
const authProvider = wrapOAuthClientProvider(myProvider, {
  authorizationServerUrl: 'https://auth.example.com',
  resource: 'https://mcp.example.com/mcp', // no trailing slash needed — normalized either way
  fallbackTokenTtlMs: 55 * 60 * 1000, // used only when the server omits expires_in
  registration: { maxAttempts: 5, baseDelayMs: 250 }, // opt in to retried DCR
});

const transport = new StreamableHTTPClientTransport(new URL('https://mcp.example.com/mcp'), {
  authProvider,
});
```

`wrapOAuthClientProvider` returns a standard `OAuthClientProvider` — pass it
anywhere the unwrapped provider was accepted.

## Design note: conditional delegation

The wrapper only defines an **optional** `OAuthClientProvider` member
(`state`, `validateResourceURL`, `saveClientInformation`,
`invalidateCredentials`, `prepareTokenRequest`, `saveDiscoveryState`,
`discoveryState`, `addClientAuthentication`, `clientMetadataUrl`) if the
wrapped provider itself defines it. This isn't a style choice — the SDK's own
`auth()` orchestrator uses *presence* of these methods as feature detection
(`provider.validateResourceURL ? ... : ...`, `provider.state ? ... :
undefined`, `provider.saveClientInformation !== undefined`, etc.). Defining
all of them unconditionally — which an earlier version of this package did —
means:

- `validateResourceURL` always being present skips the SDK's own
  `checkResourceAllowed` audience check entirely, which is exactly the kind
  of check that stops a malicious/misconfigured MCP server from getting a
  token minted for a resource it doesn't own (a confused-deputy vector).
- `state` always being present makes `auth()` call it unconditionally, which
  throws for the (common) case of a wrapped provider that doesn't implement
  the optional `state()` method — breaking the authorization flow outright.
- `saveClientInformation` always being present (even as a `?.()` no-op over
  an inner provider that has none) defeats the SDK's own guard against
  starting dynamic registration when the result can't be persisted, causing
  re-registration on every single call.

So: mcp-auth-kit only ever *narrows* behavior your provider already has
(pre-normalizing a resource string, retrying a registration call), never
*widens* it by pretending to support something it doesn't.

### A related, deliberate consequence: issuer mismatch causes re-registration

When mcp-auth-kit performs dynamic client registration itself (the
`registration` option), it stamps the result with the **configured**
`authorizationServerUrl`, exactly as the SDK's own `auth()` stamps what it
registers. If that configured value genuinely differs from the authorization
server `auth()` discovers via RFC 9728 — beyond the trailing-slash, scheme-case
and default-port tolerance the issuer comparison already applies — then
`auth()`'s own `discardIfIssuerMismatch` will discard mcp-auth-kit's
registration and register again itself.

That is intended, not a bug to suppress. Reusing a client registration bound to
one authorization server against a different one is the failure actually worth
preventing; a duplicate registration is the visible, recoverable symptom of a
configuration mismatch that a caller needs to fix. If you see duplicate client
registrations, the thing to correct is the `authorizationServerUrl` you passed,
not this behavior.

## Resource normalization: what this does and doesn't cover

`normalizeResourceIndicator()` strips a trailing slash from a `resource`
string. mcp-auth-kit applies it in exactly **one** place: `options.resource`,
before mcp-auth-kit's own `refreshAuthorization()` call sends it. That's the
only `resource` value mcp-auth-kit fully owns end to end.

It does **not** cover the `resource` the SDK's own `auth()` orchestrator
sends during discovery/authorization-code exchange, and here's why that's
correct, not an oversight — verified against `client/auth.js`:

- When the wrapped provider has **no** `validateResourceURL` of its own (the
  common case), `auth()` already sends the protected-resource metadata's
  `resource` string verbatim — `resourceMetadata.resource`, never
  `.href`-round-tripped (`auth.js:266`, the SDK's own fix for
  [modelcontextprotocol/typescript-sdk#1968](https://github.com/modelcontextprotocol/typescript-sdk)).
  There is no trailing slash for mcp-auth-kit to strip here; the SDK never
  introduces one in this path.
- When the wrapped provider **does** implement `validateResourceURL`,
  mcp-auth-kit pre-normalizes the string it passes into that call (see the
  design note above) — but that provider returns a `URL` object, and
  `auth()` then calls `.href` on it (`resourceIndicatorToString`,
  `auth.js:773-775`), which re-adds the trailing slash for a pathless
  origin regardless of what string went in. mcp-auth-kit cannot fix this
  without either reimplementing `auth()`'s resource-selection logic itself
  (a much larger scope than a token-provider wrapper) or overriding
  `validateResourceURL` on the wrapped provider's behalf — which is exactly
  what an earlier version of this package did, and exactly what reopened the
  confused-deputy vector described in the design note above (a provider's
  own `validateResourceURL` is the thing doing real audience validation;
  papering over its return value to fix formatting would mean either
  bypassing that validation or silently rewriting its result). This case is
  the wrapped provider's own responsibility, not mcp-auth-kit's.

So the trailing-slash fix (bug **c** in the table) is fully covered for
mcp-auth-kit's own refresh calls, and for the SDK's default (no
`validateResourceURL`) path — which is what most `OAuthClientProvider`
implementations look like. If your provider implements
`validateResourceURL` itself, normalizing what it returns is on it.

## Also exported

- `normalizeResourceIndicator(resource: string): string` — the trailing-slash
  fix as a standalone utility, if you just need that piece.
- `withExponentialBackoff(fn, options)` — the generic retry helper behind the
  registration fix, with pluggable `shouldRetry`/jitter.
- `isRetryableOAuthError(error)` — classifies a caught error as transient
  (network failure, `server_error`, `temporarily_unavailable`, `429`) or
  definitive (`invalid_client_metadata`, `unauthorized_client`, etc.).
- `withTimeout(fetchFn, timeoutMs)` — wraps a `fetch`-like function so every
  call aborts after `timeoutMs`. Combines with (never overrides) an
  `AbortSignal` the caller already passed in `init.signal`.
- `sanitizeForMessage(value)` — strips control characters/newlines from
  untrusted text before it's used in a log line or error message.
- `McpAuthKitError` — the typed error class, with `.phase` and `.remediation`.
- `ExpiryStore` (type) — the interface for the optional expiry-persistence
  adapter described below.
- `isRetryableRegistrationError(error)` — the registration-specific retry
  policy: like `isRetryableOAuthError`, but treats an aborted (timed-out or
  caller-cancelled) request as definitive, because RFC 7591 registration is a
  non-idempotent POST and retrying one the server may already have applied
  creates a duplicate client.

### Two options worth knowing about

- **`onWarning`** — mcp-auth-kit emits exactly one kind of warning (an
  `expiryStore` returning a non-finite value, which it then treats as
  "unknown" rather than silently trusting). It goes to `console.warn` by
  default; pass `onWarning` to route it into your own logger, or a no-op to
  silence it. Nothing else in the package writes to the console.
- **`refreshFailureCacheMs`** (default 30000) — after a refresh fails with a
  *definitive* error (`invalid_grant`: the refresh token is revoked or
  expired), further refresh attempts are short-circuited for this long
  instead of firing another doomed request on every `tokens()` call.
  Transient failures — network errors, `server_error`, `429`, and
  mcp-auth-kit's own timeout — are never cached, since those may well
  succeed on the next attempt. The window is cleared by a successful
  `saveTokens()` or by `invalidateCredentials()`.

## Expiry persistence

mcp-auth-kit tracks `expiresAt` on the wrapper instance. By default that's
**in memory only** — a process restart (the common case for CLI-style MCP
clients, like the ones behind the bugs table above) starts a fresh instance
with no memory of when its already-stored token actually expires. There are
two modes:

### Default: no `expiryStore` configured

On a cold-loaded token (`expiresAt` unknown to this instance), mcp-auth-kit
does **not** guess and does **not** force a proactive refresh. It returns the
stored token exactly as the wrapped provider's own `tokens()` returned it —
whether or not that token has actually expired.

This is a deliberate default, not an oversight, based on verifying how the
SDK itself behaves on a 401 (`@modelcontextprotocol/sdk`, checked against the
installed version in `node_modules`):

- Both stock client transports react to an HTTP 401 by calling `auth()`
  again: `StreamableHTTPClientTransport` in
  `dist/esm/client/streamableHttp.js` (`_startOrAuthSse`, line 97, and
  `send`, line 315), and `SSEClientTransport` in `dist/esm/client/sse.js`
  (the `EventSource.onerror` handler, line 89, and `send`, line 176).
- `auth()` itself, in `dist/esm/client/auth.js`, does **not** go straight to
  a brand-new interactive login when reactively re-invoked. It first calls
  `provider.tokens()` (line 341) and, if a `refresh_token` is present,
  attempts a **silent** `refreshAuthorization()` grant (lines 349–362) —
  only falling back to `startAuthorization()` +
  `provider.redirectToAuthorization()` (lines 375–387, forcing a new
  interactive login) if there's no `refresh_token`, or the refresh itself
  fails with a definitive `OAuthError` other than `ServerError` (lines
  364–373).

So for any client built on those two transports, a token that's actually
expired self-heals on the very next request — one failed round trip, then a
silent refresh, with **no interactive re-login** — even with mcp-auth-kit
never forcing a refresh at startup "just in case." Forcing one anyway would
mean burning a refresh-token rotation (and an extra request to the
authorization server) on every single process start, on the mere suspicion
that it might be needed. A client with its own hand-rolled transport that
does *not* replicate this 401-retry logic — which is exactly the shape of
several of the bugs in the table above — won't get this safety net, cold
start or not; that's a gap in that transport, not something a token-provider
wrapper can fix from the outside.

### With `expiryStore` configured

Pass an `ExpiryStore` — two methods, owned by mcp-auth-kit, not part of
`OAuthClientProvider` — to persist `expiresAt` across restarts:

```ts
import type { ExpiryStore } from 'mcp-auth-kit';

const expiryStore: ExpiryStore = {
  async get(resourceKey) {
    /* read a persisted ms-since-epoch timestamp for resourceKey, e.g. from a file */
  },
  async set(resourceKey, expiresAtMs) {
    /* persist it */
  },
};

const authProvider = wrapOAuthClientProvider(myProvider, {
  authorizationServerUrl: 'https://auth.example.com',
  resource: 'https://mcp.example.com/mcp',
  expiryStore,
  // resourceKey defaults to `${authorizationServerUrl}::${resource}` (or
  // just authorizationServerUrl if no resource is configured) — override if
  // you need a different scheme. The default exists so that two different
  // protected resources sitting behind the same authorization server don't
  // share (and clobber) one expiry entry.
});
```

With this configured, mcp-auth-kit persists `expiresAt` on every
`saveTokens()` and consults the store before deciding whether a freshly
loaded token needs a proactive refresh — so it can now decide correctly, with
real knowledge, on a cold start.

A few things mcp-auth-kit does to keep this store from becoming its own
liability:

- **A failing `get()` degrades gracefully** to the no-adapter default rather
  than blocking `tokens()`.
- **A non-finite value from `get()`** (`NaN`, `Infinity` — whether from a
  corrupted store or a hostile one) is never trusted. It's treated exactly
  like "unknown" (same as no store at all), and mcp-auth-kit `console.warn`s
  about it once per process rather than either crashing or silently
  disabling proactive refresh forever.
- **A value that's technically finite but implausible** — implying the token
  is valid for centuries, say — is capped at `maxExpiresInSeconds` from now.
  Only the *upper* bound applies on this path. `minExpiresInSeconds` is
  deliberately **not** applied to a stored timestamp: that bound exists to
  reject a malformed `expires_in` *duration* (`0` or negative) coming
  straight off the wire, whereas a stored timestamp in the past is not
  malformed at all — it is the store correctly reporting that the token has
  already expired, and `expiresAt = 0` is specifically the revocation
  sentinel below. Raising those forward would manufacture validity that
  doesn't exist and silently defeat the sentinel.
- **A failing `set()`** (during `saveTokens()`) never fails the save itself —
  the wrapped provider's own `saveTokens()` already succeeded by that point;
  a supplementary expiry cache failing to write degrades to in-memory-only
  tracking for the rest of the process instead of turning a successful save
  into a thrown error.
- **`invalidateCredentials('all' | 'tokens')`** removes the persisted entry
  via `expiryStore.delete()` if the store implements it, or overwrites it
  with a sentinel (`expiresAt = 0`, i.e. "already expired") if it doesn't —
  either way, a revoked credential doesn't leave a stale, still-valid-looking
  expiry behind.

None of the above changes *where* credentials get sent — the store only ever
influences *when* mcp-auth-kit decides to refresh, never *who* it refreshes
against (that's what the issuer check above is for). A store an attacker can
write to can, at worst, make refresh happen too early or too late; it cannot
redirect a refresh_token or client_secret anywhere.

### Which to use

The no-adapter default is right for anything built on
`StreamableHTTPClientTransport`/`SSEClientTransport` (or a transport that
faithfully replicates their reactive-401 behavior) — you get self-healing for
free and mcp-auth-kit stays out of the way. Configure `expiryStore` when you
either can't rely on that (a custom transport, or one you can't verify
implements the retry) or want to avoid the one-request latency hit of the
reactive path on every cold start.

## Tests

Each bug above has a unit test that first demonstrates the failure against a
bare (unwrapped) provider, then proves mcp-auth-kit fixes it against a
mocked authorization server. `tests/auth-integration.test.ts` additionally
drives the SDK's real `auth()` orchestrator end to end against the wrapper,
to catch regressions (like the confused-deputy issue above) that only show up
through the SDK's own feature-detection control flow, not through calling
wrapper methods directly:

```bash
npm test
```

## Status

MVP. Standalone package, zero dependency on any other product — works with
any `@modelcontextprotocol/sdk` client, whether or not you use anything else
from this author. Not yet published to npm or made public; that's a decision
still pending.

## License

MIT
