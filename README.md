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
   it. Before sending it, mcp-auth-kit checks the stored client/token
   `issuer` (when stamped) against the configured `authorizationServerUrl`
   and refuses to refresh on a mismatch, so a refresh token and client
   credentials are never sent to the wrong authorization server. Concurrent
   `tokens()` calls during expiry share a single in-flight refresh request,
   and every HTTP call mcp-auth-kit makes is bounded by a timeout so a hung
   authorization server can't block the client forever.
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
4. **Normalized `resource` indicators — without inventing validation.**
   `resource` values are stripped of a spurious trailing slash before being
   sent. mcp-auth-kit never defines `validateResourceURL` on your behalf: if
   the wrapped provider already implements it, mcp-auth-kit only
   pre-normalizes the trailing slash before delegating to it; if it doesn't,
   mcp-auth-kit leaves the member undefined so the SDK's own
   `checkResourceAllowed` audience check still runs. (See
   [Design note](#design-note-conditional-delegation) below — this one
   matters.)
5. **Typed, actionable errors — never silent failure.** Every failure mode
   above throws `McpAuthKitError` with a `phase` (`token_refresh`,
   `client_registration`, `resource_validation`, `authorization`) and a
   concrete remediation string, instead of a bare "unauthorized." Any
   server-controlled text (e.g. `error_description`) is stripped of control
   characters before it's interpolated into a message or `cause`, so a
   malicious authorization server can't forge log lines through it.

## Install

```bash
npm install mcp-auth-kit @modelcontextprotocol/sdk
```

(Not yet published — see [Status](#status) below.)

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

## Also exported

- `normalizeResourceIndicator(resource: string): string` — the trailing-slash
  fix as a standalone utility, if you just need that piece.
- `withExponentialBackoff(fn, options)` — the generic retry helper behind the
  registration fix, with pluggable `shouldRetry`/jitter.
- `isRetryableOAuthError(error)` — classifies a caught error as transient
  (network failure, `server_error`, `temporarily_unavailable`, `429`) or
  definitive (`invalid_client_metadata`, `unauthorized_client`, etc.).
- `withTimeout(fetchFn, timeoutMs)` — wraps a `fetch`-like function so every
  call aborts after `timeoutMs`.
- `sanitizeForMessage(value)` — strips control characters/newlines from
  untrusted text before it's used in a log line or error message.
- `McpAuthKitError` — the typed error class, with `.phase` and `.remediation`.
- `ExpiryStore` (type) — the interface for the optional expiry-persistence
  adapter described below.

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
  expiryStore,
  // resourceKey defaults to String(authorizationServerUrl); override if one
  // store instance needs to track more than one MCP server/session.
});
```

With this configured, mcp-auth-kit persists `expiresAt` on every
`saveTokens()` and consults the store before deciding whether a freshly
loaded token needs a proactive refresh — so it can now decide correctly, with
real knowledge, on a cold start. A failing `get()` degrades gracefully to the
no-adapter default rather than blocking `tokens()`.

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
