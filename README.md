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

## Known limitation: expiry tracking is in-memory only

mcp-auth-kit tracks `expiresAt` in memory, on the wrapper instance. It does
**not** currently persist it, which means a process that restarts (the common
case for CLI-style MCP clients, like the ones behind the bugs this package
fixes) starts every fresh instance with no memory of when its stored token
actually expires. On cold start, mcp-auth-kit either refreshes proactively
(if a `refresh_token` is present — safe, but means a refresh on every process
start even when the access token was still perfectly valid) or falls back to
serving the stored token with no expiry awareness at all (if there's no
`refresh_token`). This is being tracked as an open design question — see
`company-architecture/decisions/ADR-010-...md` for the options under
consideration — rather than papered over with a quick fix.

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
