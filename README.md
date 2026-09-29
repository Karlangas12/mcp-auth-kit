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
   silently goes stale.
2. **Real refresh-token usage.** Once the access token is due to expire (per
   `expires_in` or the fallback), mcp-auth-kit calls the `refresh_token`
   grant automatically — it doesn't just store the refresh token and never
   touch it. Concurrent calls to `tokens()` during expiry share a single
   in-flight refresh request.
3. **Retried dynamic client registration.** If the wrapped provider has no
   stored client information and you opt in via the `registration` option,
   mcp-auth-kit performs RFC 7591 dynamic client registration itself, with
   exponential backoff, instead of leaving a single unretried attempt to fail
   on the first transient error.
4. **Normalized `resource` indicators.** `resource` values are stripped of a
   spurious trailing slash before being sent, so authorization servers that
   reject or misroute a trailing-slash resource (Entra ID) still work.
5. **Typed, actionable errors — never silent failure.** Every failure mode
   above throws `McpAuthKitError` with a `phase` (`token_refresh`,
   `client_registration`, `resource_validation`, `authorization`) and a
   concrete remediation string, instead of a bare "unauthorized."

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

## Also exported

- `normalizeResourceIndicator(resource: string): string` — the trailing-slash
  fix as a standalone utility, if you just need that piece.
- `withExponentialBackoff(fn, options)` — the generic retry helper behind the
  registration fix.
- `McpAuthKitError` — the typed error class, with `.phase` and `.remediation`.

## Tests

Each bug above has a unit test that first demonstrates the failure against a
bare (unwrapped) provider, then proves mcp-auth-kit fixes it against a
mocked authorization server:

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
