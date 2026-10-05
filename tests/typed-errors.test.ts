import { describe, expect, it } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, createMockAuthServer, testClientMetadata } from './helpers.js';

const mcpServerUrl = 'https://mcp.example.com';
const authorizationServerUrl = 'https://auth.example.com';

// ---------------------------------------------------------------------------
// MEDIO-3. This file used to pin the OPPOSITE behaviour: an expired access
// token with no refresh_token made `tokens()` throw a typed McpAuthKitError,
// and that was asserted as the desired "typed, actionable error instead of
// silent failure".
//
// It was backwards, and the test is why eleven review rounds did not notice.
// `auth()` calls `provider.tokens()` BEFORE its own refresh logic
// (SDK auth.js:341), and McpAuthKitError is deliberately not one of the three
// classes auth() recovers from — so the throw aborted the entire auth() run
// and the re-authorization redirect an UNWRAPPED provider gets in exactly this
// situation never happened. Worse, StreamableHTTPClientTransport's
// `_commonHeaders` awaits `tokens()` with no catch, so every request rejected
// and even the reactive 401 path that would have re-run auth() never ran.
//
// An expired token with no refresh_token is not a failure this wrapper can
// improve on. It is the ordinary "time to re-authorize" state, which the SDK
// already handles by redirecting.
// ---------------------------------------------------------------------------

async function seedExpiredWithoutRefreshToken(
  provider: ReturnType<typeof wrapOAuthClientProvider>,
) {
  await provider.saveTokens({
    access_token: 'no-refresh',
    token_type: 'Bearer',
    // deliberately no refresh_token
  });
  await new Promise((resolve) => setTimeout(resolve, 5));
}

describe('MEDIO-3: an expired token with no refresh_token leaves re-authorization to the SDK', () => {
  it('returns the stored token instead of throwing', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fallbackTokenTtlMs: 1,
      onWarning: () => {},
    });
    await seedExpiredWithoutRefreshToken(wrapped);

    const tokens = await wrapped.tokens();
    expect(tokens?.access_token).toBe('no-refresh');
  });

  it('warns once, so the condition is visible without being fatal', async () => {
    const warnings: string[] = [];
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fallbackTokenTtlMs: 1,
      onWarning: (m: string) => warnings.push(m),
    });
    await seedExpiredWithoutRefreshToken(wrapped);

    await wrapped.tokens();
    await wrapped.tokens();
    await wrapped.tokens();

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/no refresh_token/i);
    expect(warnings[0]).toMatch(/re-authoriz/i);
  });

  it('reaches REDIRECT through the real auth(), identically to an unwrapped provider', async () => {
    // The decisive test, and the one this file lacked: side by side against the
    // SDK's real orchestrator. Before the fix the wrapped column threw and
    // recorded zero redirects while the bare column redirected.
    async function run(useWrapper: boolean) {
      const { fetchFn } = createMockAuthServer({ mcpServerUrl, authorizationServerUrl });
      const inner = new InMemoryProvider(testClientMetadata);
      const provider = useWrapper
        ? wrapOAuthClientProvider(inner, {
            authorizationServerUrl,
            fallbackTokenTtlMs: 1,
            onWarning: () => {},
          })
        : inner;

      // Seed through the same surface in both columns so the stored state is
      // identical; only the expiry bookkeeping differs, which is the point.
      await provider.saveTokens({ access_token: 'no-refresh', token_type: 'Bearer' });
      await new Promise((resolve) => setTimeout(resolve, 5));

      const result = await auth(provider, {
        serverUrl: mcpServerUrl,
        fetchFn: fetchFn as unknown as typeof fetch,
      });
      return { result, redirects: inner.redirectToAuthorizationCalls.length };
    }

    const bare = await run(false);
    const wrapped = await run(true);

    expect(bare.result).toBe('REDIRECT');
    expect(wrapped.result).toBe('REDIRECT');
    expect(wrapped.redirects).toBe(bare.redirects);
    expect(wrapped.redirects).toBe(1);
  });

  it('still refreshes normally when a refresh_token IS present', async () => {
    // The guard must not have become "never refresh".
    const inner = new InMemoryProvider(testClientMetadata);
    const fetchFn = () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: 'REFRESHED',
            token_type: 'Bearer',
            refresh_token: 'rt2',
            expires_in: 3600,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    inner.presetClientInformation({
      client_id: 'cid',
      ...testClientMetadata,
      issuer: authorizationServerUrl,
    } as never);

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      fallbackTokenTtlMs: 1,
      onWarning: () => {},
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'rt1',
      issuer: authorizationServerUrl,
    });
    await new Promise((resolve) => setTimeout(resolve, 5));

    const tokens = await wrapped.tokens();
    expect(tokens?.access_token).toBe('REFRESHED');
  });
});
