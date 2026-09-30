import { describe, expect, it, vi } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// ALTO (round 6): the generation must be captured ONCE per operation, at the
// same instant as the credentials it describes, and propagated by parameter —
// never re-read mid-chain.
//
// Before this fix, tokens() read `stored` at one moment and refreshNow() read
// `expiryGeneration` at a later one, with an await (the cold store read) in
// between. A saveTokens() landing in that window left the refresh running with
// the OLD refresh_token while labelled with the NEW generation, so it was not
// detected as superseded; the resulting `invalid_grant` — rethrown unwrapped so
// the SDK's auth() can recover — then had auth() invalidate the newer, valid
// credentials.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const MCP = 'https://mcp.example.com';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function mockAuthServer(tokenHandler: (init?: RequestInit) => Promise<Response>) {
  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const method = init?.method ?? 'GET';
    if (u.pathname === '/.well-known/oauth-protected-resource') {
      return jsonResponse({ resource: MCP, authorization_servers: [AS] });
    }
    if (u.pathname === '/.well-known/oauth-authorization-server') {
      return jsonResponse({
        issuer: AS,
        authorization_endpoint: `${AS}/authorize`,
        token_endpoint: `${AS}/token`,
        registration_endpoint: `${AS}/register`,
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (u.pathname === '/.well-known/openid-configuration') {
      return new Response('not found', { status: 404 });
    }
    if (u.pathname === '/register' && method === 'POST') {
      return jsonResponse({ client_id: 'rereg', ...testClientMetadata });
    }
    if (u.pathname === '/token' && method === 'POST') return tokenHandler(init);
    return new Response('not found', { status: 404 });
  };
}

const refreshTokenOf = (init?: RequestInit) =>
  new URLSearchParams(String(init?.body)).get('refresh_token');

/** A store whose get() blocks long enough for a saveTokens() to land mid-read. */
function slowGetStore(delayMs: number) {
  return {
    get: async () => {
      await new Promise((r) => setTimeout(r, delayMs));
      return undefined;
    },
    set: async () => {},
  };
}

/** Only the stale refresh_token is rejected, as a rotating AS does. */
function rejectOnlyStale(calls: string[]) {
  return async (init?: RequestInit) => {
    const rt = refreshTokenOf(init);
    calls.push(rt ?? '(none)');
    if (rt === 'old-rt') {
      return json({ error: 'invalid_grant', error_description: 'rotated away' }, 400);
    }
    return json({ access_token: `renewed-${rt}`, token_type: 'Bearer', expires_in: 3600 });
  };
}

describe('ALTO: a refresh is never labelled with a generation newer than its credentials', () => {
  it('treats the refresh as superseded and returns the fresh tokens, instead of letting invalid_grant escape', async () => {
    const calls: string[] = [];
    const fetchFn = mockAuthServer(rejectOnlyStale(calls));

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({ ...testClientInformation, issuer: AS });
    await inner.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      issuer: AS,
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      expiryStore: slowGetStore(120),
      minExpiresInSeconds: 1,
      // Margin above the new token's TTL, so the freshly saved token is itself
      // immediately "due" — which is what used to push this into a refresh of
      // the stale refresh_token.
      refreshMarginMs: 5_000,
      storeTimeoutMs: 5_000,
      onWarning: () => {},
    });

    // Cold tokens(): reads `stored` (old-rt), then blocks in the store read.
    const cold = wrapped.tokens();
    await new Promise((r) => setTimeout(r, 20));

    // A fresh login lands mid-read: new generation, new refresh_token.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      issuer: AS,
      expires_in: 1,
    });

    const result = await cold;

    // The stale refresh_token must never have been sent...
    expect(calls).not.toContain('old-rt');
    // ...and the caller gets the current credentials, not an error.
    expect(result?.access_token).toBe('FRESH');
    expect((await inner.tokens())?.access_token).toBe('FRESH');
  });

  it('the same race through the real auth() keeps the fresh credentials (AUTHORIZED, not REDIRECT)', async () => {
    const calls: string[] = [];
    const fetchFn = mockAuthServer(rejectOnlyStale(calls));

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AS });
    await inner.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      issuer: AS,
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      expiryStore: slowGetStore(120),
      minExpiresInSeconds: 1,
      refreshMarginMs: 5_000,
      storeTimeoutMs: 5_000,
      onWarning: () => {},
    });

    const inFlight = auth(wrapped, {
      serverUrl: MCP,
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await new Promise((r) => setTimeout(r, 20));

    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      issuer: AS,
      expires_in: 1,
    });

    const result = await inFlight;

    expect(result).toBe('AUTHORIZED');
    expect(inner.redirectToAuthorizationCalls).toHaveLength(0);
    expect(calls).not.toContain('old-rt');
    expect(await inner.tokens()).toBeDefined();
  });

  it('the "minor note": a still-valid token saved mid-read is returned, not the stale snapshot', async () => {
    const fetchFn = vi.fn(async () => json({ access_token: 'should-not-refresh', token_type: 'Bearer' }));

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'old', token_type: 'Bearer', refresh_token: 'old-rt' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      expiryStore: slowGetStore(120),
      storeTimeoutMs: 5_000,
      onWarning: () => {},
    });

    const cold = wrapped.tokens();
    await new Promise((r) => setTimeout(r, 20));

    // Long-lived, so no refresh is warranted — the old path returned the stale
    // `stored` snapshot here rather than what had just been saved.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      expires_in: 3600,
    });

    const result = await cold;
    expect(result?.access_token).toBe('FRESH');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('a concurrent invalidation mid-read yields undefined rather than a stale token or a throw', async () => {
    const fetchFn = vi.fn(async () => json({ access_token: 'x', token_type: 'Bearer' }));

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'old', token_type: 'Bearer', refresh_token: 'old-rt' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      expiryStore: slowGetStore(120),
      storeTimeoutMs: 5_000,
      onWarning: () => {},
    });

    const cold = wrapped.tokens();
    await new Promise((r) => setTimeout(r, 20));
    await wrapped.invalidateCredentials!('tokens');

    // auth() handles `undefined` by going to re-authorization; throwing here
    // would be strictly worse.
    await expect(cold).resolves.toBeUndefined();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('the ordinary path is unchanged: a due token still refreshes normally', async () => {
    const fetchFn = vi.fn(async () =>
      json({ access_token: 'renewed', token_type: 'Bearer', expires_in: 3600 }),
    );

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: -10,
    });

    expect((await wrapped.tokens())?.access_token).toBe('renewed');
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});
