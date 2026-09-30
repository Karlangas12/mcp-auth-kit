import { describe, expect, it, vi } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// ALTO-1 / MEDIO-1 / MEDIO-2 (round 5): the in-flight refresh slot (`refreshing`)
// was the one piece of shared state left outside the generation mechanism.
//
// A caller from a NEWER generation could join an OLDER refresh and inherit its
// outcome. Since round 4 rethrows `invalid_grant` unwrapped so the SDK's auth()
// can recover, inheriting that outcome made auth() invalidate credentials —
// destroying the newer, valid tokens. A bare provider, having no dedupe at all,
// would simply have refreshed the current refresh_token and succeeded.
//
// Every test here forces the interleaving with manually controlled promises.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const MCP = 'https://mcp.example.com';

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
const drain = () => new Promise((r) => setImmediate(r));

/** Discovery + token endpoint, with the token handler supplied per test. */
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

function refreshTokenOf(init?: RequestInit): string | null {
  return new URLSearchParams(String(init?.body)).get('refresh_token');
}

describe('ALTO-1: a new generation never joins an older in-flight refresh', () => {
  it('does not lose newly saved tokens when an older refresh fails with invalid_grant (through the real auth())', async () => {
    const oldRefreshGate = deferred();
    const tokenCalls: string[] = [];

    const fetchFn = mockAuthServer(async (init) => {
      const rt = refreshTokenOf(init);
      tokenCalls.push(rt ?? '(none)');
      if (rt === 'old-rt') {
        // The stale refresh: held open, then rejected the way a rotating
        // authorization server rejects a superseded grant.
        await oldRefreshGate.promise;
        return jsonResponse({ error: 'invalid_grant', error_description: 'superseded grant' }, 400);
      }
      return jsonResponse({ access_token: `renewed-${rt}`, token_type: 'Bearer', expires_in: 3600 });
    });

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AS });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });

    // Generation N: tokens with old-rt, already due for refresh.
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      issuer: AS,
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    // A background refresh of old-rt goes in flight and stays there.
    const background = wrapped.tokens().catch(() => 'background failed');
    while (tokenCalls.length === 0) await drain();

    // Generation N+1: a fresh login completes and stores new, valid credentials
    // — which are themselves already due, so auth() below will want a refresh.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      issuer: AS,
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    // The real auth(), now in generation N+1, must refresh new-rt on its own
    // rather than adopting the old-rt refresh still in flight.
    const result = await auth(wrapped, {
      serverUrl: MCP,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    oldRefreshGate.resolve();
    await background;

    // It ran its own refresh with the current refresh_token...
    expect(tokenCalls).toContain('new-rt');
    // ...succeeded, so no re-authorization was needed...
    expect(result).toBe('AUTHORIZED');
    expect(inner.redirectToAuthorizationCalls).toHaveLength(0);
    // ...and the credentials were NOT wiped by the stale invalid_grant.
    expect((await inner.tokens())?.access_token).toBe('renewed-new-rt');
  });

  it('still shares one in-flight refresh between concurrent callers of the SAME generation', async () => {
    const gate = deferred();
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      await gate.promise;
      return jsonResponse({ access_token: 'renewed', token_type: 'Bearer', expires_in: 3600 });
    });

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

    const a = wrapped.tokens();
    const b = wrapped.tokens();
    const c = wrapped.tokens();
    gate.resolve();
    const [ra, rb, rc] = await Promise.all([a, b, c]);

    // The dedupe that rounds 1-4 established must survive this fix.
    expect(calls).toBe(1);
    expect(ra?.access_token).toBe('renewed');
    expect(rb?.access_token).toBe('renewed');
    expect(rc?.access_token).toBe('renewed');
  });
});

describe('MEDIO-2: a superseded-but-successful refresh resolves to the current tokens', () => {
  it('returns the newer saved tokens instead of failing the request', async () => {
    const gate = deferred();
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      await gate.promise;
      // A non-rotating AS: the old refresh_token still works.
      return jsonResponse({ access_token: 'from-old-rt', token_type: 'Bearer', expires_in: 3600 });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    const inFlight = wrapped.tokens();
    while (calls === 0) await drain();

    // A newer saveTokens() supersedes the in-flight refresh.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      expires_in: 3600,
    });

    gate.resolve();

    // Last-write-wins: the caller gets the newer valid tokens, not an error,
    // and the superseded response is not persisted over them.
    const result = await inFlight;
    expect(result?.access_token).toBe('FRESH');
    expect((await inner.tokens())?.access_token).toBe('FRESH');
  });

  it('a request served through the real auth() succeeds across that same race', async () => {
    const gate = deferred();
    let refreshCalls = 0;
    const fetchFn = mockAuthServer(async () => {
      refreshCalls += 1;
      if (refreshCalls === 1) {
        await gate.promise;
        return jsonResponse({ access_token: 'from-old-rt', token_type: 'Bearer', expires_in: 3600 });
      }
      return jsonResponse({ access_token: 'renewed', token_type: 'Bearer', expires_in: 3600 });
    });

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AS });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      issuer: AS,
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    const background = wrapped.tokens().catch(() => 'bg failed');
    while (refreshCalls === 0) await drain();

    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      issuer: AS,
      expires_in: 3600,
    });

    gate.resolve();
    expect(await background).not.toBe('bg failed');

    const result = await auth(wrapped, {
      serverUrl: MCP,
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    expect(result).toBe('AUTHORIZED');
    expect(inner.redirectToAuthorizationCalls).toHaveLength(0);
  });

  it('a refresh superseded by invalidateCredentials() still surfaces, since there is nothing to return', async () => {
    const gate = deferred();
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      await gate.promise;
      return jsonResponse({ access_token: 'resurrected', token_type: 'Bearer', expires_in: 3600 });
    });

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation(testClientInformation);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });

    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    const inFlight = wrapped.tokens().then(
      (t) => ({ ok: true as const, t }),
      (e) => ({ ok: false as const, e: e as Error }),
    );
    while (calls === 0) await drain();

    await wrapped.invalidateCredentials!('tokens');
    gate.resolve();

    const outcome = await inFlight;
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.e).toMatchObject({ phase: 'token_refresh' });
    // And the discarded tokens were not resurrected into storage.
    expect((await inner.tokens())?.access_token).not.toBe('resurrected');
  });
});

describe('MEDIO-1: a superseded failure neither caches nor escapes as a recoverable error', () => {
  it('does not let a stale invalid_grant reach auth() and wipe newer credentials', async () => {
    const gate = deferred();
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      await gate.promise;
      return jsonResponse({ error: 'invalid_grant', error_description: 'stale' }, 400);
    });

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
      refreshFailureCacheMs: 60_000,
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    const inFlight = wrapped.tokens().then(
      (t) => ({ ok: true as const, t }),
      (e) => ({ ok: false as const, e: e as Error }),
    );
    while (calls === 0) await drain();

    // Supersede with a fresh, valid, long-lived token.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      expires_in: 3600,
    });

    gate.resolve();
    const outcome = await inFlight;

    // The stale failure must NOT surface as the unwrapped OAuth error that
    // auth() reacts to by invalidating credentials. Superseded-by-save means
    // the current tokens are the answer.
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.t?.access_token).toBe('FRESH');

    // And it must NOT have opened a failure-cache window over the new
    // generation: the fresh token is valid for an hour, so nothing should be
    // suppressed, and a later refresh must be attempted normally.
    const before = calls;
    await wrapped.saveTokens({
      access_token: 'FRESH2',
      token_type: 'Bearer',
      refresh_token: 'new-rt',
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));
    await wrapped.tokens().catch(() => {});
    expect(calls).toBeGreaterThan(before);
  });
});
