import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// M6 (round 2, re-audited): the refresh grant is a non-idempotent POST, and an
// authorization server typically rotates the refresh token the moment it
// processes one. Aborting the request at `timeoutMs` therefore destroyed
// credentials: the server had already invalidated the old refresh token, and
// the response carrying the new one went away with the connection. Every later
// attempt then failed with invalid_grant and forced a full re-login — for a
// refresh that had actually succeeded.
//
// The fix separates the two concerns. `timeoutMs` still releases the caller;
// the request itself is kept alive for up to `refreshSalvageMs` and, if it
// lands with tokens, they are persisted under the same generation check every
// other late result goes through.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const drain = () => new Promise((r) => setImmediate(r));

/**
 * An authorization server that rotates on receipt, exactly as a real one does:
 * the moment it sees `old-rt` that token is dead, whether or not the client
 * ever reads the response. Honours AbortSignal, like a conforming `fetch`.
 */
function rotatingAuthServer(responseDelayMs: number) {
  const state = { rotated: false, requests: [] as (string | null)[] };
  const fetchFn = (_url: string | URL, init?: RequestInit): Promise<Response> => {
    const rt = new URLSearchParams(String(init?.body)).get('refresh_token');
    state.requests.push(rt);
    if (rt !== 'old-rt') {
      return Promise.resolve(json({ error: 'invalid_grant', error_description: 'already used' }, 400));
    }
    state.rotated = true;
    return new Promise((resolve, reject) => {
      const t = setTimeout(
        () =>
          resolve(
            json({ access_token: 'NEW', token_type: 'Bearer', refresh_token: 'new-rt', expires_in: 3600 }),
          ),
        responseDelayMs,
      );
      init?.signal?.addEventListener('abort', () => {
        clearTimeout(t);
        reject(new DOMException('The operation was aborted', 'AbortError'));
      });
    });
  };
  return { fetchFn, state };
}

async function dueProvider() {
  const inner = new InMemoryProvider(testClientMetadata, {
    canInvalidateCredentials: true,
    invalidateClearsCredentials: true,
  });
  inner.presetClientInformation({ ...testClientInformation, issuer: AS });
  return inner;
}

describe('M6: a refresh that answers after timeoutMs is salvaged, not destroyed', () => {
  it('persists the rotated refresh_token instead of leaving the client on a dead one', async () => {
    const { fetchFn, state } = rotatingAuthServer(200);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 50,
      refreshSalvageMs: 5_000,
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
    await sleep(1100);

    // The caller's own attempt still fails at timeoutMs — it is not blocked.
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(state.rotated).toBe(true);

    // But the response lands afterwards and is salvaged.
    await sleep(300);
    expect((await inner.tokens())?.refresh_token).toBe('new-rt');
    expect((await inner.tokens())?.access_token).toBe('NEW');

    // So the next call succeeds without another round trip to the AS.
    const before = state.requests.length;
    expect((await wrapped.tokens())?.access_token).toBe('NEW');
    expect(state.requests.length).toBe(before);
  });

  it('releases the caller at timeoutMs, not at refreshSalvageMs', async () => {
    const { fetchFn } = rotatingAuthServer(3_000);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 40,
      refreshSalvageMs: 10_000,
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
    await sleep(1100);

    const startedAt = Date.now();
    await expect(wrapped.tokens()).rejects.toThrow();
    // Bounded by timeoutMs, nowhere near the 3s response or the 10s window.
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it('the timeout error advises retrying rather than discarding credentials', async () => {
    const { fetchFn } = rotatingAuthServer(3_000);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 40,
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
    await sleep(1100);

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }
    const err = caught as Error & { remediation?: string };
    // Telling the caller to discard tokens here would be wrong: a salvage may
    // still land.
    expect(err.remediation).toMatch(/retry rather than discarding/);
    expect(err.remediation).not.toMatch(/discard stored tokens/);
  });

  it('refreshSalvageMs: 0 restores the old abort-at-timeoutMs behaviour', async () => {
    const { fetchFn, state } = rotatingAuthServer(200);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 50,
      refreshSalvageMs: 0,
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
    await sleep(1100);

    await expect(wrapped.tokens()).rejects.toThrow();
    await sleep(300);

    expect(state.rotated).toBe(true);
    // Opted out: the rotated token is lost, as documented for this setting.
    expect((await inner.tokens())?.refresh_token).toBe('old-rt');
  });
});

describe('M6: the salvage is generation-guarded like every other late writer', () => {
  it('discards a late success if the credentials were invalidated meanwhile', async () => {
    const { fetchFn, state } = rotatingAuthServer(200);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 40,
      refreshSalvageMs: 5_000,
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
    await sleep(1100);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(state.rotated).toBe(true);

    // Revoke while the salvage is still in flight.
    await wrapped.invalidateCredentials!('all');
    await sleep(300);

    // The salvage must not resurrect credentials that were just revoked.
    expect(await inner.tokens()).toBeUndefined();
  });

  it('discards a late success if a newer saveTokens() superseded it', async () => {
    const { fetchFn } = rotatingAuthServer(200);
    const inner = await dueProvider();

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 40,
      refreshSalvageMs: 5_000,
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
    await sleep(1100);

    await expect(wrapped.tokens()).rejects.toThrow();

    // A fresh login lands before the salvage does.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'fresh-rt',
      issuer: AS,
      expires_in: 3600,
    });
    await sleep(300);

    // Last write wins: the salvage must not overwrite newer credentials.
    expect((await inner.tokens())?.access_token).toBe('FRESH');
    expect((await inner.tokens())?.refresh_token).toBe('fresh-rt');
  });

  it('a late FAILURE is swallowed: it neither throws nor opens the failure-cache window', async () => {
    let calls = 0;
    const fetchFn = vi.fn((_url: string | URL, init?: RequestInit): Promise<Response> => {
      calls += 1;
      if (calls === 1) {
        // Slow, and ultimately a definitive rejection.
        return new Promise((resolve) => {
          setTimeout(() => resolve(json({ error: 'invalid_grant' }, 400)), 200);
          init?.signal?.addEventListener('abort', () => {});
        });
      }
      return Promise.resolve(
        json({ access_token: 'renewed', token_type: 'Bearer', refresh_token: 'r2', expires_in: 3600 }),
      );
    });

    const inner = await dueProvider();
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 40,
      refreshSalvageMs: 5_000,
      refreshFailureCacheMs: 60_000,
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
    await sleep(1100);

    await expect(wrapped.tokens()).rejects.toThrow();
    await sleep(300); // the late invalid_grant lands here

    // A timeout is transient, so nothing may be suppressed: the next attempt
    // must reach the authorization server rather than be short-circuited by a
    // failure that belonged to an abandoned attempt.
    const before = calls;
    const result = await wrapped.tokens();
    expect(calls).toBeGreaterThan(before);
    expect(result?.access_token).toBe('renewed');
  });

  it('does not leave an unhandled rejection behind when the salvage fails', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const fetchFn = (_url: string | URL, init?: RequestInit): Promise<Response> =>
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new TypeError('connection reset')), 150);
          init?.signal?.addEventListener('abort', () => {});
        });

      const inner = await dueProvider();
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: AS,
        fetchFn: fetchFn as unknown as typeof fetch,
        timeoutMs: 40,
        refreshSalvageMs: 5_000,
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
      await sleep(1100);

      await expect(wrapped.tokens()).rejects.toThrow();
      await sleep(300);
      await drain();

      expect(unhandled).toHaveLength(0);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});
