import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// FIX 1 (round 4): every write to the wrapper's shared expiry/refresh state
// goes through commitExpiryState(generation, patch), and both saveTokens() and
// invalidateCredentials() start a new generation. Anything computed under an
// older generation is dropped.
//
// Four async paths touch that state — tokens(), saveTokens(), performRefresh()
// and invalidateCredentials() — and previously only invalidateCredentials()
// bumped the generation, so the other three could clobber each other. Each
// test below forces the exact interleaving with manually-controlled promises;
// none of them depend on implicit timing.
// ---------------------------------------------------------------------------

/** A promise whose resolution this test controls explicitly. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Lets the microtask queue drain so an awaiting continuation actually runs. */
const drain = () => new Promise((r) => setImmediate(r));

describe('FIX 1 (a): a cold ExpiryStore read cannot clobber a newer saveTokens()', () => {
  it('keeps the expiry written by a concurrent saveTokens() and discards the late store read', async () => {
    const storeGate = deferred<number>();
    let firstGet = true;
    const store = {
      get: async () => {
        if (firstGet) {
          firstGet = false;
          return storeGate.promise; // blocks until we release it
        }
        return undefined;
      },
      set: async () => {},
    };

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'old', token_type: 'Bearer', refresh_token: 'r1' });

    let refreshes = 0;
    const fetchFn = vi.fn(async () => {
      refreshes += 1;
      return jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1, // let a deliberately tiny TTL through
      refreshMarginMs: 0,
    });

    // 1. A cold tokens() blocks inside the store read.
    const coldRead = wrapped.tokens();
    await drain();

    // 2. Meanwhile a saveTokens() lands a SHORT-lived token (1s).
    await wrapped.saveTokens({
      access_token: 'fresh-short',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: 1,
    });

    // 3. Only now does the stale store read resolve, claiming another hour.
    storeGate.resolve(Date.now() + 60 * 60 * 1000);
    await coldRead;

    // 4. Once the 1s token has really expired, tokens() must refresh. If the
    //    stale read had won, the wrapper would believe it has an hour left and
    //    hand back an expired access token instead.
    await new Promise((r) => setTimeout(r, 1100));
    await wrapped.tokens();

    expect(refreshes).toBe(1);
  });
});

describe('FIX 1 (b): a refresh failing AFTER invalidateCredentials() cannot repopulate the failure cache', () => {
  it('does not block a fresh refresh_token with a failure from discarded credentials', async () => {
    const fetchGate = deferred<void>();
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      if (calls === 1) {
        await fetchGate.promise;
        return new Response(JSON.stringify({ error: 'invalid_grant' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return jsonResponse({ access_token: 'renewed', token_type: 'Bearer', expires_in: 3600 });
    });

    const values = new Map<string, number>();
    const store = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        values.set(k, v);
      },
      // no delete() -> invalidateCredentials writes the 0 sentinel
    };

    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    inner.presetClientInformation(testClientInformation);

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
      refreshFailureCacheMs: 60_000,
    });

    // Make the wrapper believe the token is expired, then start a refresh.
    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: 1,
    });
    await new Promise((r) => setTimeout(r, 1100));

    const refreshAttempt = wrapped.tokens().catch(() => 'failed');
    await drain();
    expect(calls).toBe(1); // the refresh really is in flight

    // Invalidate WHILE the refresh is in flight.
    await wrapped.invalidateCredentials!('tokens');

    // Only now let the in-flight refresh fail definitively.
    fetchGate.resolve();
    await refreshAttempt;

    // A fresh authorization elsewhere stores a new refresh_token.
    inner.saveTokens({ access_token: 'b', token_type: 'Bearer', refresh_token: 'r2' });

    // The new token must get a real attempt: the failure belonged to a
    // generation that was discarded, so it must not be suppressing anything.
    const before = calls;
    await wrapped.tokens().catch(() => {});
    expect(calls).toBeGreaterThan(before);
  });
});

describe('FIX 1 (c): a refresh SUCCEEDING after invalidateCredentials() cannot resurrect credentials', () => {
  it('does not persist the refreshed tokens, overwrite the sentinel, or clear the failure window', async () => {
    const fetchGate = deferred<void>();
    const fetchFn = vi.fn(async () => {
      await fetchGate.promise;
      return jsonResponse({
        access_token: 'resurrected',
        token_type: 'Bearer',
        refresh_token: 'r-new',
        expires_in: 3600,
      });
    });

    const values = new Map<string, number>();
    const store = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        values.set(k, v);
      },
      // no delete() -> sentinel path
    };

    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    inner.presetClientInformation(testClientInformation);

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
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

    const refreshAttempt = wrapped.tokens().then(
      (t) => ({ ok: true as const, t }),
      (e) => ({ ok: false as const, e }),
    );
    await drain();
    expect(fetchFn).toHaveBeenCalledTimes(1); // in flight

    // Invalidate while the refresh is in flight. This writes the 0 sentinel.
    await wrapped.invalidateCredentials!('tokens');
    expect(values.get('https://auth.example.com')).toBe(0);

    // Now let the refresh SUCCEED.
    fetchGate.resolve();
    const outcome = await refreshAttempt;

    // The successful-but-superseded result must be discarded, not committed.
    expect(outcome.ok).toBe(false);

    // The sentinel must survive: the refresh must not have written its own
    // expiry over the revocation marker.
    expect(values.get('https://auth.example.com')).toBe(0);

    // And the discarded tokens must not have been persisted into the provider.
    expect((await inner.tokens())?.access_token).not.toBe('resurrected');
  });
});

describe('FIX 1: the happy paths still behave', () => {
  it('a normal cold store read is still adopted when nothing supersedes it', async () => {
    const store = {
      get: async () => Date.now() + 60 * 60 * 1000,
      set: async () => {},
    };
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'good', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect((await wrapped.tokens())?.access_token).toBe('good');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('a normal refresh with no concurrent invalidation still persists and returns', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'renewed', token_type: 'Bearer', expires_in: 3600 }),
    );
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: -10,
    });

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('renewed');
    expect((await inner.tokens())?.access_token).toBe('renewed');
  });
});
