import { describe, expect, it } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STORE_TIMEOUT = 300;

/** A store whose every operation never settles. */
function hungStore() {
  let gets = 0;
  return {
    gets: () => gets,
    api: {
      get: () => {
        gets += 1;
        return new Promise<number | undefined>(() => {});
      },
      set: () => new Promise<void>(() => {}),
      delete: () => new Promise<void>(() => {}),
    },
  };
}

function provider() {
  let tokens: Record<string, unknown> | undefined;
  const invalidations: number[] = [];
  const startedAt = Date.now();
  return {
    invalidations,
    peek: () => tokens,
    api: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: () => ({ client_id: 'cid', ...testClientMetadata, issuer: AS }),
      saveClientInformation: () => {},
      tokens: () => tokens,
      saveTokens: (t: Record<string, unknown>) => {
        tokens = t;
      },
      redirectToAuthorization: () => {},
      saveCodeVerifier: () => {},
      codeVerifier: () => 'cv',
      invalidateCredentials: () => {
        invalidations.push(Date.now() - startedAt);
        tokens = undefined;
      },
    },
  };
}

function wrap(storeApi: unknown, p: ReturnType<typeof provider>) {
  return wrapOAuthClientProvider(p.api as never, {
    authorizationServerUrl: AS,
    expiryStore: storeApi as never,
    resourceKey: 'k',
    storeTimeoutMs: STORE_TIMEOUT,
    minExpiresInSeconds: 1,
    onWarning: () => {},
  });
}

const someTokens = (id: string) => ({
  access_token: id,
  token_type: 'Bearer' as const,
  refresh_token: `r-${id}`,
  expires_in: 3600,
});

// ---------------------------------------------------------------------------
// MEDIO-2. Ordering the expiry-store writes fixed BAJO-1 but started each
// write's storeTimeoutMs clock when its TURN came rather than when its caller
// enqueued it. So write k+1 only began once write k had timed out, and the k-th
// caller waited k * storeTimeoutMs. At the 5000ms default that is ~25s on
// tokens(), which the transport calls on every request, and ~30s before the
// SDK's auth() can get past the revocation it awaits.
//
// The write stays ordered in the internal chain either way. What is bounded is
// how long a caller watches it — which is all a supplementary cache is owed.
// ---------------------------------------------------------------------------
describe('MEDIO-2: a caller waits one storeTimeoutMs, not k of them', () => {
  it('bounds five concurrent saves at roughly one timeout each, not a growing sum', async () => {
    const store = hungStore();
    const p = provider();
    const wrapped = wrap(store.api, p);

    const startedAt = Date.now();
    const elapsed = await Promise.all(
      ['a', 'b', 'c', 'd', 'e'].map(async (id) => {
        await wrapped.saveTokens(someTokens(id));
        return Date.now() - startedAt;
      }),
    );

    // Before the fix these landed at ~310/623/932/1242/1554ms — k * timeout.
    // The last caller is what matters: it must not have waited for the queue.
    expect(Math.max(...elapsed)).toBeLessThan(STORE_TIMEOUT * 2);
    // And every one of them did wait for its own deadline, so the bound is a
    // bound rather than the write being dropped.
    expect(Math.min(...elapsed)).toBeGreaterThanOrEqual(STORE_TIMEOUT - 50);
  });

  it('bounds invalidateCredentials() even with writes outstanding', async () => {
    const store = hungStore();
    const p = provider();
    const wrapped = wrap(store.api, p);

    for (const id of ['a', 'b', 'c', 'd', 'e']) void wrapped.saveTokens(someTokens(id));
    await sleep(20);

    const startedAt = Date.now();
    await wrapped.invalidateCredentials!('all');
    const took = Date.now() - startedAt;

    // Before the fix this resolved after ~1861ms ≈ 6 * storeTimeoutMs, on the
    // path auth() awaits before it can recover.
    expect(took).toBeLessThan(STORE_TIMEOUT * 2);
    // The revocation itself was never the slow part — it reached the provider
    // immediately, which is the property that must not regress.
    expect(p.invalidations.length).toBeGreaterThanOrEqual(1);
    expect(p.peek()).toBeUndefined();
  });

  it('bounds a refreshing tokens() queued behind outstanding writes', async () => {
    const store = hungStore();
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store.api as never,
      resourceKey: 'k',
      storeTimeoutMs: STORE_TIMEOUT,
      fetchFn: (() =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              access_token: 'NEW',
              token_type: 'Bearer',
              refresh_token: 'RT-2',
              expires_in: 3600,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        )) as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
      onWarning: () => {},
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);
    // Four more writes queued against the hung store.
    for (const id of ['a', 'b', 'c', 'd']) void wrapped.saveTokens(someTokens(id));
    await sleep(20);

    const startedAt = Date.now();
    await wrapped.tokens();
    const took = Date.now() - startedAt;

    // Before the fix: ~1501ms = 5 * storeTimeoutMs on the per-request path.
    expect(took).toBeLessThan(STORE_TIMEOUT * 2);
  });

  it('a cold read stays bounded and never enters the write queue', async () => {
    const store = hungStore();
    const p = provider();
    const wrapped = wrap(store.api, p);
    p.api.saveTokens({ access_token: 'cold', token_type: 'Bearer', refresh_token: 'r' });

    for (const id of ['a', 'b', 'c']) void wrapped.saveTokens(someTokens(id));
    await sleep(20);

    const startedAt = Date.now();
    await wrapped.tokens();
    expect(Date.now() - startedAt).toBeLessThan(STORE_TIMEOUT * 2);
  });
});

describe('MEDIO-2: bounding the wait does not uncouple the ordering it protects', () => {
  it('still lands the later save\'s expiry last, and the delete after both', async () => {
    const now = Date.now();
    const order: string[] = [];
    const values = new Map<string, number>();
    const store = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        // Latency varies with the value, as a real store's does.
        await sleep(v - now > 1_000_000 ? 120 : 5);
        order.push(`set:${v - now > 1_000_000 ? 'far' : 'near'}`);
        values.set(k, v);
      },
      delete: async (k: string) => {
        order.push('delete');
        values.delete(k);
      },
    };

    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store,
      resourceKey: 'k',
      storeTimeoutMs: 2_000,
      minExpiresInSeconds: 1,
      onWarning: () => {},
    });

    void wrapped.saveTokens({
      access_token: 'A',
      token_type: 'Bearer',
      refresh_token: 'rA',
      expires_in: 100_000,
    });
    void wrapped.saveTokens({
      access_token: 'B',
      token_type: 'Bearer',
      refresh_token: 'rB',
      expires_in: 60,
    });
    await sleep(20);
    await wrapped.invalidateCredentials!('all');
    await sleep(500);

    // BAJO-1's guarantee must survive MEDIO-2's fix: the chain, not the wait,
    // is what orders these.
    expect(order).toEqual(['set:far', 'set:near', 'delete']);
    expect(values.has('k')).toBe(false);
  });
});
