import { describe, expect, it } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function provider() {
  let tokens: Record<string, unknown> | undefined;
  return {
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
        tokens = undefined;
      },
    },
  };
}

// ---------------------------------------------------------------------------
// MEDIO-1 (second pass). Registering the cancel handle only once a refresh had
// become a salvage left the entire PRE-timeout window — timeoutMs, 30s by
// default — with nothing for a revocation to reach. That window is the common
// case, not an edge: a logout while a refresh is simply in flight left the
// user's refresh_token on the wire for the rest of the salvage window.
// ---------------------------------------------------------------------------
describe('MEDIO-1: a revocation aborts a refresh in any phase, not only a salvage', () => {
  it('aborts a request that has not yet reached the soft timeout', async () => {
    let signal: AbortSignal | undefined;
    const fetchFn = (_u: string | URL, init?: RequestInit) => {
      signal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('The operation was aborted', 'AbortError')),
        );
      });
    };

    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 5_000, // deliberately long: the soft timeout must NOT be what saves us
      refreshSalvageMs: 30_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    const refreshing = wrapped.tokens().catch(() => undefined);
    await sleep(80);
    expect(signal).toBeDefined();
    expect(signal!.aborted).toBe(false); // in flight, nowhere near timeoutMs

    await wrapped.invalidateCredentials!('tokens');
    await sleep(20);

    // The decisive assertion: the revoked user's refresh is off the wire now,
    // not in 5s and not in 30s.
    expect(signal!.aborted).toBe(true);
    await refreshing;
  });

  it('still aborts one that HAS become a salvage', async () => {
    let signal: AbortSignal | undefined;
    const fetchFn = (_u: string | URL, init?: RequestInit) => {
      signal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('The operation was aborted', 'AbortError')),
        );
      });
    };

    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 30_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(signal!.aborted).toBe(false);
    await wrapped.invalidateCredentials!('all');
    await sleep(20);
    expect(signal!.aborted).toBe(true);
  });

  it('does not abort a refresh belonging to credentials that were not revoked', async () => {
    // The handle must be released when the request ends, so a later revocation
    // cannot reach into an already-finished one (or a newer unrelated caller).
    let aborts = 0;
    const fetchFn = (_u: string | URL, init?: RequestInit) => {
      init?.signal?.addEventListener('abort', () => (aborts += 1));
      return Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: 'NEW',
            token_type: 'Bearer',
            refresh_token: 'RT-2',
            expires_in: 3600,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    };

    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    const refreshed = await wrapped.tokens();
    expect(refreshed?.access_token).toBe('NEW');
    await wrapped.invalidateCredentials!('all');
    expect(aborts).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// BAJO-1. The expiry store's write is issued after its save has released its
// queue turn, so two saves' writes raced — and only the newest was tracked, so
// a revocation awaited the wrong one. Both reproduce only against a store whose
// latency varies with the value, which is what a real one does.
// ---------------------------------------------------------------------------
function latencyStore(latencyFor: (v: number) => number) {
  const values = new Map<string, number>();
  const writeOrder: number[] = [];
  let deletes = 0;
  return {
    writeOrder,
    deletes: () => deletes,
    get: () => values.get('k'),
    api: {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        await sleep(latencyFor(v));
        writeOrder.push(v);
        values.set(k, v);
      },
      delete: async (k: string) => {
        deletes += 1;
        values.delete(k);
      },
    },
  };
}

describe('BAJO-1: expiry-store writes are ordered and all of them are tracked', () => {
  it('leaves the LATER save\'s expiry in the store, not the earlier one\'s', async () => {
    const now = Date.now();
    // The far-future expiry is slow to write; the near one is fast. Unordered,
    // the slow one lands last and the store ends up describing tokens that are
    // no longer there.
    const store = latencyStore((v) => (v - now > 1_000_000 ? 120 : 5));
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store.api,
      resourceKey: 'k',
      storeTimeoutMs: 2_000,
      minExpiresInSeconds: 1,
      onWarning: () => {},
    });

    const a = wrapped.saveTokens({
      access_token: 'A',
      token_type: 'Bearer',
      refresh_token: 'rA',
      expires_in: 100_000,
    });
    const b = wrapped.saveTokens({
      access_token: 'B',
      token_type: 'Bearer',
      refresh_token: 'rB',
      expires_in: 60,
    });
    await Promise.all([a, b]);
    await sleep(250);

    // Provider holds B, so the store must hold B's expiry. With A's landing
    // last, a restarted process would read a +100000s expiry for a token that
    // actually lived 60s and never refresh it proactively.
    expect((p.peek() as { access_token?: string })?.access_token).toBe('B');
    const persisted = store.get()!;
    expect(persisted - now).toBeLessThan(70_000);
    // And the writes themselves went out in call order.
    expect(store.writeOrder).toHaveLength(2);
    expect(store.writeOrder[1]).toBe(persisted);
  });

  it('a straggling write cannot restore an expiry after a revocation deleted it', async () => {
    const now = Date.now();
    const store = latencyStore((v) => (v - now > 1_000_000 ? 150 : 5));
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store.api,
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
    await sleep(400);

    // The decisive assertion: nothing came back after the delete. Before the
    // fix, only the newest write was awaited, so the older slow one landed
    // afterwards and put a live-looking far-future expiry back.
    expect(store.get()).toBeUndefined();
    expect(store.deletes()).toBe(1);
    expect(p.peek()).toBeUndefined();
  });
});
