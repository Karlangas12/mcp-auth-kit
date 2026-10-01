import { describe, expect, it, vi } from 'vitest';
import { withTimeout } from '../src/fetchTimeout.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// ALTO-1: `saveTokens()` awaited `provider.saveTokens()` — real I/O — between
// the caller's generation check and the commit. An `invalidateCredentials()`
// landing during that window cleared the state and wrote the revocation
// sentinel, and the save's write then landed afterwards, putting the revoked
// credentials back into storage.
//
// Detecting the overlap after the fact is not enough: by the time a re-check
// can see it, the write has already happened and no later check can un-write
// it. So the two are ordered against each other, and the re-check stays as a
// second line of defence for interleavings the ordering cannot see (an
// application mutating the wrapped provider directly, behind this wrapper).
//
// This is the ORDINARY path — `refreshSalvageMs: 0`. The salvage only widened
// the window; it did not create it.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A provider whose credential writes take real time, as a keychain or a file does. */
function slowStorageProvider(saveDelayMs: number) {
  let tokens: Record<string, unknown> | undefined = {
    access_token: 'old',
    token_type: 'Bearer',
    refresh_token: 'old-rt',
    issuer: AS,
  };
  let clientInfo: Record<string, unknown> | undefined = {
    client_id: 'cid',
    ...testClientMetadata,
    issuer: AS,
  };
  const log: string[] = [];
  return {
    log,
    peek: () => tokens,
    provider: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: () => clientInfo,
      saveClientInformation: (i: Record<string, unknown>) => {
        clientInfo = i;
      },
      tokens: () => tokens,
      saveTokens: async (t: Record<string, unknown>) => {
        await sleep(saveDelayMs);
        log.push(`SAVE:${t.access_token as string}`);
        tokens = t;
      },
      redirectToAuthorization: () => {},
      saveCodeVerifier: () => {},
      codeVerifier: () => 'cv',
      invalidateCredentials: async (scope: string) => {
        log.push('INVALIDATE');
        if (scope === 'all' || scope === 'tokens') tokens = undefined;
        if (scope === 'all' || scope === 'client') clientInfo = undefined;
      },
    },
  };
}

describe('ALTO-1: a revocation cannot be overtaken by a save that started before it', () => {
  it('does not resurrect revoked credentials when invalidateCredentials() lands mid-write', async () => {
    const storeValues = new Map<string, number>();
    const expiryStore = {
      get: async (k: string) => storeValues.get(k),
      set: async (k: string, v: number) => {
        storeValues.set(k, v);
      },
      delete: async (k: string) => {
        storeValues.delete(k);
      },
    };

    const { provider, log, peek } = slowStorageProvider(200);
    const fetchFn = vi.fn(async () =>
      json({ access_token: 'REFRESHED', token_type: 'Bearer', refresh_token: 'new-rt', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(provider as never, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
      refreshSalvageMs: 0, // ordinary path — this is not a salvage-only bug
      expiryStore,
      resourceKey: 'k',
      storeTimeoutMs: 2_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
      onWarning: () => {},
    });

    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'old-rt',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    // A refresh succeeds and enters its 200ms storage write...
    const refreshing = wrapped.tokens().catch(() => undefined);
    await sleep(80);
    // ...and the credentials are revoked while that write is in flight.
    await wrapped.invalidateCredentials!('all');
    await refreshing;
    await sleep(400);

    // The revocation must be the last word on the credentials themselves...
    expect(peek()).toBeUndefined();
    // ...and on the persisted expiry, which must not be an expiry for tokens
    // that no longer exist.
    expect(storeValues.has('k')).toBe(false);
    // MEDIO-B: the revocation now fires immediately AND queues a second,
    // idempotent pass behind the in-flight save — so the save is still followed
    // by a revocation rather than being the last word, without the revocation
    // having to wait on it.
    expect(log[0]).toBe('SAVE:old');
    expect(log.at(-1)).toBe('INVALIDATE');
    expect(log.indexOf('SAVE:REFRESHED')).toBeLessThan(log.lastIndexOf('INVALIDATE'));
  });

  it('a save issued AFTER a revocation still wins, as call order demands', async () => {
    const { provider, peek } = slowStorageProvider(50);
    const wrapped = wrapOAuthClientProvider(provider as never, {
      authorizationServerUrl: AS,
      refreshSalvageMs: 0,
    });

    await wrapped.invalidateCredentials!('all');
    expect(peek()).toBeUndefined();

    // A fresh login after a logout must not be swallowed by the ordering.
    await wrapped.saveTokens({
      access_token: 'FRESH',
      token_type: 'Bearer',
      refresh_token: 'fresh-rt',
      issuer: AS,
      expires_in: 3600,
    });
    expect((peek() as { access_token?: string })?.access_token).toBe('FRESH');
  });

  it('ordering does not serialize unrelated reads: tokens() still works during a slow save', async () => {
    const { provider } = slowStorageProvider(150);
    const wrapped = wrapOAuthClientProvider(provider as never, {
      authorizationServerUrl: AS,
      refreshSalvageMs: 0,
    });

    const saving = wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    const startedAt = Date.now();
    await wrapped.tokens();
    // The read must not have queued behind the write.
    expect(Date.now() - startedAt).toBeLessThan(120);
    await saving;
  });
});

// ---------------------------------------------------------------------------
// ALTO-2: the fetch deadline timer kept the Node event loop alive, so a
// short-lived client could not exit while a request was pending — for up to
// the full deadline. Deadlines are safety nets; they must not be a reason for
// a process to stay alive.
// ---------------------------------------------------------------------------
describe('ALTO-2: a pending fetch deadline does not keep the process alive', () => {
  it('withTimeout adds no ref\'d timer to the event loop', async () => {
    const countTimers = () =>
      process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;

    const before = countTimers();
    // A request that never settles: the deadline timer is the only thing this
    // wrapper contributes, and it must not hold the loop.
    const neverSettles = () => new Promise<Response>(() => {});
    const wrapped = withTimeout(neverSettles as unknown as typeof fetch, 60_000);
    void wrapped('https://example.com').catch(() => {});
    await new Promise((r) => setImmediate(r));

    expect(countTimers()).toBe(before);
  });

  it('still fires while the process is otherwise busy', async () => {
    // Unref'd does not mean inert: the deadline must still abort a hung request
    // whenever anything else is keeping the process running.
    const neverSettles = (_u: string | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('The operation was aborted', 'AbortError')),
        );
      });

    const wrapped = withTimeout(neverSettles as unknown as typeof fetch, 30);
    // The test runner itself keeps the loop alive here, as a real workload would.
    await expect(wrapped('https://example.com')).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('1.0.1: refreshSalvageMs: 0 still aborts at timeoutMs', () => {
  it('does not salvage when explicitly disabled', async () => {
    const state = { rotated: false };
    const fetchFn = (_u: string | URL, init?: RequestInit) =>
      new Promise<Response>((resolve, reject) => {
        state.rotated = true;
        const t = setTimeout(
          () =>
            resolve(
              json({ access_token: 'NEW', token_type: 'Bearer', refresh_token: 'new-rt', expires_in: 3600 }),
            ),
          200,
        );
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(t);
          reject(new DOMException('The operation was aborted', 'AbortError'));
        });
      });

    const { provider, peek } = slowStorageProvider(0);
    const wrapped = wrapOAuthClientProvider(provider as never, {
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
    // Salvage explicitly off: the rotated token is not picked up.
    expect((peek() as { refresh_token?: string })?.refresh_token).toBe('old-rt');
  });
});

describe('the mutation queue is per-instance, not global', () => {
  it('a wedged provider does not block credential writes on another instance', async () => {
    // The queue is a closure variable, so each wrapper owns one. Hoisting it to
    // module scope would make one hung keychain stall every other server's
    // credentials in the same process — this test is what catches that.
    let releaseWedged: () => void = () => {};
    const wedged = slowStorageProvider(0);
    wedged.provider.saveTokens = () => new Promise<void>((r) => (releaseWedged = () => r()));

    const healthy = slowStorageProvider(0);

    const a = wrapOAuthClientProvider(wedged.provider as never, {
      authorizationServerUrl: AS,
      refreshSalvageMs: 0,
    });
    const b = wrapOAuthClientProvider(healthy.provider as never, {
      authorizationServerUrl: AS,
      refreshSalvageMs: 0,
    });

    const tokens = { token_type: 'Bearer', refresh_token: 'r', expires_in: 3600 } as const;
    let aSettled = false;
    void a.saveTokens({ access_token: 'wedged', ...tokens }).then(() => (aSettled = true));
    await sleep(20);

    // B must not be waiting on A's hung storage.
    await b.saveTokens({ access_token: 'healthy', ...tokens });
    expect((healthy.peek() as { access_token?: string })?.access_token).toBe('healthy');
    expect(aSettled).toBe(false);

    releaseWedged();
    await sleep(20);
    expect(aSettled).toBe(true);
  });
});
