import { describe, expect, it, vi } from 'vitest';
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { sanitizedCause } from '../src/sanitize.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// MEDIO-3 (round 5): ExpiryStore operations had no timeout. The store is a
// supplementary cache, but a hung one could stall tokens() — which the
// transport calls on EVERY request — and hang invalidateCredentials(), which
// the SDK's auth() awaits during recovery. Worse, the wrapped provider was
// invalidated only AFTER the store cleanup, so a hung store meant the
// credentials were never actually revoked.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';

/** A store whose operations never settle. */
const hangingStore = {
  get: () => new Promise<number | undefined>(() => {}),
  set: () => new Promise<void>(() => {}),
  delete: () => new Promise<void>(() => {}),
};

describe('MEDIO-3: a hung expiryStore cannot stall tokens()', () => {
  it('tokens() resolves despite a get() that never settles', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stored', token_type: 'Bearer', refresh_token: 'r1' });

    const warnings: string[] = [];
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: hangingStore,
      storeTimeoutMs: 30,
      onWarning: (m) => warnings.push(m),
    });

    const result = await wrapped.tokens();

    // Degrades to "expiry unknown" — the documented no-adapter behaviour.
    expect(result?.access_token).toBe('stored');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/storeTimeoutMs/);
  });

  it('a hung get() does not make every later call pay the timeout again', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stored', token_type: 'Bearer', refresh_token: 'r1' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: hangingStore,
      storeTimeoutMs: 30,
      onWarning: () => {},
    });

    await wrapped.tokens();
    const startedAt = Date.now();
    await wrapped.tokens();
    await wrapped.tokens();
    // The store was already consulted once; subsequent calls must not re-read.
    expect(Date.now() - startedAt).toBeLessThan(25);
  });

  it('a hung set() does not stall saveTokens()', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: hangingStore,
      storeTimeoutMs: 30,
      onWarning: () => {},
    });

    await expect(
      wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 }),
    ).resolves.toBeUndefined();
    // The authoritative save still happened.
    expect((await inner.tokens())?.access_token).toBe('a');
  });
});

describe('MEDIO-3: a hung expiryStore cannot stall or skip credential invalidation', () => {
  it('invalidateCredentials() resolves, and the wrapped provider is really invalidated', async () => {
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'revoke-me', token_type: 'Bearer', refresh_token: 'r1' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: hangingStore,
      storeTimeoutMs: 30,
      onWarning: () => {},
    });

    await expect(wrapped.invalidateCredentials!('all')).resolves.toBeUndefined();

    // The decisive assertion: revocation reached the thing that actually holds
    // the credentials, even though the expiry cache never answered.
    // MEDIO-B: the revocation reaches the provider immediately, and a second,
    // idempotent pass is queued behind anything already in flight so a save
    // that started earlier cannot land after it. Both carry the same scope.
    expect(inner.invalidateCredentialsCalls[0]).toBe('all');
    expect(new Set(inner.invalidateCredentialsCalls)).toEqual(new Set(['all']));
    expect(await inner.tokens()).toBeUndefined();
  });

  it('the wrapped provider is invalidated even when the store cleanup is merely slow', async () => {
    const order: string[] = [];
    const slowStore = {
      get: async () => undefined,
      set: async () => {},
      delete: async () => {
        await new Promise((r) => setTimeout(r, 40));
        order.push('store-delete');
      },
    };

    const base = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    const inner = Object.assign(base, {
      invalidateCredentials: async (scope: string) => {
        order.push('provider-invalidate');
        base.invalidateCredentialsCalls.push(scope);
      },
    }) as unknown as InMemoryProvider;

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: slowStore,
      storeTimeoutMs: 500,
      onWarning: () => {},
    });

    await wrapped.invalidateCredentials!('tokens');

    // Revocation first, cache housekeeping second. The queued second pass
    // (MEDIO-B) is idempotent and unordered with respect to the store cleanup,
    // so only the first revocation's position is asserted.
    expect(order[0]).toBe('provider-invalidate');
    expect(order.indexOf('store-delete')).toBeGreaterThan(-1);
    expect(order.filter((e) => e === 'store-delete')).toHaveLength(1);
  });
});

describe('MEDIO-3 / residual: a pending store write is ordered before the revocation cleanup', () => {
  it('a slow set() from saveTokens() cannot land after the revocation sentinel', async () => {
    const values = new Map<string, number>();
    const applied: string[] = [];
    // Network-like: set is slow, delete is fast, so completion order would not
    // match issue order without explicit sequencing.
    const reordering = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        // Asymmetric latency, as independent network requests have: the
        // sentinel write is fast, the expiry write slow. Without explicit
        // sequencing the slow expiry lands AFTER the sentinel and leaves a
        // live-looking expiry behind a revocation.
        await new Promise((r) => setTimeout(r, v === 0 ? 1 : 60));
        values.set(k, v);
        applied.push(v === 0 ? 'sentinel' : 'expiry');
      },
      // no delete() -> sentinel path
    };

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: reordering,
      resourceKey: 'k',
      storeTimeoutMs: 500,
      onWarning: () => {},
    });

    // Start a save whose store write is in flight, then revoke.
    const save = wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    await new Promise((r) => setImmediate(r));
    await wrapped.invalidateCredentials!('all');
    await save;
    await new Promise((r) => setTimeout(r, 120));

    // The sentinel must be the last word, not the expiry.
    expect(applied).toEqual(['expiry', 'sentinel']);
    expect(values.get('k')).toBe(0);
  });
});

// MEDIO-2 (round 6): runStoreOp invoked op() directly, so a store violating its
// own `Promise<...>` contract with a synchronous throw propagated straight out
// and broke tokens() — the one function that exists so the store is never
// load-bearing.
describe('MEDIO-2: a store that throws synchronously degrades like one that rejects', () => {
  it('tokens() survives a get() that throws synchronously', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stored', token_type: 'Bearer', refresh_token: 'r1' });

    const syncThrowingStore = {
      get() {
        throw new Error('sync boom');
      },
      set: async () => {},
    } as unknown as { get: () => Promise<number | undefined>; set: () => Promise<void> };

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: syncThrowingStore,
      onWarning: () => {},
    });

    await expect(wrapped.tokens()).resolves.toMatchObject({ access_token: 'stored' });
  });

  it('behaves identically to a get() that rejects asynchronously', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stored', token_type: 'Bearer', refresh_token: 'r1' });

    const asyncRejectingStore = {
      get: async () => {
        throw new Error('async boom');
      },
      set: async () => {},
    } as unknown as { get: () => Promise<number | undefined>; set: () => Promise<void> };

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: asyncRejectingStore,
      onWarning: () => {},
    });

    await expect(wrapped.tokens()).resolves.toMatchObject({ access_token: 'stored' });
  });

  it('saveTokens() survives a set() that throws synchronously', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const syncThrowingStore = {
      get: async () => undefined,
      set() {
        throw new Error('sync boom on write');
      },
    } as unknown as { get: () => Promise<number | undefined>; set: () => Promise<void> };

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: syncThrowingStore,
      onWarning: () => {},
    });

    await expect(
      wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 }),
    ).resolves.toBeUndefined();
    expect((await inner.tokens())?.access_token).toBe('a');
  });
});

// MEDIO-1 (round 6): the FIFO ordering only holds while the store answers within
// storeTimeoutMs. `pendingStoreWrite` is the timeout-bounded promise, not the
// underlying operation, so a write slower than the timeout resolves (as
// abandoned) before it has actually been applied — and then lands after the
// sentinel. This is the documented behaviour, not a silent break; the test pins
// it down so it cannot change unnoticed.
describe('MEDIO-1: write ordering holds only within storeTimeoutMs, as documented', () => {
  function reorderingStore(slowSetMs: number) {
    const values = new Map<string, number>();
    const applied: string[] = [];
    return {
      values,
      applied,
      store: {
        get: async (k: string) => values.get(k),
        set: async (k: string, v: number) => {
          // Sentinel fast, expiry slow — as independent requests behave.
          await new Promise((r) => setTimeout(r, v === 0 ? 1 : slowSetMs));
          values.set(k, v);
          applied.push(v === 0 ? 'sentinel' : 'expiry');
        },
        // no delete() -> sentinel path
      },
    };
  }

  async function runRevokeDuringSave(slowSetMs: number, storeTimeoutMs: number) {
    const { store, values, applied } = reorderingStore(slowSetMs);
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: store,
      resourceKey: 'k',
      storeTimeoutMs,
      onWarning: () => {},
    });

    const save = wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    await new Promise((r) => setImmediate(r));
    await wrapped.invalidateCredentials!('all');
    await save;
    await new Promise((r) => setTimeout(r, slowSetMs + 80));
    return { values, applied };
  }

  it('store faster than the timeout: the sentinel is the last word', async () => {
    const { values, applied } = await runRevokeDuringSave(40, 400);
    expect(applied).toEqual(['expiry', 'sentinel']);
    expect(values.get('k')).toBe(0);
  });

  it('store SLOWER than the timeout: the late write lands after the sentinel — the documented limitation', async () => {
    const { values, applied } = await runRevokeDuringSave(300, 40);

    // This is the behaviour the README documents as the limitation, and the
    // reason it is acceptable: a stale expiry entry, never a redirected
    // credential. Pinned so the README and the code cannot drift apart.
    expect(applied).toEqual(['sentinel', 'expiry']);
    expect(values.get('k')).not.toBe(0);

    // And the impact bound the README relies on: the wrapped provider really
    // did revoke, so the stale entry is inert — tokens() has nothing to judge.
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    expect(await inner.tokens()).toBeUndefined();
  });
});

describe('BAJO-1: error_uri is sanitized like message', () => {
  it('strips control characters from errorUri on a rethrown OAuth error', () => {
    const error = new InvalidGrantError('revoked\nline two', 'https://as.example.com/e\n[FATAL] forged');
    const sanitized = sanitizedCause(error) as Error & { errorUri?: string };

    expect(sanitized).toBeInstanceOf(InvalidGrantError);
    expect(sanitized.message).not.toMatch(/[\n\r]/);
    expect(sanitized.errorUri).toBeDefined();
    expect(sanitized.errorUri).not.toMatch(/[\n\r]/);
    expect(sanitized.errorUri).toContain('forged'); // content kept, control chars stripped
  });

  it('leaves an absent errorUri alone', () => {
    const error = new InvalidGrantError('plain');
    const sanitized = sanitizedCause(error) as Error & { errorUri?: string };
    expect(sanitized.errorUri).toBeUndefined();
  });

  it('end to end: the unwrapped error surfaced from a refresh has a clean errorUri', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify({
          error: 'invalid_grant',
          error_description: 'revoked',
          error_uri: 'https://as.example.com/docs\n[FATAL] forged log line',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: -10,
    });

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }

    const err = caught as Error & { errorUri?: string };
    expect(err).toBeInstanceOf(InvalidGrantError);
    expect(err.errorUri).toBeDefined();
    expect(err.errorUri).not.toMatch(/[\n\r]/);
  });
});

describe('MEDIO-3: a store that works normally is unaffected', () => {
  it('still reads, writes and deletes within the timeout', async () => {
    const values = new Map<string, number>();
    const store = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        values.set(k, v);
      },
      delete: async (k: string) => {
        values.delete(k);
      },
    };

    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      invalidateClearsCredentials: true,
    });
    const warnings: string[] = [];
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AS,
      expiryStore: store,
      resourceKey: 'k',
      storeTimeoutMs: 1000,
      onWarning: (m) => warnings.push(m),
    });

    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    expect(values.get('k')).toBeGreaterThan(Date.now());

    await wrapped.invalidateCredentials!('all');
    expect(values.has('k')).toBe(false);
    expect(warnings).toHaveLength(0);
  });
});
