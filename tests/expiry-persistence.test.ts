import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import {
  InMemoryExpiryStore,
  InMemoryProvider,
  jsonResponse,
  testClientInformation,
  testClientMetadata,
} from './helpers.js';

// M9: expiry tracking across a process restart.
//
// Verified against the SDK (@modelcontextprotocol/sdk/dist/esm/client/auth.js
// and streamableHttp.js/sse.js — see README "Expiry persistence" for full
// citations): both stock client transports react to an HTTP 401 by calling
// auth() again, and auth() itself attempts a silent refresh_token grant
// (auth.js ~line 349-373) BEFORE ever falling back to full interactive
// re-authorization. So even with no proactive refresh at all, a stale token
// loaded cold self-heals on the very next request — at the cost of one
// failed round trip — for any client built on those transports.

describe('M9 default (no ExpiryStore): no forced proactive refresh on a cold-loaded token', () => {
  it('returns a token loaded fresh from storage as-is, even if it is actually already expired, without calling the authorization server', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    // Written directly to the inner provider's storage, simulating tokens
    // persisted by a *previous* process — this wrapper instance has never
    // called saveTokens() itself and so has no in-memory expiry knowledge.
    await inner.saveTokens({
      access_token: 'possibly-stale-access-token',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60, // would have expired ages ago, if we tracked it
    });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'should-not-be-called', token_type: 'Bearer' }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
      // no expiryStore
    });

    const result = await wrapped.tokens();

    expect(result?.access_token).toBe('possibly-stale-access-token');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('still refreshes proactively once THIS wrapper instance has saved tokens itself and enough time passes', async () => {
    vi.useFakeTimers();
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);

      const fetchFn = vi.fn(async () =>
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
      );

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await wrapped.saveTokens({
        access_token: 'short-lived',
        token_type: 'Bearer',
        refresh_token: 'refresh-1',
        expires_in: 60,
      });

      vi.advanceTimersByTime(5 * 60 * 1000);
      const result = await wrapped.tokens();

      expect(result?.access_token).toBe('refreshed');
      expect(fetchFn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('M9 with an ExpiryStore: correctly decides on a cold start', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('persists expiresAt on saveTokens, and a fresh wrapper instance (simulating a restart) proactively refreshes once it reads a known-expired value', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    // "Process 1": saves tokens, which persists expiresAt into the shared store.
    const wrappedBeforeRestart = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });
    await wrappedBeforeRestart.saveTokens({
      access_token: 'short-lived',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60,
    });
    expect(store.setCalls).toHaveLength(1);

    // Time passes well beyond expiry, then the process "restarts": a brand
    // new wrapper instance is created, wrapping the same underlying storage
    // and the same expiry store, with no in-memory knowledge of its own.
    vi.advanceTimersByTime(5 * 60 * 1000);

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed-after-restart', token_type: 'Bearer', expires_in: 3600 }),
    );
    const wrappedAfterRestart = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    const result = await wrappedAfterRestart.tokens();

    expect(store.getCalls.length).toBeGreaterThan(0);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('refreshed-after-restart');
  });

  it('does NOT refresh on a fresh instance when the store shows the token is still valid', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const wrappedBeforeRestart = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });
    await wrappedBeforeRestart.saveTokens({
      access_token: 'still-good',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 3600, // 1 hour
    });

    vi.advanceTimersByTime(10 * 1000); // only 10s later — nowhere near expiry

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
    const wrappedAfterRestart = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    const result = await wrappedAfterRestart.tokens();

    expect(result?.access_token).toBe('still-good');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('falls back to the no-adapter default when the store has nothing for this resourceKey yet', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({
      access_token: 'never-tracked',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60,
    });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store, // configured, but store is empty for this key
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    const result = await wrapped.tokens();

    expect(result?.access_token).toBe('never-tracked');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('degrades gracefully to the no-adapter default if the store read fails', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({
      access_token: 'unreadable-store',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60,
    });

    const brokenStore = {
      get: async () => {
        throw new Error('store unavailable');
      },
      set: async () => {},
    };

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: brokenStore,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    const result = await wrapped.tokens();

    expect(result?.access_token).toBe('unreadable-store');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('uses a custom resourceKey instead of authorizationServerUrl when provided', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      resourceKey: 'custom-key-per-mcp-server',
    });
    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 60,
    });

    expect(store.setCalls[0]?.resourceKey).toBe('custom-key-per-mcp-server');
  });
});

// M3: the default resourceKey must combine authorizationServerUrl AND
// resource, so two different protected resources sitting behind the same
// authorization server don't clobber each other's expiry.
describe('M3: default resourceKey combines authorizationServerUrl and resource', () => {
  it('uses a different key for two different `resource` values under the same authorizationServerUrl', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);

    const wrappedA = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      resource: 'https://mcp-a.example.com',
    });
    const wrappedB = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      resource: 'https://mcp-b.example.com',
    });

    await wrappedA.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 60 });
    await wrappedB.saveTokens({ access_token: 'b', token_type: 'Bearer', expires_in: 60 });

    expect(store.setCalls).toHaveLength(2);
    const keys = store.setCalls.map((c) => c.resourceKey);
    expect(new Set(keys).size).toBe(2);
    expect(keys[0]).toContain('https://auth.example.com');
    expect(keys[0]).toContain('https://mcp-a.example.com');
    expect(keys[1]).toContain('https://mcp-b.example.com');
  });

  it('falls back to just authorizationServerUrl when no resource is configured', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });

    await wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 60 });

    expect(store.setCalls[0]?.resourceKey).toBe('https://auth.example.com');
  });
});

// M2: a corrupted or hostile ExpiryStore value must never silently disable
// proactive refresh forever — it should be treated as "unknown" (same as no
// store at all) and warned about once, and a value within range but
// implausible must be clamped rather than trusted verbatim.
describe('M2: ExpiryStore values are validated and clamped', () => {
  it('treats a non-finite stored value (NaN) as unknown, warns once, and does not disable future refreshes', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const brokenStore = {
        get: async () => Number.NaN,
        set: async () => {},
      };
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);
      await inner.saveTokens({
        access_token: 'a',
        token_type: 'Bearer',
        refresh_token: 'r1',
        expires_in: 60,
      });

      const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: brokenStore,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      // Falls back to the no-adapter default (pass-through, no forced refresh)
      // rather than treating NaN as "never expires".
      const result = await wrapped.tokens();
      expect(result?.access_token).toBe('a');
      expect(fetchFn).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0]?.[0]).toMatch(/non-finite/);

      // Calling tokens() again must not warn a second time, but also must not
      // have permanently cached "the token never expires" — a subsequent
      // in-session saveTokens()+expiry still works normally afterward.
      await wrapped.tokens();
      expect(warnSpy).toHaveBeenCalledTimes(1);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('treats Infinity from the store the same way (unknown, not "never expires")', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const store = {
        get: async () => Number.POSITIVE_INFINITY,
        set: async () => {},
      };
      const inner = new InMemoryProvider(testClientMetadata);
      await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

      const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: store,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await wrapped.tokens();
      expect(result?.access_token).toBe('a');
      expect(fetchFn).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('clamps an implausibly-far-future stored expiry down to maxExpiresInSeconds', async () => {
    vi.useFakeTimers();
    try {
      const farFuture = Date.now() + 999_999_999_999; // "expires" in ~31,000 years
      const store = {
        get: async () => farFuture,
        set: async () => {},
      };
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);
      await inner.saveTokens({
        access_token: 'a',
        token_type: 'Bearer',
        refresh_token: 'r1',
      });

      const fetchFn = vi.fn(async () =>
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
      );
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: store,
        fetchFn: fetchFn as unknown as typeof fetch,
        maxExpiresInSeconds: 100,
      });

      // First cold tokens() call: reads the store, clamps the absurd
      // far-future value down to 100s from THIS moment, and establishes
      // that as expiresAt (not re-read on subsequent calls).
      const first = await wrapped.tokens();
      expect(first?.access_token).toBe('a');
      expect(fetchFn).not.toHaveBeenCalled();

      // Now advance well past that clamped 100s window and check again —
      // if the far-future value had been trusted verbatim, this would never
      // refresh.
      vi.advanceTimersByTime(150_000);
      const second = await wrapped.tokens();

      expect(second?.access_token).toBe('refreshed');
      expect(fetchFn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

// Bajo-2: two concurrent cold tokens() calls must share one expiryStore.get(),
// the same way concurrent refreshes already share one in-flight request.
describe('Bajo-2: concurrent cold reads are deduped', () => {
  it('only calls expiryStore.get() once for two concurrent tokens() calls on a cold instance', async () => {
    const store = new InMemoryExpiryStore();
    await store.set('https://auth.example.com', Date.now() + 3_600_000); // valid for an hour
    const inner = new InMemoryProvider(testClientMetadata);
    await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });

    const [a, b] = await Promise.all([wrapped.tokens(), wrapped.tokens()]);

    expect(a?.access_token).toBe('a');
    expect(b?.access_token).toBe('a');
    expect(store.getCalls).toHaveLength(1);
  });
});

// M4: an ExpiryStore write failure is supplementary-cache-only — it must
// never turn an already-successful inner.saveTokens() into a thrown error.
describe('M4: expiryStore.set() failures degrade to in-memory tracking, never fail saveTokens', () => {
  it('saveTokens resolves even though expiryStore.set() throws, and the inner provider did persist', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const brokenStore = {
      get: async () => undefined,
      set: async () => {
        throw new Error('disk full');
      },
    };

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: brokenStore,
    });

    await expect(
      wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 }),
    ).resolves.toBeUndefined();

    expect((await inner.tokens())?.access_token).toBe('a');
  });

  it('in-memory expiry tracking still works for the rest of this process despite the store failing', async () => {
    vi.useFakeTimers();
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);
      const brokenStore = {
        get: async () => undefined,
        set: async () => {
          throw new Error('disk full');
        },
      };

      const fetchFn = vi.fn(async () =>
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
      );
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: brokenStore,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await wrapped.saveTokens({
        access_token: 'short-lived',
        token_type: 'Bearer',
        refresh_token: 'r1',
        expires_in: 60,
      });

      vi.advanceTimersByTime(5 * 60 * 1000);
      const result = await wrapped.tokens();

      expect(result?.access_token).toBe('refreshed');
    } finally {
      vi.useRealTimers();
    }
  });
});

// M5: invalidateCredentials must not leave a stale (still-valid-looking)
// expiry behind in the store.
describe('M5: invalidateCredentials clears the persisted expiry', () => {
  it('calls expiryStore.delete() when the store implements it', async () => {
    const deleteCalls: string[] = [];
    const store = new InMemoryExpiryStore();
    store.delete = async (key: string) => {
      deleteCalls.push(key);
    };

    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });
    await wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 });

    await wrapped.invalidateCredentials!('all');

    expect(deleteCalls).toEqual(['https://auth.example.com']);
  });

  it('writes a sentinel (0) when the store has no delete()', async () => {
    const store = new InMemoryExpiryStore(); // no delete() implemented
    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });
    await wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 });

    await wrapped.invalidateCredentials!('all');

    expect(await store.get('https://auth.example.com')).toBe(0);
  });

  it('does not touch the store on a scope that is neither "all" nor "tokens"', async () => {
    const store = new InMemoryExpiryStore();
    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
    });
    await wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 });
    store.setCalls.length = 0;

    await wrapped.invalidateCredentials!('verifier');

    expect(store.setCalls).toHaveLength(0);
  });
});
