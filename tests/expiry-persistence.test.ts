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
