import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import {
  InMemoryExpiryStore,
  InMemoryProvider,
  jsonResponse,
  testClientInformation,
  testClientMetadata,
} from './helpers.js';

// ---------------------------------------------------------------------------
// B4 (round 3, BLOCKER): the minimum clamp must NOT apply to an absolute
// timestamp read back from the store. A past timestamp is not a malformed
// duration — it is the store reporting the token is already expired, and
// `expiresAt = 0` is specifically the revocation sentinel M5 writes.
//
// Every test below deliberately uses a config where the old (min-clamped)
// behavior yielded "valid for another minExpiresInSeconds". With the defaults
// (min 30s, margin 30000ms) the two cancel each other exactly and the bug is
// invisible — which is why it survived two review rounds.
// ---------------------------------------------------------------------------
describe('B4: a stored absolute expiry in the past is honoured, never clamped forward', () => {
  it('treats the M5 revocation sentinel (expiresAt = 0) as expired on read-back, not as valid', async () => {
    const store = new InMemoryExpiryStore();
    await store.set('https://auth.example.com', 0); // exactly what invalidateCredentials() writes

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'revoked', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      // Margin below minExpiresInSeconds*1000: with the old clamp the sentinel
      // read back as "valid for another 30s" and no refresh happened at all.
      refreshMarginMs: 5_000,
    });

    const result = await wrapped.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('refreshed');
  });

  it('treats a timestamp that expired an hour ago as expired, under a small refreshMarginMs', async () => {
    const store = new InMemoryExpiryStore();
    await store.set('https://auth.example.com', Date.now() - 60 * 60 * 1000);

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stale', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      refreshMarginMs: 5_000,
    });

    const result = await wrapped.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('refreshed');
  });

  it('treats an expired stored timestamp as expired under a raised minExpiresInSeconds too', async () => {
    const store = new InMemoryExpiryStore();
    await store.set('https://auth.example.com', Date.now() - 60 * 60 * 1000);

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'stale', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      // min (300s) far above the default margin (30s): the old clamp claimed
      // five more minutes of validity for a token that expired an hour ago.
      minExpiresInSeconds: 300,
    });

    const result = await wrapped.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('refreshed');
  });

  it('full round trip: invalidateCredentials() writes the sentinel and a fresh wrapper reads it as expired', async () => {
    const store = new InMemoryExpiryStore(); // no delete() -> sentinel path
    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    inner.presetClientInformation(testClientInformation);

    const wrappedBefore = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      refreshMarginMs: 5_000,
    });
    await wrappedBefore.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r1',
      expires_in: 3600,
    });
    await wrappedBefore.invalidateCredentials!('all');
    expect(await store.get('https://auth.example.com')).toBe(0);

    // "Process restart": a brand new wrapper over the same store must read
    // that sentinel as expired and refresh, not serve the old token.
    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
    );
    const wrappedAfter = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      refreshMarginMs: 5_000,
    });

    const result = await wrappedAfter.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('refreshed');
  });

  it('still caps an implausibly-far-future stored timestamp (upper bound retained on this path)', async () => {
    vi.useFakeTimers();
    try {
      const store = new InMemoryExpiryStore();
      await store.set('https://auth.example.com', Date.now() + 999_999_999_999);

      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);
      await inner.saveTokens({ access_token: 'a', token_type: 'Bearer', refresh_token: 'r1' });

      const fetchFn = vi.fn(async () =>
        jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
      );
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: store,
        fetchFn: fetchFn as unknown as typeof fetch,
        maxExpiresInSeconds: 100,
        refreshMarginMs: 1_000,
      });

      const first = await wrapped.tokens();
      expect(first?.access_token).toBe('a');
      expect(fetchFn).not.toHaveBeenCalled();

      vi.advanceTimersByTime(150_000);
      const second = await wrapped.tokens();
      expect(second?.access_token).toBe('refreshed');
      expect(fetchFn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a stored timestamp still in the future is honoured verbatim (no refresh)', async () => {
    const store = new InMemoryExpiryStore();
    await store.set('https://auth.example.com', Date.now() + 60 * 60 * 1000);

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'still-good', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: store,
      fetchFn: fetchFn as unknown as typeof fetch,
      refreshMarginMs: 5_000,
    });

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('still-good');
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// M11: a store read already in flight when invalidateCredentials() runs must
// not write its (pre-invalidation) result over the state just cleared.
// ---------------------------------------------------------------------------
describe('M11: an in-flight expiry load is discarded if credentials are invalidated meanwhile', () => {
  it('does not resurrect a pre-invalidation expiry, so the next call still sees the invalidated state', async () => {
    let releaseGet: (value: number) => void = () => {};
    const gate = new Promise<number>((resolve) => {
      releaseGet = resolve;
    });

    const values = new Map<string, number>();
    let firstGet = true;
    const slowStore = {
      get: async (key: string): Promise<number | undefined> => {
        if (firstGet) {
          firstGet = false;
          return gate; // blocks until releaseGet() is called
        }
        return values.get(key);
      },
      set: async (key: string, value: number): Promise<void> => {
        values.set(key, value);
      },
      // deliberately no delete() -> invalidateCredentials writes the 0 sentinel
    };

    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({ access_token: 'a', token_type: 'Bearer', refresh_token: 'r1' });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'refreshed', token_type: 'Bearer', expires_in: 3600 }),
    );
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      expiryStore: slowStore,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    // Start a cold tokens() whose store read blocks on `gate`.
    const inFlight = wrapped.tokens();
    await Promise.resolve();

    // Invalidate while that read is still in flight (writes the 0 sentinel).
    await wrapped.invalidateCredentials!('all');

    // Now let the stale read resolve, claiming the token is valid for an hour.
    releaseGet(Date.now() + 60 * 60 * 1000);
    await inFlight;

    // Decisive: if that stale "valid for 1h" value had been adopted, the
    // wrapper would consider expiry known-and-future and never refresh again.
    // Discarding it means the next call re-reads the store, finds the
    // sentinel, and refreshes.
    const second = await wrapped.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(second?.access_token).toBe('refreshed');
  });
});

// ---------------------------------------------------------------------------
// M12 / M13: the one warning the package emits must be sanitized, and must be
// routable and silenceable.
// ---------------------------------------------------------------------------
describe('M12/M13: the expiry-store warning is sanitized and injectable', () => {
  it('M13: routes the warning to onWarning instead of console.warn when provided', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const warnings: string[] = [];
      const inner = new InMemoryProvider(testClientMetadata);
      await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: { get: async () => Number.NaN, set: async () => {} },
        onWarning: (message) => warnings.push(message),
      });

      await wrapped.tokens();

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/non-finite/);
      expect(consoleSpy).not.toHaveBeenCalled();
    } finally {
      consoleSpy.mockRestore();
    }
  });

  it('M13: a no-op onWarning silences the warning entirely', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: { get: async () => Number.NaN, set: async () => {} },
        onWarning: () => {},
      });

      await wrapped.tokens();
      expect(consoleSpy).not.toHaveBeenCalled();
    } finally {
      consoleSpy.mockRestore();
    }
  });

  it('M13: still defaults to console.warn when onWarning is not supplied', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        expiryStore: { get: async () => Number.NaN, set: async () => {} },
      });

      await wrapped.tokens();
      expect(consoleSpy).toHaveBeenCalledTimes(1);
    } finally {
      consoleSpy.mockRestore();
    }
  });

  it('M12: strips control characters from the resourceKey before it reaches the warning', async () => {
    const warnings: string[] = [];
    const inner = new InMemoryProvider(testClientMetadata);
    await inner.saveTokens({ access_token: 'a', token_type: 'Bearer' });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      // A resourceKey carrying server-influenced text with a forged log line.
      resourceKey: 'https://mcp.example.com\n[FATAL] forged log line\r\nadmin=true',
      expiryStore: { get: async () => Number.NaN, set: async () => {} },
      onWarning: (message) => warnings.push(message),
    });

    await wrapped.tokens();

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toMatch(/[\n\r]/);
    // Content is preserved; only the control characters are stripped.
    expect(warnings[0]).toContain('forged log line');
  });
});
