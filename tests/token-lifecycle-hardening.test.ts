import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

describe('M6: saveTokens persists before advancing the in-memory expiry clock', () => {
  it('does not advance expiresAt if the wrapped provider fails to persist', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.saveTokens = () => {
      throw new Error('disk full');
    };

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
    });

    await expect(
      wrapped.saveTokens({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 }),
    ).rejects.toThrow('disk full');

    // Since the write failed, the wrapper must not believe it has a token
    // that's valid for the next hour. With no tokens ever actually stored,
    // inner.tokens() returns undefined and tokens() must reflect that
    // rather than fabricating a fresh expiry window around nothing.
    inner.saveTokens = InMemoryProvider.prototype.saveTokens;
    expect(await wrapped.tokens()).toBeUndefined();
  });

  it('a successful save does advance the expiry clock as expected', async () => {
    vi.useFakeTimers();
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);
      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
      });

      await wrapped.saveTokens({
        access_token: 'a',
        token_type: 'Bearer',
        refresh_token: 'r1',
        expires_in: 3600,
      });

      vi.advanceTimersByTime(1000); // well within the 1h window
      const stillValid = await wrapped.tokens();
      expect(stillValid?.access_token).toBe('a');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('M7: a hung authorization server times out instead of hanging the client', () => {
  it('aborts a refresh request that never resolves once timeoutMs elapses', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    // A server that never responds: the fetch promise only ever settles via
    // the AbortSignal mcp-auth-kit attaches for its timeout.
    const fetchFn = vi.fn((_url: string | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted', 'AbortError'));
        });
      });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
      timeoutMs: 20, // real timers, kept tiny so the test stays fast
    });

    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});

describe('M8: server-supplied expires_in is clamped to a sane range', () => {
  it('clamps a zero/negative expires_in up to the configured minimum instead of refreshing on every call', async () => {
    vi.useFakeTimers();
    try {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation(testClientInformation);

      let refreshCount = 0;
      const fetchFn = vi.fn(async () => {
        refreshCount += 1;
        return jsonResponse({ access_token: `t${refreshCount}`, token_type: 'Bearer', expires_in: 3600 });
      });

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        fetchFn: fetchFn as unknown as typeof fetch,
        minExpiresInSeconds: 60,
        refreshMarginMs: 1000,
      });

      await wrapped.saveTokens({
        access_token: 'a',
        token_type: 'Bearer',
        refresh_token: 'r1',
        expires_in: 0,
      });

      // Clamped to 60s TTL, 1s margin: should NOT need a refresh yet at t=+10s.
      vi.advanceTimersByTime(10_000);
      await wrapped.tokens();
      expect(refreshCount).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clamps an unreasonably large expires_in down to the configured maximum', async () => {
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
        maxExpiresInSeconds: 100,
        refreshMarginMs: 1000,
      });

      await wrapped.saveTokens({
        access_token: 'a',
        token_type: 'Bearer',
        refresh_token: 'r1',
        expires_in: 999_999_999, // a server claiming this token is valid for ~31 years
      });

      // Clamped to 100s: at t=+150s this must be treated as expired and refreshed.
      vi.advanceTimersByTime(150_000);
      const result = await wrapped.tokens();
      expect(result?.access_token).toBe('refreshed');
      expect(fetchFn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
