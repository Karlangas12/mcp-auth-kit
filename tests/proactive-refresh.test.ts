import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// Reproduces anthropics/claude-code#26281: the authorization server's token
// response omits `expires_in`. A provider with no TTL fallback never learns
// the token is stale and reuses it forever — mcp-auth-kit must not.

describe('proactive refresh when expires_in is missing (claude-code#26281)', () => {
  const authorizationServerUrl = 'https://auth.example.com';

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('a bare provider keeps returning the same token forever with no expires_in', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({
      access_token: 'stale-access-token',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      // no expires_in, per the bug report
    });

    vi.advanceTimersByTime(6 * 60 * 60 * 1000); // 6 hours later

    const stillStale = await inner.tokens();
    expect(stillStale?.access_token).toBe('stale-access-token');
  });

  it('mcp-auth-kit proactively refreshes once the fallback TTL elapses', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body));
      expect(body.get('grant_type')).toBe('refresh_token');
      expect(body.get('refresh_token')).toBe('refresh-1');
      return jsonResponse({
        access_token: 'fresh-access-token',
        token_type: 'Bearer',
        refresh_token: 'refresh-2',
        expires_in: 3600,
      });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      fallbackTokenTtlMs: 60 * 60 * 1000, // 1 hour, since the server never tells us
    });

    await wrapped.saveTokens({
      access_token: 'stale-access-token',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      // no expires_in
    });

    vi.advanceTimersByTime(2 * 60 * 60 * 1000); // well past the fallback TTL

    const result = await wrapped.tokens();

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('fresh-access-token');
    expect(result?.refresh_token).toBe('refresh-2');
  });
});
