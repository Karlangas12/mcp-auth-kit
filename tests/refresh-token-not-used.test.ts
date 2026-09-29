import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// Reproduces openai/codex#17265: the server issues a valid refresh_token
// alongside expires_in, but the client never calls the refresh grant with
// it once the access token expires — it just keeps using (or failing with)
// the stale access token.

describe('refresh_token is actually used once the access token expires (codex#17265)', () => {
  const authorizationServerUrl = 'https://auth.example.com';

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('a bare provider has a refresh_token available but never uses it', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    await inner.saveTokens({
      access_token: 'short-lived',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60,
    });

    vi.advanceTimersByTime(5 * 60 * 1000); // 5 minutes later, well past expiry

    // A bare provider has no concept of "expired" — it just returns what
    // was stored, forcing every downstream request to fail with 401.
    const stillExpired = await inner.tokens();
    expect(stillExpired?.access_token).toBe('short-lived');
  });

  it('mcp-auth-kit calls the refresh grant automatically once expires_in elapses', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body));
      expect(body.get('grant_type')).toBe('refresh_token');
      expect(body.get('refresh_token')).toBe('refresh-1');
      return jsonResponse({
        access_token: 'renewed',
        token_type: 'Bearer',
        refresh_token: 'refresh-2',
        expires_in: 3600,
      });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
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

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(result?.access_token).toBe('renewed');
  });

  it('concurrent tokens() calls during expiry share a single refresh request', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    let fetchCount = 0;
    const fetchFn = vi.fn(async () => {
      fetchCount += 1;
      return jsonResponse({
        access_token: 'renewed',
        token_type: 'Bearer',
        refresh_token: 'refresh-2',
        expires_in: 3600,
      });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    await wrapped.saveTokens({
      access_token: 'short-lived',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: 60,
    });

    vi.advanceTimersByTime(5 * 60 * 1000);

    const [a, b, c] = await Promise.all([wrapped.tokens(), wrapped.tokens(), wrapped.tokens()]);

    expect(fetchCount).toBe(1);
    expect(a?.access_token).toBe('renewed');
    expect(b?.access_token).toBe('renewed');
    expect(c?.access_token).toBe('renewed');
  });
});
