import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// Bajo-7 (round 3): a refresh_token the authorization server has definitively
// rejected (invalid_grant) will be rejected identically every time. Without a
// negative cache, every tokens() call launches another doomed request — and
// with the timeout in place, a hung server makes each one cost up to
// `timeoutMs`. Transient failures must NOT be cached.

function oauthErrorResponse(error: string, status = 400) {
  return new Response(JSON.stringify({ error, error_description: `${error} description` }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function seedExpiredTokens(wrapped: ReturnType<typeof wrapOAuthClientProvider>) {
  await wrapped.saveTokens({
    access_token: 'expired',
    token_type: 'Bearer',
    refresh_token: 'r1',
    expires_in: -10,
  });
}

describe('Bajo-7: a definitively-failed refresh is not retried within the failure-cache window', () => {
  it('hits the authorization server once, then short-circuits subsequent attempts', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () => oauthErrorResponse('invalid_grant'));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).toHaveBeenCalledTimes(1);

    // Second and third attempts must not reach the network at all.
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('the short-circuit error explains itself and preserves the original cause', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () => oauthErrorResponse('invalid_grant'));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }
    const err = caught as Error & { cause?: unknown; phase?: string };
    expect(err.phase).toBe('token_refresh');
    expect(err.message).toMatch(/failure-cache window/);
    expect((err.cause as Error)?.message).toMatch(/invalid_grant/);
  });

  it('does NOT cache a transient failure (server_error stays retryable)', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () => oauthErrorResponse('server_error', 500));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });

    // Both attempts reached the server: a transient failure may well succeed
    // on the next try, so suppressing it would be wrong.
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('does NOT cache our own timeout (an abort is transient on the refresh path)', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

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
      timeoutMs: 20,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('the window lapses after refreshFailureCacheMs', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () => oauthErrorResponse('invalid_grant'));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
      refreshFailureCacheMs: 20,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await new Promise((resolve) => setTimeout(resolve, 40));

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('invalidateCredentials() clears the window immediately', async () => {
    const inner = new InMemoryProvider(testClientMetadata, { canInvalidateCredentials: true });
    inner.presetClientInformation(testClientInformation);

    const fetchFn = vi.fn(async () => oauthErrorResponse('invalid_grant'));
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await wrapped.invalidateCredentials!('tokens');
    // Re-seed (invalidation cleared the wrapper's expiry knowledge).
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('a successful saveTokens() clears the window', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);

    let failNext = true;
    const fetchFn = vi.fn(async () => {
      if (failNext) return oauthErrorResponse('invalid_grant');
      return jsonResponse({ access_token: 'ok', token_type: 'Bearer', expires_in: 3600 });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await seedExpiredTokens(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(1);

    // A fresh authorization elsewhere stores new tokens through the wrapper.
    failNext = false;
    await seedExpiredTokens(wrapped);

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('ok');
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});
