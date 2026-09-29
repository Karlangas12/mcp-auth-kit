import { describe, expect, it, vi } from 'vitest';
import { registerClient } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, errorResponse, jsonResponse, testClientMetadata } from './helpers.js';

// Reproduces openai/codex#13200: dynamic client registration fails once
// (transient 500, or a server that is briefly unready) and the client gives
// up immediately with "Dynamic client registration not supported" instead of
// retrying.

describe('dynamic client registration retry (openai/codex#13200)', () => {
  const authorizationServerUrl = 'https://auth.example.com';

  it('a single unretried registration call fails on a transient server error', async () => {
    const fetchFn = vi.fn(async () => errorResponse(500, 'server_error'));

    await expect(
      registerClient(authorizationServerUrl, {
        clientMetadata: testClientMetadata,
        fetchFn: fetchFn as unknown as typeof fetch,
      }),
    ).rejects.toThrow();

    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('mcp-auth-kit retries with backoff and succeeds once the server recovers', async () => {
    let attempts = 0;
    const fetchFn = vi.fn(async () => {
      attempts += 1;
      if (attempts < 3) return errorResponse(500, 'server_error');
      return jsonResponse({
        client_id: 'registered-client-id',
        ...testClientMetadata,
      });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      registration: {
        maxAttempts: 5,
        baseDelayMs: 1,
        maxDelayMs: 5,
        sleep: () => Promise.resolve(),
      },
    });

    const info = await wrapped.clientInformation();

    expect(attempts).toBe(3);
    expect(info?.client_id).toBe('registered-client-id');
    // The successful registration is persisted back to the wrapped provider.
    expect(await inner.clientInformation()).toMatchObject({ client_id: 'registered-client-id' });
  });

  it('throws a typed, actionable error once retries are exhausted', async () => {
    const fetchFn = vi.fn(async () => errorResponse(500, 'server_error'));

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      registration: {
        maxAttempts: 3,
        baseDelayMs: 1,
        maxDelayMs: 5,
        sleep: () => Promise.resolve(),
      },
    });

    await expect(wrapped.clientInformation()).rejects.toMatchObject({
      name: 'McpAuthKitError',
      phase: 'client_registration',
    });
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });
});
