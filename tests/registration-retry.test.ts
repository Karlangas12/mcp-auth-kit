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

  // M10: a definitive rejection (bad client metadata) will fail identically
  // no matter how many times it's retried — retrying just wastes time and
  // hammers the server.
  it('does not retry a definitive 400 invalid_client_metadata rejection', async () => {
    const fetchFn = vi.fn(async () => errorResponse(400, 'invalid_client_metadata'));

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

    await expect(wrapped.clientInformation()).rejects.toMatchObject({
      phase: 'client_registration',
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('does not retry unauthorized_client either', async () => {
    const fetchFn = vi.fn(async () => errorResponse(401, 'unauthorized_client'));

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 5, baseDelayMs: 1, sleep: () => Promise.resolve() },
    });

    await expect(wrapped.clientInformation()).rejects.toMatchObject({
      phase: 'client_registration',
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('retries a network failure (no HTTP response at all)', async () => {
    let attempts = 0;
    const fetchFn = vi.fn(async () => {
      attempts += 1;
      if (attempts < 2) throw new TypeError('network error');
      return jsonResponse({ client_id: 'recovered-client-id', ...testClientMetadata });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 3, baseDelayMs: 1, sleep: () => Promise.resolve() },
    });

    const info = await wrapped.clientInformation();
    expect(info?.client_id).toBe('recovered-client-id');
    expect(attempts).toBe(2);
  });

  // A5: mcp-auth-kit must refuse to auto-register a client it cannot persist,
  // rather than silently discarding the registration on every call (which
  // would re-register a brand new client with the AS every single time).
  it('refuses to enable auto-registration against a provider with no saveClientInformation', () => {
    const inner = new InMemoryProvider(testClientMetadata, { canSaveClientInformation: false });

    expect(() =>
      wrapOAuthClientProvider(inner, {
        authorizationServerUrl,
        registration: { maxAttempts: 3 },
      }),
    ).toThrow(/saveClientInformation/);
  });

  it('does not define saveClientInformation on the wrapper when the inner provider has none', () => {
    const inner = new InMemoryProvider(testClientMetadata, { canSaveClientInformation: false });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    expect(wrapped.saveClientInformation).toBeUndefined();
  });
});
