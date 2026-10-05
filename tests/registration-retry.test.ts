import { describe, expect, it, vi } from 'vitest';
import { registerClient } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import {
  InMemoryProvider,
  errorResponse,
  jsonResponse,
  advertisedRegistrationEndpoint,
  routeDiscovery,
  testClientMetadata,
} from './helpers.js';

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
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
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
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
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
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
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
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
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
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
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

// ---------------------------------------------------------------------------
// BAJO-6. Auto-registration called registerClient with no `metadata`, so the
// SDK fell back to `new URL('/register', authorizationServerUrl)` — discarding
// any path in the configured URL and ignoring whatever the server advertises.
// Against an AS whose registration endpoint is elsewhere, the POST 404'd, the
// 404 classified as transient and was retried, and the caller was then told to
// "verify the authorization server advertises a registration_endpoint" — which
// it did, and which this package never read.
// ---------------------------------------------------------------------------
describe('BAJO-6: auto-registration posts to the advertised registration_endpoint', () => {
  const authorizationServerUrl = 'https://auth.example.com';

  it('uses the endpoint from discovery, not a guessed /register', async () => {
    const posted: string[] = [];
    const register = vi.fn(async (url: string | URL) => {
      posted.push(String(url));
      return jsonResponse({ client_id: 'from-advertised-endpoint', ...testClientMetadata });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: routeDiscovery(register as never) as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    const info = await wrapped.clientInformation();
    expect((info as { client_id?: string })?.client_id).toBe('from-advertised-endpoint');
    expect(posted).toEqual([advertisedRegistrationEndpoint]);
    // The guess the SDK falls back to without metadata.
    expect(posted[0]).not.toBe('https://auth.example.com/register');
  });

  it('keeps a path in authorizationServerUrl instead of dropping it', async () => {
    // The concrete regression: a per-tenant issuer. Without metadata the POST
    // went to the origin root and lost /tenantX entirely.
    const posted: string[] = [];
    const register = vi.fn(async (url: string | URL) => {
      posted.push(String(url));
      return jsonResponse({ client_id: 'tenant-client', ...testClientMetadata });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://login.example.com/tenantX',
      fetchFn: routeDiscovery(register as never, {
        registrationEndpoint: 'https://login.example.com/tenantX/register',
      }) as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    await wrapped.clientInformation();
    expect(posted).toEqual(['https://login.example.com/tenantX/register']);
  });

  it('says so plainly when the server advertises no registration_endpoint', async () => {
    const register = vi.fn(async () => jsonResponse({ client_id: 'never' }));
    const noEndpoint = async (url: string | URL, init?: RequestInit) => {
      if (String(url).includes('/.well-known/')) {
        // Discovery succeeds, and the document states no DCR support.
        return jsonResponse({
          issuer: authorizationServerUrl,
          authorization_endpoint: `${authorizationServerUrl}/authorize`,
          token_endpoint: `${authorizationServerUrl}/token`,
          response_types_supported: ['code'],
        });
      }
      return register(url, init);
    };

    const wrapped = wrapOAuthClientProvider(new InMemoryProvider(testClientMetadata), {
      authorizationServerUrl,
      fetchFn: noEndpoint as unknown as typeof fetch,
      registration: { maxAttempts: 3, baseDelayMs: 1 },
    });

    await expect(wrapped.clientInformation()).rejects.toMatchObject({
      phase: 'client_registration',
    });
    // No doomed POST to a guessed URL, and no retries of its 404 — which is
    // what used to produce "verify the server advertises a registration_endpoint"
    // against a server that genuinely does not support registration.
    expect(register).not.toHaveBeenCalled();
  });

  it('still works against a server with no metadata document at all', async () => {
    // Discovery failing must not break a server that only has the
    // conventional endpoint — that fallback is the SDK's, and it stays.
    const posted: string[] = [];
    const register = vi.fn(async (url: string | URL) => {
      posted.push(String(url));
      return jsonResponse({ client_id: 'fallback-client', ...testClientMetadata });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl,
      fetchFn: routeDiscovery(register as never, {
        registrationEndpoint: null,
      }) as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    const info = await wrapped.clientInformation();
    expect((info as { client_id?: string })?.client_id).toBe('fallback-client');
    expect(posted).toEqual(['https://auth.example.com/register']);
  });
});
