import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientMetadata } from './helpers.js';

// A3: refuse to send a refresh_token / client_secret to an authorization
// server other than the one the client was actually registered with (or the
// tokens were actually issued by). Without this check, a wrapper misconfigured
// with the wrong authorizationServerUrl — or reused across multiple MCP
// servers — would leak live credentials to an unrelated party.

describe('issuer binding is enforced before refresh (A3)', () => {
  it('refuses to refresh when clientInformation.issuer does not match the configured authorizationServerUrl', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({
      client_id: 'client-1',
      ...testClientMetadata,
      issuer: 'https://real-auth.example.com',
    });
    await inner.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://wrong-auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    // Nothing — not even a request — was sent to any authorization server.
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses to refresh when tokens.issuer does not match the configured authorizationServerUrl', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({ client_id: 'client-1', ...testClientMetadata });
    await inner.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
      issuer: 'https://real-auth.example.com',
    });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://wrong-auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
      issuer: 'https://real-auth.example.com',
    });

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refreshes normally when the issuer matches', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({
      client_id: 'client-1',
      ...testClientMetadata,
      issuer: 'https://auth.example.com',
    });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
      issuer: 'https://auth.example.com',
    });

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('fresh');
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('refreshes normally when neither clientInformation nor tokens carry an issuer stamp (unstamped/legacy storage)', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({ client_id: 'client-1', ...testClientMetadata });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('fresh');
  });

  // B2: the SDK's own fallback authorization server URL (when RFC 9728
  // discovery isn't available) is `String(new URL('/', serverUrl))`, which
  // ALWAYS carries a trailing slash, and that value is exactly what auth()
  // stamps onto saved tokens/client info as `issuer`. A wrapper configured
  // with `authorizationServerUrl: 'https://auth.example.com'` (no trailing
  // slash — the natural way to write it, and what the README's own example
  // shows) must not treat that as a mismatch.
  it('does not treat a trailing-slash difference between the configured authorizationServerUrl and a stamped issuer as a mismatch', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({
      client_id: 'client-1',
      ...testClientMetadata,
      issuer: 'https://auth.example.com/', // as auth.js would stamp it via the RFC 9728 fallback
    });

    const fetchFn = vi.fn(async () =>
      jsonResponse({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 }),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com', // no trailing slash — the natural way to configure it
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
      issuer: 'https://auth.example.com/',
    });

    const result = await wrapped.tokens();
    expect(result?.access_token).toBe('fresh');
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('still catches a genuine issuer mismatch that merely happens to share a trailing slash', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({
      client_id: 'client-1',
      ...testClientMetadata,
      issuer: 'https://real-auth.example.com/',
    });

    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'x', token_type: 'Bearer' }));

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://wrong-auth.example.com/',
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
      issuer: 'https://real-auth.example.com/',
    });

    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  // B1: refreshAuthorization() parses the AS response with a schema that
  // OMITS `issuer` (it's a client-side stamp, never part of the wire
  // response) — mcp-auth-kit must re-stamp it before persisting, or the A3
  // check above disables itself the very first time a refresh happens.
  describe('B1: the issuer stamp survives mcp-auth-kit\'s own refresh, so A3 keeps working afterward', () => {
    it('a refreshed token carries the configured issuer stamp', async () => {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation({
        client_id: 'client-1',
        ...testClientMetadata,
        issuer: 'https://auth.example.com',
      });

      const fetchFn = vi.fn(async () =>
        // Simulates the real SDK behavior: the token endpoint response never
        // includes `issuer` — that's a client-side-only stamp.
        jsonResponse({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 }),
      );

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        fetchFn: fetchFn as unknown as typeof fetch,
      });
      await wrapped.saveTokens({
        access_token: 'expired',
        token_type: 'Bearer',
        refresh_token: 'refresh-1',
        expires_in: -10,
        issuer: 'https://auth.example.com',
      });

      const result = await wrapped.tokens();
      expect(result?.issuer).toBe('https://auth.example.com');
      // And what was actually persisted into the wrapped provider is stamped too.
      expect((await inner.tokens())?.issuer).toBe('https://auth.example.com');
    });

    it('a SECOND refresh still enforces A3 correctly (the stamp was not lost after the first refresh)', async () => {
      const inner = new InMemoryProvider(testClientMetadata);
      inner.presetClientInformation({
        client_id: 'client-1',
        ...testClientMetadata,
        issuer: 'https://auth.example.com',
      });

      let refreshCount = 0;
      const fetchFn = vi.fn(async () => {
        refreshCount += 1;
        return jsonResponse({
          access_token: `fresh-${refreshCount}`,
          token_type: 'Bearer',
          refresh_token: `refresh-${refreshCount + 1}`,
          expires_in: -10, // stays "expired" so every tokens() call refreshes again
        });
      });

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        fetchFn: fetchFn as unknown as typeof fetch,
        minExpiresInSeconds: 1, // allow the deliberately-tiny expires_in above through the clamp
      });
      await wrapped.saveTokens({
        access_token: 'expired',
        token_type: 'Bearer',
        refresh_token: 'refresh-1',
        expires_in: -10,
        issuer: 'https://auth.example.com',
      });

      const first = await wrapped.tokens();
      expect(first?.access_token).toBe('fresh-1');
      expect(first?.issuer).toBe('https://auth.example.com');

      // refreshMarginMs (default 30s) dominates the clamped 1s TTL above, so
      // the freshly-refreshed token is already due for another refresh.
      const second = await wrapped.tokens();
      expect(second?.access_token).toBe('fresh-2');
      expect(second?.issuer).toBe('https://auth.example.com');
      expect(refreshCount).toBe(2);
    });

    it('registering a new client via auto-registration stamps the issuer too', async () => {
      const inner = new InMemoryProvider(testClientMetadata);
      const fetchFn = vi.fn(async () =>
        jsonResponse({ client_id: 'dcr-client-id', ...testClientMetadata }),
      );

      const wrapped = wrapOAuthClientProvider(inner, {
        authorizationServerUrl: 'https://auth.example.com',
        fetchFn: fetchFn as unknown as typeof fetch,
        registration: { maxAttempts: 1 },
      });

      const info = await wrapped.clientInformation();
      expect(info?.issuer).toBe('https://auth.example.com');
      expect((await inner.clientInformation())?.issuer).toBe('https://auth.example.com');
    });
  });
});
