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
});
