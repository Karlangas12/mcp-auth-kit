import { describe, expect, it, vi } from 'vitest';
import { normalizeResourceIndicator, wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// Reproduces anthropics/claude-code#52871: `new URL('https://mcp.example.com')`
// always yields a trailing slash for a pathless origin, and some
// authorization servers (Entra ID) reject the `resource` parameter carrying
// one that shouldn't be there.

describe('resource indicator trailing-slash normalization (claude-code#52871)', () => {
  it('normalizeResourceIndicator strips exactly one trailing slash', () => {
    expect(normalizeResourceIndicator('https://mcp.example.com/')).toBe('https://mcp.example.com');
    expect(normalizeResourceIndicator('https://mcp.example.com/mcp/')).toBe(
      'https://mcp.example.com/mcp',
    );
    expect(normalizeResourceIndicator('https://mcp.example.com/mcp')).toBe(
      'https://mcp.example.com/mcp',
    );
  });

  it('a naive URL-based resource always carries a trailing slash for a pathless origin', () => {
    expect(new URL('https://mcp.example.com').href).toBe('https://mcp.example.com/');
  });

  it('does not define validateResourceURL when the wrapped provider has none of its own', () => {
    // Defining it unconditionally would bypass the SDK's own checkResourceAllowed
    // validation (see the auth()-integration regression test for C1).
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
    });

    expect(wrapped.validateResourceURL).toBeUndefined();
  });

  it('pre-normalizes the resource before delegating to a provider that DOES implement validateResourceURL', async () => {
    const inner = new InMemoryProvider(testClientMetadata, {
      validateResourceURL: async (_serverUrl, resource) =>
        resource !== undefined ? new URL(resource) : undefined,
    });
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
    });

    const result = await wrapped.validateResourceURL!(
      'https://mcp.example.com/mcp',
      'https://mcp.example.com/mcp/',
    );

    expect(result?.href).toBe('https://mcp.example.com/mcp');
    // The inner provider's own validation actually ran and received the
    // already-normalized string — mcp-auth-kit never invents validation of
    // its own that the wrapped provider didn't already opt into.
    expect(inner.validateResourceURLCalls).toEqual([
      { serverUrl: 'https://mcp.example.com/mcp', resource: 'https://mcp.example.com/mcp' },
    ]);
  });

  it('the normalized resource (no trailing slash) is what actually gets sent on refresh', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10, // already expired
    });

    const fetchFn = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body));
      expect(body.get('resource')).toBe('https://mcp.example.com/mcp');
      return jsonResponse({
        access_token: 'fresh',
        token_type: 'Bearer',
        expires_in: 3600,
      });
    });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
      resource: normalizeResourceIndicator(new URL('https://mcp.example.com/mcp').href),
    });
    // saveTokens above went through `inner` directly so the wrapper doesn't
    // yet know the expiry; save again through the wrapper so it does.
    await wrapped.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    await wrapped.tokens();
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});
