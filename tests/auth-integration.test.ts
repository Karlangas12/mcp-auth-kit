import { describe, expect, it } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, createMockAuthServer, testClientMetadata } from './helpers.js';

// These tests drive the SDK's REAL auth() orchestrator against the wrapped
// provider — not just the wrapper's own methods in isolation. The original
// (class-based) implementation of mcp-auth-kit always defined every optional
// OAuthClientProvider member, which changes auth()'s internal control flow
// via feature-detection (`provider.validateResourceURL ? ... : ...`,
// `provider.state ? ... : undefined`, etc.) in ways that unit tests calling
// wrapper methods directly could never catch. Each test below documents
// exactly what would have failed against the old implementation.

const mcpServerUrl = 'https://mcp.example.com';
const authorizationServerUrl = 'https://auth.example.com';

describe('auth() integration: validateResourceURL confused-deputy guard (C1)', () => {
  it('rejects a protected-resource metadata document whose resource does not match the MCP server, when the wrapped provider has no validateResourceURL of its own', async () => {
    // A malicious/misconfigured MCP server advertises a `resource` that does
    // NOT match the server the client actually connected to — the SDK's own
    // checkResourceAllowed() is supposed to catch this and refuse to proceed,
    // preventing the client from requesting (and the AS from minting) a
    // token scoped to a resource the client never intended to talk to.
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: 'https://attacker.example.com', // mismatched on purpose
    });

    const inner = new InMemoryProvider(testClientMetadata); // no validateResourceURL of its own
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    await expect(
      auth(wrapped, { serverUrl: mcpServerUrl, fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toThrow(/does not match expected/);

    // Sanity: with the OLD class-based wrapper (which always defined
    // validateResourceURL, doing only `new URL(normalized)` with no
    // checkResourceAllowed call), this same scenario would have resolved to
    // 'REDIRECT' instead of throwing — silently accepting a resource
    // indicator for a server the client never asked to talk to.
  });

  it('proceeds normally when the resource does match', async () => {
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: mcpServerUrl,
    });

    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({ client_id: 'preregistered', ...testClientMetadata });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    const result = await auth(wrapped, {
      serverUrl: mcpServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    expect(inner.redirectToAuthorizationCalls).toHaveLength(1);
  });
});

describe('auth() integration: resource normalization does not disable the wrapped provider\'s own validation (C2)', () => {
  it('when the wrapped provider implements validateResourceURL, auth() calls it (via the wrapper) with a pre-normalized resource', async () => {
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      // Trailing slash on purpose, per anthropics/claude-code#52871.
      protectedResource: `${mcpServerUrl}/`,
    });

    const inner = new InMemoryProvider(testClientMetadata, {
      validateResourceURL: async (_serverUrl, resource) =>
        resource !== undefined ? new URL(resource) : undefined,
    });
    inner.presetClientInformation({ client_id: 'preregistered', ...testClientMetadata });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    const result = await auth(wrapped, {
      serverUrl: mcpServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    expect(inner.validateResourceURLCalls).toHaveLength(1);
    // The trailing slash from the server's own metadata was stripped before
    // the wrapped provider's own validation ever saw it.
    expect(inner.validateResourceURLCalls[0]?.resource).toBe(mcpServerUrl);
  });
});

describe('auth() integration: state() is only called when the wrapped provider implements it (A4)', () => {
  it('completes normally against a provider with no state() implementation', async () => {
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: mcpServerUrl,
    });

    const inner = new InMemoryProvider(testClientMetadata); // no state()
    inner.presetClientInformation({ client_id: 'preregistered', ...testClientMetadata });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    // With the OLD class-based wrapper, `state` was always defined and threw
    // McpAuthKitError when the inner provider had none — breaking auth() for
    // any provider that doesn't implement the (optional) state() method,
    // which is the common case.
    const result = await auth(wrapped, {
      serverUrl: mcpServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    const redirectUrl = inner.redirectToAuthorizationCalls[0];
    expect(redirectUrl?.searchParams.has('state')).toBe(false);
  });

  it('uses the wrapped provider\'s state() when it has one', async () => {
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: mcpServerUrl,
    });

    const inner = new InMemoryProvider(testClientMetadata, { state: () => 'my-state-value' });
    inner.presetClientInformation({ client_id: 'preregistered', ...testClientMetadata });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    await auth(wrapped, { serverUrl: mcpServerUrl, fetchFn: fetchFn as unknown as typeof fetch });

    const redirectUrl = inner.redirectToAuthorizationCalls[0];
    expect(redirectUrl?.searchParams.get('state')).toBe('my-state-value');
  });
});

describe('auth() integration: saveClientInformation presence controls registration (A5)', () => {
  it('drives real dynamic client registration end to end and persists the result into the wrapped provider', async () => {
    const { fetchFn, calls } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: mcpServerUrl,
      registrationResponse: { client_id: 'dcr-registered-id', ...testClientMetadata },
    });

    const inner = new InMemoryProvider(testClientMetadata); // no preset clientInformation — forces DCR
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    const result = await auth(wrapped, {
      serverUrl: mcpServerUrl,
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    expect(calls.some((c) => c.url.endsWith('/register') && c.method === 'POST')).toBe(true);
    // auth()'s own registration flow called provider.saveClientInformation(),
    // and the wrapper's delegation actually persisted it into inner — not
    // discarded via a `?.()` no-op.
    const stored = await inner.clientInformation();
    expect(stored?.client_id).toBe('dcr-registered-id');
  });

  it('surfaces the SDK\'s own "must be saveable for dynamic registration" error when the wrapped provider cannot persist at all', async () => {
    const { fetchFn } = createMockAuthServer({
      mcpServerUrl,
      authorizationServerUrl,
      protectedResource: mcpServerUrl,
    });

    const inner = new InMemoryProvider(testClientMetadata, { canSaveClientInformation: false });
    const wrapped = wrapOAuthClientProvider(inner, { authorizationServerUrl });

    // With the OLD class-based wrapper, saveClientInformation was always
    // defined (delegating via `?.()` to a possibly-absent inner method), so
    // `provider.saveClientInformation !== undefined` was always true and the
    // SDK's own guard against un-persistable dynamic registration never
    // fired — silently discarding the registered client on every call.
    await expect(
      auth(wrapped, { serverUrl: mcpServerUrl, fetchFn: fetchFn as unknown as typeof fetch }),
    ).rejects.toThrow(/must be saveable for dynamic registration/);
  });
});
