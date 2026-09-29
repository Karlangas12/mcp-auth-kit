import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import * as sdkErrors from '@modelcontextprotocol/sdk/server/auth/errors.js';
import {
  InvalidClientError,
  InvalidGrantError,
  UnauthorizedClientError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { isSdkRecoverableOAuthError } from '../src/classifyError.js';
import { InMemoryProvider, jsonResponse, testClientInformation, testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// FIX 2 (round 4, BLOCKER): the SDK's real auth() recovers from exactly three
// error classes by calling invalidateCredentials() and retrying into a
// re-authorization redirect:
//
//   if (error instanceof InvalidClientError || error instanceof UnauthorizedClientError) {
//       await provider.invalidateCredentials?.('all');   return await authInternal(...)
//   } else if (error instanceof InvalidGrantError) {
//       await provider.invalidateCredentials?.('tokens'); return await authInternal(...)
//   }
//   throw error;
//
// auth() calls provider.tokens() BEFORE its own refresh logic, so a refresh
// failure raised inside this wrapper is what auth() sees. Wrapping those three
// in McpAuthKitError (which extends Error, not OAuthError) made the instanceof
// match fail and turned a recoverable situation into a hard error — strictly
// worse than not using the package.
//
// These tests drive the REAL auth() (not a mock) against a mock authorization
// server, and compare a bare provider against the wrapped one.
// ---------------------------------------------------------------------------

const MCP_SERVER = 'https://mcp.example.com';
const AUTH_SERVER = 'https://auth.example.com';

/** A mock server whose /token endpoint returns the given OAuth error. */
function mockServerRejectingToken(error: string) {
  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const method = init?.method ?? 'GET';

    if (u.pathname === '/.well-known/oauth-protected-resource') {
      return jsonResponse({ resource: MCP_SERVER, authorization_servers: [AUTH_SERVER] });
    }
    if (u.pathname === '/.well-known/oauth-authorization-server') {
      return jsonResponse({
        issuer: AUTH_SERVER,
        authorization_endpoint: `${AUTH_SERVER}/authorize`,
        token_endpoint: `${AUTH_SERVER}/token`,
        registration_endpoint: `${AUTH_SERVER}/register`,
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (u.pathname === '/.well-known/openid-configuration') {
      return new Response('not found', { status: 404 });
    }
    // invalid_client / unauthorized_client make auth() invalidate 'all', which
    // clears the client registration too, so the retry re-registers via DCR.
    if (u.pathname === '/register' && method === 'POST') {
      return jsonResponse({ client_id: 're-registered', ...testClientMetadata });
    }
    if (u.pathname === '/token' && method === 'POST') {
      return new Response(JSON.stringify({ error, error_description: `${error} description` }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response('not found', { status: 404 });
  };
}

const revokedTokens = {
  access_token: 'stale',
  token_type: 'Bearer',
  refresh_token: 'revoked',
  issuer: AUTH_SERVER,
};

describe('FIX 2: auth() still auto-recovers from a revoked refresh_token through the wrapper', () => {
  it('baseline: a BARE provider is sent to re-authorization (REDIRECT)', async () => {
    const bare = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      // A real provider deletes the credentials, which is what makes the SDK's
      // recovery observable: the retried authInternal finds nothing usable and
      // falls through to a re-authorization redirect.
      invalidateClearsCredentials: true,
    });
    bare.presetClientInformation({ ...testClientInformation, issuer: AUTH_SERVER });
    await bare.saveTokens(revokedTokens);

    const result = await auth(bare, {
      serverUrl: MCP_SERVER,
      fetchFn: mockServerRejectingToken('invalid_grant') as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    expect(bare.redirectToAuthorizationCalls).toHaveLength(1);
  });

  it('the WRAPPED provider reaches the same outcome, not a hard error', async () => {
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      // A real provider deletes the credentials, which is what makes the SDK's
      // recovery observable: the retried authInternal finds nothing usable and
      // falls through to a re-authorization redirect.
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AUTH_SERVER });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AUTH_SERVER,
      fetchFn: mockServerRejectingToken('invalid_grant') as unknown as typeof fetch,
    });

    // Make the wrapper aware the token is expired, as it would be mid-session,
    // so its own proactive refresh is the thing that fails.
    await wrapped.saveTokens({ ...revokedTokens, expires_in: -10 });

    const result = await auth(wrapped, {
      serverUrl: MCP_SERVER,
      fetchFn: mockServerRejectingToken('invalid_grant') as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
    expect(inner.redirectToAuthorizationCalls).toHaveLength(1);
  });

  it('recovers the same way for invalid_client', async () => {
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      // A real provider deletes the credentials, which is what makes the SDK's
      // recovery observable: the retried authInternal finds nothing usable and
      // falls through to a re-authorization redirect.
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AUTH_SERVER });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AUTH_SERVER,
      fetchFn: mockServerRejectingToken('invalid_client') as unknown as typeof fetch,
    });
    await wrapped.saveTokens({ ...revokedTokens, expires_in: -10 });

    const result = await auth(wrapped, {
      serverUrl: MCP_SERVER,
      fetchFn: mockServerRejectingToken('invalid_client') as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
  });

  it('recovers the same way for unauthorized_client', async () => {
    const inner = new InMemoryProvider(testClientMetadata, {
      canInvalidateCredentials: true,
      // A real provider deletes the credentials, which is what makes the SDK's
      // recovery observable: the retried authInternal finds nothing usable and
      // falls through to a re-authorization redirect.
      invalidateClearsCredentials: true,
    });
    inner.presetClientInformation({ ...testClientInformation, issuer: AUTH_SERVER });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AUTH_SERVER,
      fetchFn: mockServerRejectingToken('unauthorized_client') as unknown as typeof fetch,
    });
    await wrapped.saveTokens({ ...revokedTokens, expires_in: -10 });

    const result = await auth(wrapped, {
      serverUrl: MCP_SERVER,
      fetchFn: mockServerRejectingToken('unauthorized_client') as unknown as typeof fetch,
    });

    expect(result).toBe('REDIRECT');
  });

  it('a NON-recoverable OAuth failure still surfaces as a typed McpAuthKitError', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation({ ...testClientInformation, issuer: AUTH_SERVER });

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: AUTH_SERVER,
      fetchFn: mockServerRejectingToken('invalid_scope') as unknown as typeof fetch,
    });
    await wrapped.saveTokens({ ...revokedTokens, expires_in: -10 });

    // invalid_scope is definitive but not one of auth()'s three classes, so the
    // actionable wrapper is still the right surface here.
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
  });
});

describe('FIX 2: isSdkRecoverableOAuthError matches exactly the three classes auth() handles', () => {
  it('matches the three', () => {
    expect(isSdkRecoverableOAuthError(new InvalidGrantError('x'))).toBe(true);
    expect(isSdkRecoverableOAuthError(new InvalidClientError('x'))).toBe(true);
    expect(isSdkRecoverableOAuthError(new UnauthorizedClientError('x'))).toBe(true);
  });

  it('matches nothing else', async () => {
    const { InvalidScopeError, ServerError, InvalidRequestError } = await import(
      '@modelcontextprotocol/sdk/server/auth/errors.js'
    );
    expect(isSdkRecoverableOAuthError(new InvalidScopeError('x'))).toBe(false);
    expect(isSdkRecoverableOAuthError(new ServerError('x'))).toBe(false);
    expect(isSdkRecoverableOAuthError(new InvalidRequestError('x'))).toBe(false);
    expect(isSdkRecoverableOAuthError(new Error('x'))).toBe(false);
    expect(isSdkRecoverableOAuthError(undefined)).toBe(false);
  });

  // Drift guard: isSdkRecoverableOAuthError mirrors a decision made inside the
  // SDK's auth(). If upstream adds or removes a class from that catch, the
  // mirror goes stale silently — and the consequence is a regression of this
  // very blocker. So assert against the real installed source.
  it('the set matches the classes auth() actually branches on in the installed SDK', () => {
    // Read the ESM build specifically — that is what the code under test
    // imports. `require.resolve` alone would hand back the CJS build, which
    // spells these classes with a namespace prefix and would silently make the
    // assertion below vacuous.
    const require = createRequire(import.meta.url);
    const anyEntry = require.resolve('@modelcontextprotocol/sdk/client/auth.js');
    const marker = `@modelcontextprotocol${path.sep}sdk`;
    const pkgRoot = anyEntry.slice(0, anyEntry.indexOf(marker) + marker.length);
    const entry = path.join(pkgRoot, 'dist', 'esm', 'client', 'auth.js');
    const source = readFileSync(entry, 'utf8');

    // Isolate `export async function auth(...) { ... }` by brace matching.
    const start = source.indexOf('async function auth(provider, options)');
    expect(
      start,
      'Could not locate auth() in the installed SDK — re-verify isSdkRecoverableOAuthError by hand.',
    ).toBeGreaterThan(-1);
    const bodyStart = source.indexOf('{', start);
    let depth = 0;
    let end = -1;
    for (let i = bodyStart; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') {
        depth--;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    const authSource = source.slice(start, end);

    // Every `instanceof <X>Error` auth() branches on, deduped.
    const branched = [...new Set([...authSource.matchAll(/instanceof\s+(?:[\w$]+\.)?(\w*Error)/g)].map((m) => m[1]!))].sort();

    expect(
      branched,
      `auth()'s recovery branches changed. isSdkRecoverableOAuthError in ` +
        `src/classifyError.ts mirrors this set and must be updated together with it, ` +
        `or the SDK's automatic re-authorization breaks again (round-4 blocker 1).`,
    ).toEqual(['InvalidClientError', 'InvalidGrantError', 'UnauthorizedClientError']);

    // And our mirror agrees with it.
    for (const name of branched) {
      const instance = Object.create(
        (sdkErrors as Record<string, { prototype: object }>)[name]!.prototype,
      ) as Error;
      expect(isSdkRecoverableOAuthError(instance)).toBe(true);
    }
  });
});
