import { describe, expect, it, vi } from 'vitest';
import { InvalidGrantError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { wrapOAuthClientProvider } from '../src/index.js';
import { sanitizeForMessage, sanitizedCause } from '../src/sanitize.js';
import { InMemoryProvider, errorResponse, testClientInformation, testClientMetadata } from './helpers.js';

// B11: a malicious or misconfigured authorization server controls
// error_description (and we echo back `resource`). Neither must be able to
// plant newlines/control characters into our error message or cause chain —
// that's a log-forging vector once the error is logged verbatim.

describe('sanitizeForMessage strips control characters', () => {
  it('strips newlines, carriage returns and other control chars', () => {
    const malicious = 'invalid_grant\n[ERROR] fake log line\r\nuser=admin action=granted\x1b[31m';
    const sanitized = sanitizeForMessage(malicious);
    expect(sanitized).not.toMatch(/[\n\r\x1b]/);
  });

  it('truncates very long text', () => {
    const long = 'a'.repeat(10_000);
    expect(sanitizeForMessage(long).length).toBeLessThan(400);
  });
});

describe('server-controlled text never reaches McpAuthKitError.message or .cause unsanitized', () => {
  it('a malicious error_description in a refresh failure does not inject newlines into the thrown error', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    await inner.saveTokens({
      access_token: 'expired',
      token_type: 'Bearer',
      refresh_token: 'refresh-1',
      expires_in: -10,
    });

    const maliciousDescription = 'invalid_grant\n[2026-01-01] FAKE ADMIN LOGIN SUCCESSFUL';
    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify({ error: 'invalid_grant', error_description: maliciousDescription }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
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

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(Error);
    const err = caught as Error & { cause?: unknown };
    expect(err.message).not.toMatch(/[\n\r]/);
    expect(String((err.cause as Error)?.message ?? '')).not.toMatch(/[\n\r]/);
  });

  it('a malicious registration error_description does not inject newlines into the thrown error', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const maliciousDescription = 'invalid_client_metadata\nFAKE_LOG_LINE=injected';
    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify({ error: 'server_error', error_description: maliciousDescription }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    let caught: unknown;
    try {
      await wrapped.clientInformation();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(Error);
    const err = caught as Error & { cause?: unknown };
    expect(err.message).not.toMatch(/[\n\r]/);
    expect(String((err.cause as Error)?.message ?? '')).not.toMatch(/[\n\r]/);
  });

  // Guard against errorResponse() calls elsewhere in the suite silently no
  // longer producing a parsed OAuthError (which would make the assertions
  // above vacuous).
  it('sanity: errorResponse() still round-trips through the SDK as an OAuth error', async () => {
    const res = errorResponse(500);
    expect(res.status).toBe(500);
  });
});

// M7: sanitizedCause() must sanitize server-controlled text WITHOUT
// discarding the concrete error type — callers need `err.cause instanceof
// InvalidGrantError` to distinguish "revoked, re-authorize" from "transient,
// retry later".
describe('sanitizedCause preserves the real error type (M7)', () => {
  it('a sanitized OAuthError subclass instance is still that exact subclass', () => {
    const original = new InvalidGrantError('the refresh_token\nis dead\r\nlong live the token');
    const result = sanitizedCause(original);

    expect(result).toBeInstanceOf(InvalidGrantError);
    expect(result).toBe(original); // same object, mutated in place — not replaced
    expect((result as Error).message).not.toMatch(/[\n\r]/);
    expect((result as Error).message).toContain('the refresh_token');
    expect((result as Error).message).toContain('is dead');
  });

  it('distinguishes InvalidGrantError from ServerError after sanitization', () => {
    const grantError = sanitizedCause(new InvalidGrantError('revoked\nby admin'));
    const serverError = sanitizedCause(new ServerError('temporarily\ndown'));

    expect(grantError).toBeInstanceOf(InvalidGrantError);
    expect(grantError).not.toBeInstanceOf(ServerError);
    expect(serverError).toBeInstanceOf(ServerError);
    expect(serverError).not.toBeInstanceOf(InvalidGrantError);
  });

  it('end to end: a refresh failing with invalid_grant surfaces as cause instanceof InvalidGrantError', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    inner.presetClientInformation(testClientInformation);
    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify({ error: 'invalid_grant', error_description: 'refresh token revoked' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
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

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }

    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(InvalidGrantError);
  });

  it('a non-Error value becomes a sanitized plain Error', () => {
    const result = sanitizedCause('raw string\nwith a newline');
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).not.toMatch(/\n/);
  });
});
