import { describe, expect, it } from 'vitest';
import { McpAuthKitError, wrapOAuthClientProvider } from '../src/index.js';
import { InMemoryProvider, testClientMetadata } from './helpers.js';

describe('typed, actionable errors instead of silent failure', () => {
  it('tokens() with an expired token and no refresh_token names the phase and remediation', async () => {
    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fallbackTokenTtlMs: 1,
    });

    await wrapped.saveTokens({
      access_token: 'no-refresh',
      token_type: 'Bearer',
      // no refresh_token
    });

    await new Promise((resolve) => setTimeout(resolve, 5));

    let caught: unknown;
    try {
      await wrapped.tokens();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(McpAuthKitError);
    expect((caught as McpAuthKitError).phase).toBe('token_refresh');
    expect((caught as McpAuthKitError).message).toMatch(/re-authorize|authorization code flow/i);
  });
});
