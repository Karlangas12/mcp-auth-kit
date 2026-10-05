import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { isRetryableRegistrationError, isRetryableOAuthError } from '../src/classifyError.js';
import {
  InMemoryProvider,
  errorResponse,
  jsonResponse,
  routeDiscovery,
  testClientMetadata,
} from './helpers.js';

// A6 (round 3): RFC 7591 dynamic client registration is a NON-IDEMPOTENT POST.
// When mcp-auth-kit's own `timeoutMs` aborts it, the authorization server may
// already have created the client — we just never saw the response. Retrying
// then creates a SECOND client registration with its own client_secret, which
// is exactly the duplicate-registration failure the retry classification
// exists to prevent.
//
// Before the fix, an AbortError fell through `isRetryableOAuthError`'s default
// `return true` (it is not an OAuthError) and was retried.

/** A fetch that never answers — it only ever settles via the AbortSignal. */
function hangingFetch() {
  return vi.fn((_url: string | URL, init?: RequestInit) => {
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        reject(new DOMException('The operation was aborted', 'AbortError'));
      });
    });
  });
}

describe('A6: a dynamic client registration aborted by our own timeout is NOT retried', () => {
  it('attempts the registration POST exactly once when it times out', async () => {
    const fetchFn = hangingFetch();
    const inner = new InMemoryProvider(testClientMetadata);

    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
      timeoutMs: 20, // real timers, kept tiny
      registration: { maxAttempts: 5, baseDelayMs: 1, sleep: () => Promise.resolve() },
    });

    await expect(wrapped.clientInformation()).rejects.toMatchObject({
      phase: 'client_registration',
    });

    // The decisive assertion: one POST, not five. A second attempt could
    // register a duplicate client if the server processed the first one.
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('still retries a genuinely transient registration failure (server_error)', async () => {
    let attempts = 0;
    const fetchFn = vi.fn(async () => {
      attempts += 1;
      if (attempts < 3) return errorResponse(500, 'server_error');
      return jsonResponse({ client_id: 'recovered', ...testClientMetadata });
    });

    const inner = new InMemoryProvider(testClientMetadata);
    const wrapped = wrapOAuthClientProvider(inner, {
      authorizationServerUrl: 'https://auth.example.com',
      fetchFn: routeDiscovery(fetchFn as never) as unknown as typeof fetch,
      registration: { maxAttempts: 5, baseDelayMs: 1, sleep: () => Promise.resolve() },
    });

    const info = await wrapped.clientInformation();
    expect(info?.client_id).toBe('recovered');
    expect(attempts).toBe(3);
  });

  it('does not retry when the CALLER aborts either (a cancellation is not a transient failure)', () => {
    const abort = new DOMException('The operation was aborted', 'AbortError');
    expect(isRetryableRegistrationError(abort)).toBe(false);
  });
});

describe('A6: the registration policy differs from the general OAuth policy, deliberately', () => {
  it('isRetryableOAuthError still treats an abort as retryable (refresh-path behavior is unchanged)', () => {
    const abort = new DOMException('The operation was aborted', 'AbortError');
    // Round 2 settled the refresh path's timeout trade-off separately; this
    // fix must not change it.
    expect(isRetryableOAuthError(abort)).toBe(true);
  });

  it('both policies agree on definitive OAuth rejections and on transient ones', () => {
    const plainNetworkError = new TypeError('fetch failed');
    expect(isRetryableOAuthError(plainNetworkError)).toBe(true);
    expect(isRetryableRegistrationError(plainNetworkError)).toBe(true);
  });

  it('classifies an AbortSignal.timeout()-style TimeoutError as non-retryable for registration too', () => {
    const timeout = new DOMException('The operation timed out', 'TimeoutError');
    expect(isRetryableRegistrationError(timeout)).toBe(false);
  });
});
