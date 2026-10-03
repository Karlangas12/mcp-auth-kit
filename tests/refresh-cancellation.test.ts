import { describe, expect, it } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const tokenResponse = (refresh: string) =>
  new Response(
    JSON.stringify({
      access_token: 'NEW',
      token_type: 'Bearer',
      refresh_token: refresh,
      expires_in: 3600,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );

/**
 * A provider whose `clientInformation()` takes real time, as a keychain, a
 * file or a network-backed credential store does. That await is the suspension
 * point MEDIO-1 kept reappearing behind.
 */
function slowClientInfoProvider(clientInfoDelayMs: number) {
  let tokens: Record<string, unknown> | undefined;
  return {
    peek: () => tokens,
    api: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: async () => {
        if (clientInfoDelayMs) await sleep(clientInfoDelayMs);
        return { client_id: 'cid', ...testClientMetadata, issuer: AS };
      },
      saveClientInformation: () => {},
      tokens: () => tokens,
      saveTokens: (t: Record<string, unknown>) => {
        tokens = t;
      },
      redirectToAuthorization: () => {},
      saveCodeVerifier: () => {},
      codeVerifier: () => 'cv',
      invalidateCredentials: () => {
        tokens = undefined;
      },
    },
  };
}

/** Records every grant that reaches the wire, with the signal it was sent on. */
function recordingEndpoint(behaviour: 'hang' | 'answer') {
  const sent: { refreshToken: string; signal: AbortSignal | undefined }[] = [];
  const fetchFn = (_u: string | URL, init?: RequestInit) => {
    const body = String(init?.body ?? '');
    const match = /refresh_token=([^&]+)/.exec(body);
    sent.push({
      refreshToken: match ? decodeURIComponent(match[1]) : '(none)',
      signal: init?.signal ?? undefined,
    });
    if (behaviour === 'answer') return Promise.resolve(tokenResponse('RT-NEW'));
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () =>
        reject(new DOMException('The operation was aborted', 'AbortError')),
      );
    });
  };
  return { sent, fetchFn };
}

// ---------------------------------------------------------------------------
// MEDIO-1, third pass. The first fix registered the cancel handle at the soft
// timeout; the second moved it before the request but still AFTER
// `await provider.clientInformation()`. A revocation landing in that gap found
// nothing to abort, and the grant then went out *after* the logout had
// completed — with no handle any code path could reach for up to
// max(timeoutMs, refreshSalvageMs).
//
// Aborting a request that does not exist yet cannot help, so the close is: the
// handle exists for the whole call by construction, AND the generation is
// re-checked after the suspension point so the grant is never sent at all.
// ---------------------------------------------------------------------------
describe('MEDIO-1: a revocation during clientInformation() stops the grant entirely', () => {
  it('never puts the refresh_token on the wire after the logout completed', async () => {
    const endpoint = recordingEndpoint('hang');
    const p = slowClientInfoProvider(200);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 5_000,
      refreshSalvageMs: 30_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    // The refresh suspends on clientInformation(); nothing is on the wire yet.
    const refreshing = wrapped.tokens().catch((e: Error) => e);
    await sleep(60);
    expect(endpoint.sent).toHaveLength(0);

    // The user logs out while the refresh is still inside that await.
    await wrapped.invalidateCredentials!('tokens');
    expect(p.peek()).toBeUndefined();

    // Let clientInformation() resolve and the refresh proceed as far as it can.
    await sleep(400);

    // The decisive assertion: the grant was never sent. Before this fix exactly
    // one request went out, after the logout, with aborted === false.
    expect(endpoint.sent).toHaveLength(0);
    const outcome = await refreshing;
    expect(outcome).toBeInstanceOf(Error);
  });

  it('still refreshes normally when no revocation intervenes', async () => {
    const endpoint = recordingEndpoint('answer');
    const p = slowClientInfoProvider(200);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    // The guard must not have turned into "never refresh".
    const refreshed = await wrapped.tokens();
    expect(refreshed?.access_token).toBe('NEW');
    expect(endpoint.sent.map((s) => s.refreshToken)).toEqual(['RT-1']);
  });

  it('aborts a request already on the wire, as before', async () => {
    const endpoint = recordingEndpoint('hang');
    const p = slowClientInfoProvider(0);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 5_000,
      refreshSalvageMs: 30_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    const refreshing = wrapped.tokens().catch(() => undefined);
    await sleep(60);
    expect(endpoint.sent).toHaveLength(1);
    expect(endpoint.sent[0].signal!.aborted).toBe(false);

    await wrapped.invalidateCredentials!('all');
    await sleep(20);
    expect(endpoint.sent[0].signal!.aborted).toBe(true);
    await refreshing;
  });
});

// ---------------------------------------------------------------------------
// BAJO-1. `inFlightRefresh` was a single slot, and `refreshNow` only dedupes
// within a generation — so a refresh for a newer generation overwrote the older
// one's cancel handle, and a revocation aborted only the newest request. The
// older one, still carrying the pre-rotation refresh_token, stayed on the wire.
// ---------------------------------------------------------------------------
describe('BAJO-1: every outstanding refresh is cancellable, not just the newest', () => {
  it('aborts an older hanging refresh as well as the current one', async () => {
    const endpoint = recordingEndpoint('hang');
    const p = slowClientInfoProvider(0);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 5_000,
      refreshSalvageMs: 30_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await wrapped.saveTokens({
      access_token: 'old',
      token_type: 'Bearer',
      refresh_token: 'RT-1',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    // Generation G: a refresh that hangs.
    const first = wrapped.tokens().catch(() => undefined);
    await sleep(50);
    expect(endpoint.sent).toHaveLength(1);

    // A save bumps the generation to G+1...
    await wrapped.saveTokens({
      access_token: 'mid',
      token_type: 'Bearer',
      refresh_token: 'RT-2',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);

    // ...and a second refresh starts under it, which used to overwrite the
    // first one's cancel handle.
    const second = wrapped.tokens().catch(() => undefined);
    await sleep(50);
    expect(endpoint.sent).toHaveLength(2);

    await wrapped.invalidateCredentials!('all');
    await sleep(20);

    // The decisive assertion: BOTH are off the wire. Before the fix this read
    // [false, true] — the oldest alive, carrying a pre-rotation refresh_token.
    expect(endpoint.sent.map((s) => s.signal!.aborted)).toEqual([true, true]);
    await Promise.all([first, second]);
  });
});
