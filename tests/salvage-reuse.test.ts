import { describe, expect, it, vi } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// MEDIO-1 and MEDIO-2 — the two costs that kept `refreshSalvageMs` off by
// default. A salvage keeps a refresh request alive after its caller gave up,
// which means a `refresh_token` the authorization server has very likely
// already consumed stays outstanding. Two things must follow from that, and
// neither did before:
//
//   MEDIO-1  a revocation cancels it, instead of leaving a revoked user's
//            credentials moving on a connection for the rest of the window.
//   MEDIO-2  no second grant goes out with that same refresh_token while it is
//            outstanding — presenting a rotated token twice is exactly what
//            RFC 6819 §5.2.2.3 describes as replay, and a strict server answers
//            it by revoking the whole family.
//
// With both closed, salvage is safe to leave on by default.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const json = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

function provider() {
  let tokens: Record<string, unknown> | undefined = {
    access_token: 'old',
    token_type: 'Bearer',
    refresh_token: 'RT-1',
    issuer: AS,
  };
  return {
    peek: () => tokens,
    api: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: () => ({ client_id: 'cid', ...testClientMetadata, issuer: AS }),
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

/** A token endpoint that answers after `latencyMs`, honouring aborts. */
function slowTokenEndpoint(latencyMs: number) {
  const seen: string[] = [];
  let aborted = 0;
  const fetchFn = vi.fn((_url: string | URL, init?: RequestInit) => {
    const body = String(init?.body ?? '');
    const match = /refresh_token=([^&]+)/.exec(body);
    seen.push(match ? decodeURIComponent(match[1]) : '(none)');
    return new Promise<Response>((resolve, reject) => {
      const t = setTimeout(
        () =>
          resolve(
            json({
              access_token: 'NEW',
              token_type: 'Bearer',
              refresh_token: 'RT-2',
              expires_in: 3600,
            }),
          ),
        latencyMs,
      );
      init?.signal?.addEventListener('abort', () => {
        clearTimeout(t);
        aborted += 1;
        reject(new DOMException('The operation was aborted', 'AbortError'));
      });
    });
  });
  return { fetchFn, seen, abortCount: () => aborted };
}

async function expired(wrapped: ReturnType<typeof wrapOAuthClientProvider>) {
  await wrapped.saveTokens({
    access_token: 'old',
    token_type: 'Bearer',
    refresh_token: 'RT-1',
    issuer: AS,
    expires_in: 1,
  });
  await sleep(1100);
}

describe('MEDIO-2: a pending salvage is joined, never raced', () => {
  it('does not send the same refresh_token a second time while one is outstanding', async () => {
    const endpoint = slowTokenEndpoint(400);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 5_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    // First caller times out softly; its request stays alive as a salvage.
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    // Second caller arrives while that salvage is in flight.
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });

    // The decisive assertion: ONE grant, not two. Before MEDIO-2 the second
    // call started its own refresh with the already-rotated RT-1.
    expect(endpoint.seen).toEqual(['RT-1']);

    // And when the salvage lands, the rotated token is persisted as usual.
    await sleep(500);
    expect((p.peek() as { refresh_token?: string })?.refresh_token).toBe('RT-2');
  });

  it('a joiner that waits is released at timeoutMs, not at refreshSalvageMs', async () => {
    const endpoint = slowTokenEndpoint(3_000);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 10_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    const startedAt = Date.now();
    await expect(wrapped.tokens()).rejects.toMatchObject({ phase: 'token_refresh' });
    // Joining must not inherit the salvage window as a latency budget.
    expect(Date.now() - startedAt).toBeLessThan(400);
  });

  it('a joiner gets the salvaged tokens when the salvage lands in time', async () => {
    // The joiner inherits a fresh timeoutMs budget, so the salvage has to land
    // within (timeoutMs) of the first caller being released: 300ms of latency
    // against a 200ms budget released at 200ms leaves 100ms of margin.
    const endpoint = slowTokenEndpoint(300);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 200,
      refreshSalvageMs: 5_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    // This one joins and the salvage answers within its own timeoutMs budget.
    const joined = await wrapped.tokens();
    expect(joined?.access_token).toBe('NEW');
    expect(endpoint.seen).toEqual(['RT-1']);
  });
});

describe('MEDIO-1: invalidateCredentials aborts a pending salvage', () => {
  it('cancels the in-flight request instead of leaving it running', async () => {
    const endpoint = slowTokenEndpoint(3_000);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 10_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    expect(endpoint.abortCount()).toBe(0); // still running as a salvage

    await wrapped.invalidateCredentials!('all');
    await sleep(50);

    // The decisive assertion: the revoked user's refresh request is gone, not
    // merely ignored when it eventually answers.
    expect(endpoint.abortCount()).toBe(1);
    expect(p.peek()).toBeUndefined();
  });

  it('the aborted salvage cannot resurrect credentials afterwards', async () => {
    const endpoint = slowTokenEndpoint(200);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 10_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    await wrapped.invalidateCredentials!('all');
    await sleep(400);

    expect(p.peek()).toBeUndefined();
  });

  it('a later refresh is not blocked by the slot the aborted salvage held', async () => {
    const endpoint = slowTokenEndpoint(3_000);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 60,
      refreshSalvageMs: 10_000,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    await wrapped.invalidateCredentials!('all');

    // Fresh credentials after the revocation must refresh normally — the
    // cleared salvage slot must not suppress them (MEDIO-2 is scoped to the
    // generation that owned the salvage).
    await wrapped.saveTokens({
      access_token: 'fresh',
      token_type: 'Bearer',
      refresh_token: 'RT-9',
      issuer: AS,
      expires_in: 1,
    });
    await sleep(1100);
    await expect(wrapped.tokens()).rejects.toThrow();
    expect(endpoint.seen).toEqual(['RT-1', 'RT-9']);
  });
});

describe('1.0.1: salvage is on by default again', () => {
  it('defaults to 120000, now that MEDIO-1 and MEDIO-2 are closed', async () => {
    const endpoint = slowTokenEndpoint(200);
    const p = provider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      timeoutMs: 50,
      // refreshSalvageMs deliberately not set
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });
    await expired(wrapped);

    await expect(wrapped.tokens()).rejects.toThrow();
    await sleep(400);

    // Salvaged by default: the rotated token is persisted rather than lost.
    expect((p.peek() as { refresh_token?: string })?.refresh_token).toBe('RT-2');
  });
});
