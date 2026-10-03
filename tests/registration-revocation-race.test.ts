import { describe, expect, it } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// MEDIO-1. A client registration's queue turn is only taken once the HTTP round
// trip RETURNS, so the mutation queue cannot order it against a revocation that
// happened *during* the round trip — that revocation's own queued pass has long
// drained by then. The result was a `client_secret` this package had just
// minted being written to the user's storage after a logout the caller was
// already told had completed.
//
// The close is persist-and-re-revoke rather than skip-the-write: the client was
// created at the authorization server, so refusing to persist it would leave it
// orphaned there — registered remotely, invisible locally. Both steps happen in
// ONE queue turn, so no other credential mutation of this wrapper can observe
// the secret in between.
// ---------------------------------------------------------------------------

function registeringProvider(saveClientDelayMs = 0) {
  let tokens: Record<string, unknown> | undefined = {
    access_token: 'at',
    token_type: 'Bearer',
    refresh_token: 'rt',
    issuer: AS,
  };
  let clientInfo: Record<string, unknown> | undefined;
  const log: string[] = [];
  return {
    log,
    client: () => clientInfo,
    tokens: () => tokens,
    api: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: () => clientInfo,
      saveClientInformation: async (i: Record<string, unknown>) => {
        if (saveClientDelayMs) await sleep(saveClientDelayMs);
        log.push(`saveClientInformation:${i.client_id as string}`);
        clientInfo = i;
      },
      tokens: () => tokens,
      saveTokens: (t: Record<string, unknown>) => {
        tokens = t;
      },
      redirectToAuthorization: () => {},
      saveCodeVerifier: () => {},
      codeVerifier: () => 'cv',
      invalidateCredentials: async (scope: string) => {
        log.push(`invalidate:${scope}`);
        if (scope === 'all' || scope === 'tokens') tokens = undefined;
        if (scope === 'all' || scope === 'client') clientInfo = undefined;
      },
    },
  };
}

/** A registration endpoint that answers after `latencyMs`. */
function slowRegistrationEndpoint(latencyMs: number) {
  let calls = 0;
  const fetchFn = () => {
    calls += 1;
    return new Promise<Response>((resolve) =>
      setTimeout(
        () =>
          resolve(
            new Response(
              JSON.stringify({
                client_id: 'NEW-CLIENT',
                client_secret: 's3cret',
                ...testClientMetadata,
              }),
              { status: 201, headers: { 'Content-Type': 'application/json' } },
            ),
          ),
        latencyMs,
      ),
    );
  };
  return { fetchFn, calls: () => calls };
}

describe('MEDIO-1: a revocation during the registration round trip', () => {
  it('does not leave the freshly minted client_secret in storage', async () => {
    const p = registeringProvider();
    const endpoint = slowRegistrationEndpoint(200);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    // Registration goes out and is still in flight.
    const registering = wrapped.clientInformation().catch((e: Error) => e);
    await sleep(60);
    expect(endpoint.calls()).toBe(1);
    expect(p.client()).toBeUndefined();

    // The user logs out while it is in flight, and is told it completed.
    await wrapped.invalidateCredentials!('all');
    const outcome = await registering;
    await sleep(60);

    // The decisive assertion: the secret this package minted is not sitting in
    // the user's storage after the logout. Before the fix, the provider held
    // { client_id: 'NEW-CLIENT', client_secret: 's3cret' }.
    expect(p.client()).toBeUndefined();
    expect((p.client() as { client_secret?: string } | undefined)?.client_secret).toBeUndefined();

    // And the caller is told what happened rather than handed a client that no
    // longer exists in storage.
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain('invalidated while it was in flight');
  });

  it('reproduces the exact log from the report, then re-revokes', async () => {
    const p = registeringProvider();
    const endpoint = slowRegistrationEndpoint(200);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    void wrapped.clientInformation().catch(() => undefined);
    await sleep(60);
    await wrapped.invalidateCredentials!('all');
    await sleep(300);

    // The report's log was: invalidate:all -> invalidate:all -> saveClientInformation,
    // and it ENDED there, with the client persisted. The write still happens —
    // the client exists at the authorization server and refusing to record it
    // would orphan it — but it is now followed by its own revocation.
    expect(p.log.slice(0, 3)).toEqual([
      'invalidate:all',
      'invalidate:all',
      'saveClientInformation:NEW-CLIENT',
    ]);
    expect(p.log.at(-1)).toBe('invalidate:client');
  });

  it('persists and re-revokes in ONE queue turn, so nothing can observe the secret', async () => {
    // A concurrent credential mutation enqueued while the registration is in
    // flight must not be able to run between the persist and the re-revoke.
    const p = registeringProvider(40);
    const endpoint = slowRegistrationEndpoint(150);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    void wrapped.clientInformation().catch(() => undefined);
    await sleep(40);
    await wrapped.invalidateCredentials!('all');
    // Queued behind the registration's write; it must land either entirely
    // before the persist or entirely after the re-revoke.
    const observed: (string | undefined)[] = [];
    void wrapped
      .saveClientInformation!({ client_id: 'OTHER', ...testClientMetadata } as never)
      .then(() => observed.push((p.client() as { client_id?: string } | undefined)?.client_id));
    await sleep(400);

    // Identified by client_id: the unrelated write logs under its own name, so
    // "nothing between them" is a claim about the registration's own pair.
    const persistIndex = p.log.indexOf('saveClientInformation:NEW-CLIENT');
    const reRevokeIndex = p.log.lastIndexOf('invalidate:client');
    expect(persistIndex).toBeGreaterThan(-1);
    expect(reRevokeIndex).toBeGreaterThan(persistIndex);
    // Nothing between them.
    expect(p.log.slice(persistIndex + 1, reRevokeIndex)).toEqual([]);
  });

  it('a registration with no revocation racing it is unaffected', async () => {
    const p = registeringProvider();
    const endpoint = slowRegistrationEndpoint(20);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    const info = await wrapped.clientInformation();
    expect((info as { client_id?: string })?.client_id).toBe('NEW-CLIENT');
    expect((p.client() as { client_secret?: string })?.client_secret).toBe('s3cret');
    expect(p.log).toEqual(['saveClientInformation:NEW-CLIENT']);
  });

  it('a revocation scoped to tokens only does not re-revoke the client', async () => {
    // invalidationCount tracks token-affecting scopes, which is what a
    // registration race must react to; but the re-revoke itself is scoped to
    // 'client' so it cannot discard tokens a legitimate login established since.
    const p = registeringProvider();
    const endpoint = slowRegistrationEndpoint(150);
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      fetchFn: endpoint.fetchFn as unknown as typeof fetch,
      registration: { maxAttempts: 1 },
    });

    void wrapped.clientInformation().catch(() => undefined);
    await sleep(40);
    await wrapped.invalidateCredentials!('tokens');
    await sleep(300);

    expect(p.log.at(-1)).toBe('invalidate:client');
    expect(p.client()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// MEDIO-2. The missing test from the previous round: a store SLOWER than
// storeTimeoutMs. The waiter used to give up at the bound and let the next
// queued operation start while the real write was still running, so an expiry
// `set` could be applied by the store after the revocation's `delete`.
// ---------------------------------------------------------------------------
describe('MEDIO-2: ordering holds for a store slower than storeTimeoutMs', () => {
  it('never applies a set after the revocation delete', async () => {
    const applied: string[] = [];
    const values = new Map<string, number>();
    // The set overruns the 50ms bound by a long way; the delete is quick. That
    // asymmetry is the whole bug: with the waiter giving up at the bound, the
    // chain advanced and the fast delete was applied first, then the abandoned
    // set landed on top of it. Equal latencies cannot reproduce it.
    const store = {
      get: async (k: string) => values.get(k),
      set: async (k: string, v: number) => {
        await sleep(300);
        applied.push(v === 0 ? 'sentinel' : 'expiry');
        values.set(k, v);
      },
      delete: async (k: string) => {
        await sleep(20);
        applied.push('delete');
        values.delete(k);
      },
    };

    const p = registeringProvider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store,
      resourceKey: 'k',
      storeTimeoutMs: 50,
      minExpiresInSeconds: 1,
      onWarning: () => {},
    });

    const startedAt = Date.now();
    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 100_000,
    });
    // The caller was released at the bound, not at the store's latency.
    expect(Date.now() - startedAt).toBeLessThan(200);

    await wrapped.invalidateCredentials!('all');
    // Let every abandoned-by-the-waiter operation finish.
    await sleep(900);

    // The decisive assertion: the expiry was applied BEFORE the delete. This
    // case previously asserted the opposite as a documented limitation.
    expect(applied).toEqual(['expiry', 'delete']);
    expect(values.has('k')).toBe(false);
  });

  it('warns once that the store exceeded its bound', async () => {
    const warnings: string[] = [];
    const store = {
      get: async () => undefined,
      set: async () => {
        await sleep(200);
      },
      delete: async () => {},
    };
    const p = registeringProvider();
    const wrapped = wrapOAuthClientProvider(p.api as never, {
      authorizationServerUrl: AS,
      expiryStore: store,
      resourceKey: 'k',
      storeTimeoutMs: 40,
      onWarning: (m: string) => warnings.push(m),
    });

    await wrapped.saveTokens({
      access_token: 'a',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    await wrapped.saveTokens({
      access_token: 'b',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });

    // Degradation must be visible, and said once rather than on every write.
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('exceeded storeTimeoutMs');
  });
});
