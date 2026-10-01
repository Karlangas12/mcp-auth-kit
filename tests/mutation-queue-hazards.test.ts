import { describe, expect, it } from 'vitest';
import { wrapOAuthClientProvider } from '../src/index.js';
import { testClientMetadata } from './helpers.js';

// ---------------------------------------------------------------------------
// The four hazards the credential-mutation queue introduced or left open, each
// reproducing the exact scenario from the 2026-10-01 review round.
// ---------------------------------------------------------------------------

const AS = 'https://auth.example.com';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Harness {
  log: string[];
  tokens: () => Record<string, unknown> | undefined;
  clientInfo: () => Record<string, unknown> | undefined;
  api: Record<string, unknown>;
}

function harness(opts: {
  saveTokensDelayMs?: number;
  saveClientDelayMs?: number;
  hangSaveTokens?: boolean;
  onSaveTokens?: (wrapped: () => ReturnType<typeof wrapOAuthClientProvider>) => Promise<void> | void;
} = {}): Harness & { setWrapped: (w: ReturnType<typeof wrapOAuthClientProvider>) => void } {
  let tokens: Record<string, unknown> | undefined;
  let clientInfo: Record<string, unknown> | undefined = {
    client_id: 'cid',
    ...testClientMetadata,
    issuer: AS,
  };
  const log: string[] = [];
  let wrapped: ReturnType<typeof wrapOAuthClientProvider> | undefined;

  return {
    log,
    tokens: () => tokens,
    clientInfo: () => clientInfo,
    setWrapped: (w) => {
      wrapped = w;
    },
    api: {
      get redirectUrl() {
        return 'https://client.example.com/callback';
      },
      get clientMetadata() {
        return testClientMetadata;
      },
      clientInformation: () => clientInfo,
      saveClientInformation: async (i: Record<string, unknown>) => {
        if (opts.saveClientDelayMs) await sleep(opts.saveClientDelayMs);
        log.push(`SAVE_CLIENT:${i.client_id as string}`);
        clientInfo = i;
      },
      tokens: () => tokens,
      saveTokens: async (t: Record<string, unknown>) => {
        if (opts.hangSaveTokens) {
          log.push(`SAVE_HANG:${t.access_token as string}`);
          await new Promise<void>(() => {});
        }
        if (opts.onSaveTokens) await opts.onSaveTokens(() => wrapped!);
        if (opts.saveTokensDelayMs) await sleep(opts.saveTokensDelayMs);
        log.push(`SAVE:${t.access_token as string}`);
        tokens = t;
      },
      redirectToAuthorization: () => {},
      saveCodeVerifier: () => {},
      codeVerifier: () => 'cv',
      invalidateCredentials: async (scope: string) => {
        log.push(`INVALIDATE:${scope}`);
        if (scope === 'all' || scope === 'tokens') tokens = undefined;
        if (scope === 'all' || scope === 'client') clientInfo = undefined;
      },
    },
  };
}

// ---------------------------------------------------------------------------
// MEDIO-B — a revocation's latency is a security property. Queueing it behind
// an in-flight save made a hung storage layer stand between a logout and the
// credentials being gone, and stall the SDK's auth() recovery, which awaits it.
// ---------------------------------------------------------------------------
describe('MEDIO-B: a hung provider save cannot block revocation', () => {
  it('revokes immediately rather than waiting on a save that never settles', async () => {
    const h = harness({ hangSaveTokens: true });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    // A save that will never complete.
    let saveSettled = false;
    void wrapped
      .saveTokens({ access_token: 'wedged', token_type: 'Bearer', refresh_token: 'r' })
      .then(() => (saveSettled = true));
    await sleep(20);
    expect(h.log).toEqual(['SAVE_HANG:wedged']);

    // The revocation must not wait for it.
    let revokeSettled = false;
    const revoking = wrapped
      .invalidateCredentials!('all')
      .then(() => (revokeSettled = true));
    await sleep(50);

    expect(revokeSettled).toBe(true);
    expect(h.log).toContain('INVALIDATE:all');
    expect(saveSettled).toBe(false); // the save is still wedged, as designed
    await revoking;
  });

  it('still orders a second pass behind the save, so a late write cannot stand', async () => {
    const h = harness({ saveTokensDelayMs: 150 });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    const saving = wrapped.saveTokens({
      access_token: 'inflight',
      token_type: 'Bearer',
      refresh_token: 'r',
    });
    await sleep(20);
    await wrapped.invalidateCredentials!('all');
    // The immediate revocation has already happened...
    expect(h.log).toEqual(['INVALIDATE:all']);
    await saving;
    await sleep(50);

    // ...and the save that landed afterwards is followed by the ordered pass,
    // so the credentials do not survive it.
    expect(h.log).toEqual(['INVALIDATE:all', 'SAVE:inflight', 'INVALIDATE:all']);
    expect(h.tokens()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// MEDIO-A — client information is a credential too: it carries the
// client_secret. It bypassed the queue entirely.
// ---------------------------------------------------------------------------
describe('MEDIO-A: client information goes through the same queue', () => {
  it('does not resurrect a rejected client when a revocation lands mid-write', async () => {
    const h = harness({ saveClientDelayMs: 200 });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    const saving = wrapped.saveClientInformation!({
      client_id: 'RESURRECTED',
      client_secret: 's3cret',
      ...testClientMetadata,
    } as never);
    await sleep(40);
    await wrapped.invalidateCredentials!('all');
    await saving;
    await sleep(60);

    // The decisive assertion: the client the authorization server rejected is
    // not back on disk, so auth() re-registers instead of retrying the same
    // refused client_id.
    expect(h.clientInfo()).toBeUndefined();
    expect(h.log.at(-1)).toBe('INVALIDATE:all');
  });

  it("routes a scope this wrapper does not track through the queue as well", async () => {
    const h = harness({ saveClientDelayMs: 150 });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    const saving = wrapped.saveClientInformation!({
      client_id: 'LATE',
      ...testClientMetadata,
    } as never);
    await sleep(30);
    await wrapped.invalidateCredentials!('client');
    await saving;
    await sleep(60);

    expect(h.clientInfo()).toBeUndefined();
    expect(h.log.at(-1)).toBe('INVALIDATE:client');
  });
});

// ---------------------------------------------------------------------------
// BAJO-D — two saves enqueued before either had written shared one starting
// generation, so the second misread the first's bump as "you were superseded"
// and skipped its own expiry commit. Storage then held the SECOND save's tokens
// under the FIRST save's expiry.
// ---------------------------------------------------------------------------
describe('BAJO-D: the later of two overlapping saves owns both storage and expiry', () => {
  it('does not leave the newer tokens under the older expiry', async () => {
    const h = harness({ saveTokensDelayMs: 40 });
    const wrapped = wrapOAuthClientProvider(h.api as never, {
      authorizationServerUrl: AS,
      minExpiresInSeconds: 1,
      refreshMarginMs: 0,
    });

    // A: long-lived. B: about to expire. Both enqueued before either writes.
    const a = wrapped.saveTokens({
      access_token: 'A',
      token_type: 'Bearer',
      refresh_token: 'rA',
      expires_in: 100_000,
    });
    const b = wrapped.saveTokens({
      access_token: 'B',
      token_type: 'Bearer',
      refresh_token: 'rB',
      expires_in: 1,
    });
    await Promise.all([a, b]);

    // B wrote last, so storage holds B...
    expect((h.tokens() as { access_token?: string })?.access_token).toBe('B');

    // ...and the expiry in force must be B's too. With A's 100000s expiry still
    // in place, this token would be served indefinitely without a refresh.
    await sleep(1100);
    const fetchCalls: string[] = [];
    const wrappedAgain = wrapped as unknown as { tokens: () => Promise<unknown> };
    await wrappedAgain.tokens().catch((e: Error) => {
      fetchCalls.push(e.name);
    });
    // Expired by B's TTL: a refresh is attempted (and fails, since no token
    // endpoint is configured here) rather than the stale token being served.
    expect(fetchCalls.length).toBe(1);
  });

  it('still bails when a real revocation lands during the write', async () => {
    const h = harness({ saveTokensDelayMs: 120 });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    const saving = wrapped.saveTokens({
      access_token: 'X',
      token_type: 'Bearer',
      refresh_token: 'r',
      expires_in: 3600,
    });
    await sleep(30);
    await wrapped.invalidateCredentials!('all');
    await saving;
    await sleep(60);

    // The discriminator must not have turned into "always commit".
    expect(h.tokens()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// BAJO-C — the wrapped provider is third-party code running inside the queue,
// so it can enqueue work behind the very mutation awaiting it.
// ---------------------------------------------------------------------------
describe('BAJO-C: reentrancy fails loudly instead of deadlocking', () => {
  it('rejects a provider that calls back into wrapped.saveTokens from its own write', async () => {
    const h = harness({
      onSaveTokens: async (getWrapped) => {
        await getWrapped().saveTokens({
          access_token: 'reentrant',
          token_type: 'Bearer',
          refresh_token: 'r',
        });
      },
    });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });
    h.setWrapped(wrapped);

    // Before: this never settled. Now it reports what the provider did wrong.
    await expect(
      wrapped.saveTokens({ access_token: 'outer', token_type: 'Bearer', refresh_token: 'r' }),
    ).rejects.toMatchObject({
      name: 'McpAuthKitError',
      message: expect.stringContaining('called back into this wrapper'),
    });
  });

  it('a reentrant invalidation is structurally safe: it neither hangs nor throws', async () => {
    // The invalidation path does not await its queued pass, so a provider that
    // revokes from inside its own write completes normally.
    const h = harness({
      onSaveTokens: async (getWrapped) => {
        await getWrapped().invalidateCredentials!('all');
      },
    });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });
    h.setWrapped(wrapped);

    await wrapped.saveTokens({ access_token: 'outer', token_type: 'Bearer', refresh_token: 'r' });
    await sleep(40);
    expect(h.log).toContain('INVALIDATE:all');
    // The save was revoked mid-flight, so it must not stand.
    expect(h.tokens()).toBeUndefined();
  });

  it('legitimate concurrent callers are serialized, never rejected as reentrant', async () => {
    const h = harness({ saveTokensDelayMs: 60 });
    const wrapped = wrapOAuthClientProvider(h.api as never, { authorizationServerUrl: AS });

    // The guard must not mistake ordinary concurrency for reentrancy — that is
    // the exact case the queue exists to serialize.
    await Promise.all([
      wrapped.saveTokens({ access_token: '1', token_type: 'Bearer', refresh_token: 'r' }),
      wrapped.saveTokens({ access_token: '2', token_type: 'Bearer', refresh_token: 'r' }),
      wrapped.saveTokens({ access_token: '3', token_type: 'Bearer', refresh_token: 'r' }),
    ]);
    expect(h.log).toEqual(['SAVE:1', 'SAVE:2', 'SAVE:3']);
  });
});
