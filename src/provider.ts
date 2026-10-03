import {
  registerClient,
  refreshAuthorization,
  type OAuthClientProvider,
} from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';

import {
  isAbortError,
  isRetryableOAuthError,
  isRetryableRegistrationError,
  isSdkRecoverableOAuthError,
} from './classifyError.js';
import { McpAuthKitError } from './errors.js';
import type { ExpiryStore } from './expiryStore.js';
import { withTimeout } from './fetchTimeout.js';
import { issuersMatch } from './issuerMatch.js';
import { normalizeResourceIndicator } from './resource.js';
import { sanitizeForMessage, sanitizedCause } from './sanitize.js';
import { withExponentialBackoff, type BackoffOptions } from './retry.js';

export interface McpAuthKitOptions {
  /** The authorization server's base URL, used for token refresh and dynamic client registration. */
  authorizationServerUrl: string | URL;
  /** Custom fetch implementation (e.g. for tests, or non-standard runtimes). */
  fetchFn?: FetchLike;
  /**
   * TTL, in ms, applied when the server's token response omits `expires_in`.
   * Without this, a missing `expires_in` means the token is never proactively
   * refreshed and silently goes stale (anthropics/claude-code#26281).
   * Default: 55 minutes.
   */
  fallbackTokenTtlMs?: number;
  /**
   * How long before the computed expiry we proactively refresh, in ms.
   * Default: 30 seconds.
   */
  refreshMarginMs?: number;
  /**
   * Lower bound, in seconds, clamped onto a server-supplied `expires_in`
   * before it's trusted. Guards against a server sending `0` or a negative
   * value, which would otherwise trigger a refresh on every single call.
   *
   * Applies ONLY to `expires_in` — a relative duration the authorization
   * server just issued, where "0 or negative" means "malformed". It is
   * deliberately NOT applied to an absolute timestamp read back from
   * `expiryStore`: there, a past timestamp is not malformed, it is the
   * store telling us the token is already expired (and `expiresAt = 0` is
   * specifically the revocation sentinel `invalidateCredentials()` writes).
   * Raising a past timestamp to "valid for another 30s" would manufacture
   * validity that does not exist and silently defeat that sentinel.
   *
   * Default: 30.
   */
  minExpiresInSeconds?: number;
  /**
   * Upper bound, in seconds, applied both to a server-supplied `expires_in`
   * and to an `expiryStore`-supplied absolute timestamp (as a cap relative
   * to "now"). Guards against an unreasonably large value leaving a token
   * that's actually been revoked looking valid indefinitely. Unlike the
   * lower bound, capping is safe on both paths: it can only ever make the
   * wrapper refresh sooner, never later. Default: 30 days.
   */
  maxExpiresInSeconds?: number;
  /**
   * Timeout, in ms, applied to every HTTP call mcp-auth-kit makes on the
   * client's behalf (registration, token refresh). A hung authorization
   * server must not be able to block the whole MCP client. Default: 30000.
   *
   * This bounds how long a CALLER waits. For the refresh grant specifically,
   * the request is not aborted at this point — see `refreshSalvageMs`.
   */
  timeoutMs?: number;
  /**
   * How long, in ms, to keep a timed-out refresh request alive in the
   * background in the hope of salvaging its result. **Default: 120000 (2 min).**
   * Set it to `0` to abort at `timeoutMs` instead.
   *
   * This defaulted to `0` while two of its costs were real. Both are now closed,
   * which is what makes salvage safe to leave on:
   *
   * - A second refresh could go out with the same `refresh_token` while a
   *   salvage still held it, which a strict authorization server reads as replay
   *   and answers by revoking the whole family. A concurrent caller now joins
   *   the salvage in flight instead of racing it (MEDIO-2).
   * - A revoked credential's request stayed in flight for the rest of the
   *   window. `invalidateCredentials()` now aborts it (MEDIO-1).
   *
   * What remains is the cost that cannot be closed from inside this package. A
   * short-lived process may exit before the salvage lands, in which case the
   * window bought nothing. The deadline timer is unref'd, so it is never itself
   * a reason to stay alive — but the in-flight request's SOCKET belongs to the
   * `fetchFn` and its agent, and if that handle holds the event loop, the
   * process can be kept alive until the request ends. Set this to `0` if you
   * would rather a short-lived client always exit promptly.
   *
   * The refresh grant is a NON-IDEMPOTENT POST against an authorization server
   * that typically rotates the refresh token the moment it processes the
   * request. Aborting at `timeoutMs` therefore destroys credentials: the server
   * has already invalidated the old refresh token, and the response carrying
   * the new one is thrown away with the connection. Every later attempt then
   * fails with `invalid_grant` and the user is forced through a full re-login —
   * for a refresh that actually succeeded.
   *
   * So the two concerns are separated. `timeoutMs` releases the caller, which
   * is what keeps a hung authorization server from blocking the client. This
   * window keeps the request itself open afterwards, and if it does land with
   * tokens, they are persisted — under the same generation check every other
   * late result goes through, so a response that arrives after the credentials
   * it belongs to were replaced or invalidated is discarded rather than
   * resurrected. The caller's own attempt still fails at `timeoutMs`; the
   * salvage shows up as valid credentials on the next `tokens()` call.
   */
  refreshSalvageMs?: number;
  /**
   * When set, enables auto dynamic-client-registration-with-retry: if the
   * wrapped provider has no stored client information, mcp-auth-kit performs
   * RFC 7591 registration itself, retrying only transient failures with
   * exponential backoff (openai/codex#13200). Requires the wrapped provider
   * to implement `saveClientInformation` — mcp-auth-kit refuses to register
   * a client it cannot persist.
   */
  registration?: BackoffOptions;
  /**
   * RFC 8707 resource indicator to send with token requests. Normalized
   * (trailing slash stripped) before mcp-auth-kit's own refresh call uses
   * it. This only covers mcp-auth-kit's own refresh path — see README
   * "Resource normalization: what this does and doesn't cover".
   */
  resource?: string | URL;
  /**
   * Optional store for the access-token expiry clock, so it survives a
   * process restart. When omitted (the default), mcp-auth-kit tracks
   * `expiresAt` in memory only, and — per the verified behavior of the
   * SDK's own `auth()`/transport reactive-401 flow (see README "Expiry
   * persistence") — does NOT force a proactive refresh on a token it just
   * loaded cold. When provided, mcp-auth-kit persists `expiresAt` through it
   * on every `saveTokens()` and consults it before deciding whether a
   * freshly loaded token needs a proactive refresh.
   */
  expiryStore?: ExpiryStore;
  /**
   * Key under which `expiryStore` persists this session's expiry. Defaults
   * to `authorizationServerUrl` combined with `resource` (when set), so two
   * different protected resources behind the same authorization server
   * don't share (and clobber) one expiry entry.
   */
  resourceKey?: string;
  /**
   * How long, in ms, to suppress further refresh attempts after one fails
   * with a DEFINITIVE error (e.g. `invalid_grant` — a revoked or expired
   * refresh token). Without this, every subsequent `tokens()` call launches
   * another doomed request at the authorization server. Transient failures
   * (network errors, `server_error`, `429`, our own timeout) are never
   * cached — those may well succeed on the next attempt. The window is
   * cleared by a successful `saveTokens()` or by `invalidateCredentials()`.
   * Default: 30000.
   */
  refreshFailureCacheMs?: number;
  /**
   * Timeout, in ms, for each individual `expiryStore` operation (`get`, `set`,
   * `delete`). The expiry store is a supplementary cache, never the source of
   * truth, so a slow or hung one must never be able to stall `tokens()` — which
   * the transport calls on every single request — or delay the credential
   * invalidation in `invalidateCredentials()`. On timeout mcp-auth-kit stops
   * waiting and carries on as if the store had nothing to say: a `get` degrades
   * to "expiry unknown", a `set`/`delete` is abandoned as best-effort. The
   * underlying operation is not cancelled (an `ExpiryStore` has no cancellation
   * contract); mcp-auth-kit simply stops awaiting it. Default: 5000.
   */
  storeTimeoutMs?: number;
  /**
   * Called instead of `console.warn` for the (rare) conditions mcp-auth-kit
   * needs to surface but must not throw on — an `expiryStore` returning a
   * non-finite value, or an `expiryStore` operation exceeding
   * `storeTimeoutMs`. Defaults to `console.warn`. Pass a no-op to silence, or
   * route it into your own logger.
   */
  onWarning?: (message: string) => void;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Wraps an existing {@link OAuthClientProvider} to add proactive token
 * refresh (with a TTL fallback and real refresh-token usage), retrying
 * dynamic client registration, RFC 8707 `resource` normalization, and typed
 * errors instead of silent failures.
 *
 * The returned provider only defines the OPTIONAL members of
 * {@link OAuthClientProvider} that the wrapped provider itself defines. The
 * SDK's `auth()` orchestrator uses *presence* of these methods as
 * feature-detection (e.g. to decide whether its own `resource`-matching
 * validation runs, or whether `state()` is generated) — defining them
 * unconditionally would silently disable security checks the wrapped
 * provider never asked to opt out of, or crash flows it never opted into.
 *
 * The returned provider is a drop-in replacement: pass it anywhere the
 * wrapped provider was used (e.g. `new Client(...).connect(transport, {
 * authProvider })` or the SDK's `auth()` orchestrator).
 */
export function wrapOAuthClientProvider(
  provider: OAuthClientProvider,
  options: McpAuthKitOptions,
): OAuthClientProvider {
  const authorizationServerUrl = options.authorizationServerUrl;
  const configuredIssuer = String(authorizationServerUrl);
  const fallbackTokenTtlMs = options.fallbackTokenTtlMs ?? 55 * 60 * 1000;
  const refreshMarginMs = options.refreshMarginMs ?? 30 * 1000;
  const minExpiresInSeconds = options.minExpiresInSeconds ?? 30;
  const maxExpiresInSeconds = options.maxExpiresInSeconds ?? 30 * 24 * 60 * 60;
  const timeoutMs = options.timeoutMs ?? 30 * 1000;
  const refreshFailureCacheMs = options.refreshFailureCacheMs ?? 30 * 1000;
  const storeTimeoutMs = options.storeTimeoutMs ?? 5 * 1000;
  const onWarning =
    options.onWarning ??
    ((message: string) => {
      // eslint-disable-next-line no-console
      console.warn(message);
    });
  const registrationOptions = options.registration;
  // B3: normalized once, up front — this is the only place mcp-auth-kit
  // itself controls the `resource` value it sends (its own refresh call).
  const resource =
    options.resource !== undefined
      ? normalizeResourceIndicator(
          typeof options.resource === 'string' ? options.resource : options.resource.href,
        )
      : undefined;
  const fetchFn = withTimeout(options.fetchFn, timeoutMs);
  const refreshSalvageMs = options.refreshSalvageMs ?? 120 * 1000;
  // The refresh grant gets a longer HARD deadline than the caller's soft one,
  // so a request that outlives `timeoutMs` stays alive long enough to be
  // salvaged instead of being aborted mid-rotation. Still bounded: it is a
  // deadline, not an absence of one.
  const refreshFetchFn =
    refreshSalvageMs > 0
      ? withTimeout(options.fetchFn, Math.max(timeoutMs, refreshSalvageMs))
      : fetchFn;
  const expiryStore = options.expiryStore;
  // M3: combine issuer + resource so two protected resources behind the
  // same authorization server don't share one expiry entry.
  const resourceKey =
    options.resourceKey ?? (resource !== undefined ? `${configuredIssuer}::${resource}` : configuredIssuer);

  if (registrationOptions && !provider.saveClientInformation) {
    throw new McpAuthKitError(
      'client_registration',
      'Auto dynamic-client-registration was requested via the `registration` option, but the wrapped provider does not implement saveClientInformation',
      'implement saveClientInformation on the wrapped provider so a newly registered client can actually be persisted, or omit the `registration` option and register the client yourself',
    );
  }

  /** Wall-clock ms at which the current access token is considered expired. */
  let expiresAt: number | undefined;
  /**
   * Whether we've already asked `expiryStore` (if any) for a persisted
   * `expiresAt` this process. Distinguishes "haven't checked yet" from
   * "checked, and the store genuinely has nothing" — without this, a store
   * that legitimately has no value would be re-queried on every tokens() call.
   */
  let expiryStoreChecked = false;
  /** In-flight expiryStore.get(), so concurrent cold tokens() calls share one read. */
  let expiryLoad: Promise<number | undefined> | undefined;
  /**
   * M11: bumped by invalidateCredentials(). A store load that was already in
   * flight when credentials were invalidated must not write its (now stale)
   * result over the cleared state once it resolves.
   */
  let expiryGeneration = 0;
  /**
   * MEDIO-2: why the current generation was started. A result computed under an
   * older generation is always superseded, but the right response differs: if a
   * newer `saveTokens()` supersedes it, valid tokens exist and last-write-wins
   * is the correct answer; if an `invalidateCredentials()` does, the credentials
   * are gone and there is nothing to hand back.
   */
  let generationReason: 'initial' | 'save' | 'invalidate' = 'initial';
  /**
   * ALTO-1: in-flight refresh, so concurrent tokens() calls share one request —
   * but scoped to the generation it was started under. A caller from a NEWER
   * generation must never inherit an older refresh's outcome: that older
   * refresh is using a refresh_token that has since been replaced, and if it
   * fails with `invalid_grant` the (now unwrapped, per FIX 2) error would reach
   * the SDK's auth(), which responds by invalidating credentials — destroying
   * the newer, valid tokens.
   */
  let refreshing: { generation: number; promise: Promise<OAuthTokens> } | undefined;
  /**
   * MEDIO-1 / MEDIO-2: a refresh that outlived its caller's soft timeout and is
   * still in flight, together with the handle that cancels it.
   *
   * It is tracked rather than merely fired and forgotten because the request is
   * still carrying a `refresh_token` the authorization server may already have
   * consumed. Two things follow, and both need this slot: a revocation has to be
   * able to cancel it (MEDIO-1), and a second refresh must not go out with that
   * same `refresh_token` while it is outstanding (MEDIO-2) — a strict
   * authorization server reads a second presentation of a rotated token as
   * replay and answers by revoking the whole token family (RFC 6819 §5.2.2.3).
   *
   * `promise` never rejects: a salvage that fails has nothing to hand anyone.
   */
  interface SalvageRegistration {
    generation: number;
    promise: Promise<OAuthTokens | undefined>;
    abort: () => void;
  }
  /**
   * BAJO-1: a SET, not a single slot. A salvage for an older generation can
   * still be outstanding when a newer one is published, and a single slot let
   * the newer one overwrite the older one's cancel handle — leaving a request
   * carrying a pre-rotation `refresh_token` on the wire with nothing able to
   * reach it. Membership is by identity and removal happens on settle.
   */
  const pendingSalvages = new Set<SalvageRegistration>();

  /** The salvage a same-generation caller may join (MEDIO-2), if there is one. */
  function salvageForGeneration(generation: number): SalvageRegistration | undefined {
    for (const salvage of pendingSalvages) {
      if (salvage.generation === generation) return salvage;
    }
    return undefined;
  }

  /**
   * MEDIO-1: cancel an in-flight salvage and clear the slot. Idempotent, and
   * safe to call when there is nothing pending.
   *
   * Clearing the slot first matters: `abort()` can settle the attempt
   * synchronously, and the settle handler only releases a slot it still owns.
   */
  function abortPendingSalvages(): void {
    const salvages = [...pendingSalvages];
    pendingSalvages.clear();
    for (const salvage of salvages) salvage.abort();
  }

  /**
   * MEDIO-1: the cancel handle for a refresh request that is in flight RIGHT
   * NOW, published the moment the request starts rather than when it becomes a
   * salvage.
   *
   * Registering only at the soft timeout left the whole pre-timeout window —
   * `timeoutMs`, 30s by default, and the common case rather than an edge one —
   * with no handle for a revocation to reach, so a logout during it left the
   * user's `refresh_token` on the wire for the rest of the salvage window. The
   * registration exists for the request's whole life; `pendingSalvages`
   * continues to carry it afterwards for the join (MEDIO-2), a different
   * question.
   */
  interface RefreshRegistration {
    generation: number;
    abort: () => void;
  }
  /**
   * BAJO-1: a SET, for the same reason as `pendingSalvages`. `refreshNow` only
   * dedupes within a generation, so a refresh for a newer generation can start
   * while an older one still hangs; a single slot meant the newer registration
   * overwrote the older one and a revocation aborted only the newest request.
   */
  const inFlightRefreshes = new Set<RefreshRegistration>();

  /**
   * MEDIO-1: cancel every outstanding refresh request of this instance,
   * whichever phase it is in. Called when credentials are revoked: there is
   * nothing left for any of them to refresh.
   */
  function abortInFlightRefreshes(): void {
    const active = [...inFlightRefreshes];
    inFlightRefreshes.clear();
    for (const registration of active) registration.abort();
    abortPendingSalvages();
  }
  /** Whether we've already warned about an invalid expiryStore value this process. */
  let warnedInvalidExpiryValue = false;
  /** Whether we've already warned about an expiryStore operation timing out this process. */
  let warnedStoreTimeout = false;
  /**
   * BAJO-1: expiry-store writes are ordered against each other, and ALL of the
   * outstanding ones are tracked — not just the most recent.
   *
   * Two defects came from doing neither. A store write is issued after its
   * save has already released its queue turn, so two saves' writes raced: a
   * store whose latency varies with the value (a file, a keychain, a network
   * cache — i.e. a real one) could land the earlier save's expiry last, leaving
   * the persisted copy describing tokens that are no longer there. That is the
   * same failure BAJO-D fixed in memory, surviving in the persisted copy. And
   * tracking only the newest write meant a revocation awaited the wrong one, so
   * an older straggler could restore a live-looking expiry after the delete
   * that M5 exists to guarantee.
   *
   * This queue is separate from the credential-mutation queue on purpose: the
   * expiry store is a supplementary cache, and coupling credential writes to
   * its latency is exactly what `storeTimeoutMs` exists to prevent.
   *
   * MEDIO-2: each CALLER's wait is bounded from the moment it enqueues, not
   * from the moment its turn comes. Bounding only the operation left the wait
   * scaling with queue depth — the k-th caller waited k * storeTimeoutMs,
   * because write k+1's clock only started once write k had timed out. That put
   * minutes on `tokens()`, which the transport calls on every request, and on
   * the revocation path `auth()` awaits. The write stays ordered in the internal
   * chain either way; what the deadline bounds is how long the caller watches
   * it, which is all a supplementary cache is owed.
   *
   * The returned promise never rejects: a store operation's failure is already
   * swallowed by `runStoreOp`, which degrades to in-memory tracking rather than
   * turning a successful credential save into a thrown error.
   */
  let storeWrites: Promise<unknown> = Promise.resolve();

  function queueStoreWrite(label: string, op: () => Promise<unknown>): Promise<void> {
    // MEDIO-2: the chain waits for the RAW operation, not for a bounded view of
    // it. Chaining on a bounded wrapper meant that a store slower than
    // `storeTimeoutMs` had its write abandoned by the waiter while the real
    // write kept running — so the next queued operation started anyway and a
    // `set` could still be applied by the store AFTER the revocation's
    // `delete`, putting a future expiry back behind a logout. Ordering has to
    // reflect when the store actually applied the write; only the CALLER's wait
    // is bounded, by the deadline below.
    //
    // `Promise.resolve().then(op)` rather than `op()`: a store that violates
    // its own `Promise<...>` contract and throws synchronously must not
    // propagate out of here, and a failing store must degrade exactly like a
    // missing one.
    const raw = (): Promise<void> =>
      Promise.resolve()
        .then(op)
        .then(
          () => undefined,
          () => undefined,
        );
    const next = storeWrites.then(raw, raw);
    storeWrites = next;

    return new Promise<void>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
        timer = undefined;
        warnStoreTimeout(label);
        // The write is still queued and still ordered; this caller simply stops
        // watching it, which is all a supplementary cache is owed.
        resolve();
      }, storeTimeoutMs);
      // Delivers this caller's answer rather than guarding other work, so it is
      // deliberately not unref'd — see the note on runStoreOp's timer.
      void next.then(() => {
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        resolve();
      });
    });
  }

  /** Bajo-7: wall-clock ms until which refresh attempts are suppressed after a definitive failure. */
  let refreshBlockedUntil = 0;
  /** The sanitized cause of the definitive failure that opened the current suppression window. */
  let refreshBlockedCause: unknown;

  /**
   * A patch to the wrapper's shared expiry/refresh state. Optional keys are
   * detected by presence (`in`), not by value, so `{ expiresAt: undefined }`
   * is a real "clear it" instruction rather than "leave it alone".
   */
  interface ExpiryStatePatch {
    expiresAt?: number | undefined;
    expiryStoreChecked?: boolean;
    /** `null` clears the refresh-failure window; an object opens one. */
    refreshFailure?: { until: number; cause: unknown } | null;
  }

  /**
   * THE single write point for every piece of shared mutable state in this
   * wrapper (`expiresAt`, `expiryStoreChecked`, `refreshBlockedUntil`,
   * `refreshBlockedCause`). Nothing else assigns them.
   *
   * Four independent async paths can reach this state — `tokens()`,
   * `saveTokens()`, `performRefresh()` and `invalidateCredentials()` — and any
   * two of them can overlap. `generation` is the value of `expiryGeneration`
   * read BEFORE the async work that produced `patch` began. If a newer
   * generation has started since (a `saveTokens()` landed, or credentials were
   * invalidated), this result describes state that has been superseded and is
   * dropped silently, exactly as the original M11 guard did for the cold store
   * load.
   *
   * @returns whether the patch was applied.
   */
  function commitExpiryState(generation: number, patch: ExpiryStatePatch): boolean {
    if (generation !== expiryGeneration) return false;
    if ('expiresAt' in patch) expiresAt = patch.expiresAt;
    if (patch.expiryStoreChecked !== undefined) expiryStoreChecked = patch.expiryStoreChecked;
    if (patch.refreshFailure !== undefined) {
      if (patch.refreshFailure === null) {
        refreshBlockedUntil = 0;
        refreshBlockedCause = undefined;
      } else {
        refreshBlockedUntil = patch.refreshFailure.until;
        refreshBlockedCause = patch.refreshFailure.cause;
      }
    }
    return true;
  }

  /**
   * Starts a new generation, superseding anything computed under the previous
   * one. Called by the two paths that establish authoritative new state:
   * `saveTokens()` (we now hold accepted tokens) and `invalidateCredentials()`
   * (the credentials are gone). The reason is recorded so a superseded result
   * can tell those two cases apart — see `generationReason`.
   */
  /**
   * ALTO-1: serializes this wrapper's own mutations of the wrapped provider's
   * credential storage — tokens AND client information — so mutations that
   * overlap are applied in call order rather than in I/O-completion order.
   *
   * Detecting the overlap afterwards is not enough on its own. By the time a
   * generation re-check can see that credentials were invalidated mid-write,
   * `provider.saveTokens()` has already written them back — the revoked tokens
   * are in storage and no later check can un-write them. The only way to keep
   * a revocation is to not let the write land after it.
   *
   * What this queue does and does not bound (corrected — the previous wording
   * here claimed it "bounds nothing", which was wrong):
   *
   * - It DOES couple each queued mutation's latency to the latency of every
   *   mutation enqueued before it. A hung `provider.saveTokens()` therefore
   *   delays everything behind it for as long as it hangs, with no timeout.
   *   Bounding the queue is not the fix — bailing out of it re-opens ALTO-1 —
   *   so the one caller for which delay is a security property, revocation,
   *   does not wait on it at all. See `invalidateCredentials` below (MEDIO-B):
   *   it revokes immediately and uses the queue only for a second, idempotent
   *   ordering pass that nobody awaits.
   * - It is per wrapper instance (a closure variable), so one wedged provider
   *   cannot stall another server's credentials in the same process.
   *
   * Reentrancy (BAJO-C — the previous wording claimed a deadlock was
   * impossible; it is not). The wrapped provider is third-party code running
   * INSIDE this queue, so a provider whose `saveTokens` calls back into
   * `wrapped.saveTokens`/`wrapped.invalidateCredentials` would enqueue work
   * behind the very mutation that is awaiting it. `reentrancyDepth` is raised
   * around the synchronous head of each queued mutation, which is where a
   * storage layer that rejects a token it was just handed calls back from, and
   * such a call is rejected immediately with a clear error instead of hanging.
   * A provider that calls back only AFTER its own first `await` is outside
   * what a synchronous marker can see; the wrapped provider must not do that,
   * and the README states so. The invalidation path is structurally safe
   * either way, since its queued pass is not awaited.
   */
  let credentialMutations: Promise<unknown> = Promise.resolve();
  let reentrancyDepth = 0;
  function serializeCredentialMutation<T>(
    run: () => Promise<T> | T,
    /**
     * Set only for work that nobody awaits. The guard exists to turn a deadlock
     * into an error, and a mutation no caller is waiting on cannot deadlock —
     * rejecting it would instead silently drop the ordering pass that keeps a
     * reentrant revocation effective.
     */
    options?: { allowReentrant?: boolean },
  ): Promise<T> {
    if (reentrancyDepth > 0 && !options?.allowReentrant) {
      return Promise.reject(
        new McpAuthKitError(
          'authorization',
          'The wrapped provider called back into this wrapper from inside one of its own credential writes',
          'a credential write (saveTokens / saveClientInformation / invalidateCredentials) must not call wrapped.saveTokens() or wrapped.invalidateCredentials() on the same wrapper instance — mcp-auth-kit applies these in call order, so a write that waits on work queued behind itself can never complete; call the underlying provider directly from inside that write instead',
        ),
      );
    }
    const guarded = (): Promise<T> | T => {
      reentrancyDepth += 1;
      try {
        return run();
      } finally {
        // Lowered when `run` RETURNS, not when it settles: this marks the
        // synchronous head of the provider's own call, which is the reentrant
        // window a marker can attribute. Keeping it raised for the whole
        // awaited body would reject legitimate concurrent callers, which is
        // precisely what this queue exists to serialize rather than refuse.
        reentrancyDepth -= 1;
      }
    };
    const next = credentialMutations.then(guarded, guarded);
    credentialMutations = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  /**
   * BAJO-D: bumped once per `invalidateCredentials()` call, synchronously, at
   * call time — the moment the revocation becomes authoritative.
   *
   * The generation counter alone cannot carry this. It moves for two different
   * reasons, and a save that finds it has moved must react to them oppositely:
   * an invalidation means "bail, your tokens are revoked", while an earlier
   * save means "you are the newer write, commit". Since the queue guarantees an
   * earlier save completed before this one started, conflating the two made the
   * later save skip its own expiry commit and leave storage holding ITS tokens
   * under the EARLIER save's expiry. This counter is the discriminator: it moves
   * only for revocations.
   */
  let invalidationCount = 0;

  function beginGeneration(reason: 'save' | 'invalidate'): number {
    expiryGeneration += 1;
    generationReason = reason;
    return expiryGeneration;
  }

  /**
   * MEDIO-3: runs one `expiryStore` operation with a bound on how long we wait,
   * and swallows its errors. The store is a supplementary cache: it must never
   * be able to stall `tokens()` (called on every request by the transport) or
   * `invalidateCredentials()`. On timeout we stop awaiting and return
   * `fallback`; the operation itself keeps running, since `ExpiryStore` has no
   * cancellation contract.
   */
  function warnStoreTimeout(label: string): void {
    if (warnedStoreTimeout) return;
    warnedStoreTimeout = true;
    onWarning(
      `[mcp-auth-kit] expiryStore.${label}("${sanitizeForMessage(resourceKey)}") exceeded storeTimeoutMs (${storeTimeoutMs}ms); continuing without it. The expiry store is a cache, never the source of truth.`,
    );
  }

  async function runStoreOp<T>(
    label: string,
    op: () => Promise<T>,
    fallback: T,
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = Symbol('store-timeout');
    try {
      const outcome = await Promise.race([
        // MEDIO-2: `Promise.resolve().then(op)` rather than `op()` directly. A
        // store that violates its own `Promise<...>` contract and throws
        // synchronously would otherwise propagate straight out of here and break
        // tokens() — the one function that exists so the store is never
        // load-bearing. Deferring the call turns a synchronous throw into an
        // ordinary rejection, absorbed by the same handler as an async one.
        Promise.resolve()
          .then(op)
          .then(
            (value) => value,
            () => fallback, // a failing store degrades exactly like a missing one
          ),
        new Promise<typeof timedOut>((resolve) => {
          // ALTO-2: deliberately NOT unref'd. This timer is not a safety net
          // standing behind other work — it is the thing that resolves this
          // race and lets tokens() proceed. Unref it and a process whose only
          // pending work is a hung store would exit before it fired, leaving
          // the caller's promise unsettled instead of degrading gracefully.
          timer = setTimeout(() => resolve(timedOut), storeTimeoutMs);
        }),
      ]);
      if (outcome === timedOut) {
        warnStoreTimeout(label);
        return fallback;
      }
      return outcome;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Clamp for a server-supplied `expires_in` — a relative duration. Both
   * bounds apply: a 0/negative value is malformed and would otherwise cause
   * a refresh on every call.
   */
  function clampServerExpiresInSeconds(expiresIn: number): number {
    return Math.min(Math.max(expiresIn, minExpiresInSeconds), maxExpiresInSeconds);
  }

  /**
   * B4: cap for an absolute expiry timestamp read back from `expiryStore`.
   * ONLY the upper bound applies. A timestamp in the past is not malformed —
   * it is the store reporting that the token is already expired, and
   * `expiresAt = 0` is specifically the revocation sentinel written by
   * invalidateCredentials(). Applying the lower bound here would raise both
   * of those to "valid for another `minExpiresInSeconds`", manufacturing
   * validity that does not exist and silently defeating the sentinel.
   */
  function capStoredExpiresAt(storedExpiresAt: number, now: number): number {
    return Math.min(storedExpiresAt, now + maxExpiresInSeconds * 1000);
  }

  async function clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    const existing = await provider.clientInformation();
    if (existing) return existing;
    if (!registrationOptions) return undefined;

    // MEDIO-1: counted BEFORE the registration round trip starts. The queue
    // cannot order this write against a revocation that happened DURING the
    // round trip, because this write only takes its turn once the HTTP call
    // returns — by which time the revocation's own queued pass has long
    // drained. So the ordering guarantee has to be re-established explicitly,
    // and this is the observation it rests on.
    const invalidationsAtEntry = invalidationCount;

    let registered: OAuthClientInformationFull;
    try {
      registered = await withExponentialBackoff(
        () =>
          registerClient(authorizationServerUrl, {
            clientMetadata: provider.clientMetadata,
            fetchFn,
          }),
        // A6: registration-specific policy — an aborted (timed-out)
        // non-idempotent POST must not be retried. See isRetryableRegistrationError.
        { ...registrationOptions, shouldRetry: isRetryableRegistrationError },
      );
    } catch (error) {
      throw new McpAuthKitError(
        'client_registration',
        `Dynamic client registration (RFC 7591) failed after ${registrationOptions.maxAttempts ?? 3} attempt(s)`,
        'verify the authorization server advertises a registration_endpoint and supports dynamic client registration, or pre-register a client and provide clientInformation() statically instead of relying on auto-registration',
        sanitizedCause(error),
      );
    }

    // B1: stamp `issuer`, same as the SDK's own auth() does after a fresh
    // registration (auth.js `clientInformation = { ...fullInformation, issuer }`).
    // The SDK's own bindClientInformation() would repair a missing stamp
    // later anyway, but stamping it here keeps our own saveClientInformation
    // delegation consistent with what saveTokens does for A3's sake.
    //
    // Bajo-6 (reviewed, intentional — no code change): the stamp uses the
    // CONFIGURED authorizationServerUrl. If that genuinely differs from the
    // one auth() discovers via RFC 9728 (beyond the trailing-slash/case/port
    // tolerance of issuersMatch), auth()'s discardIfIssuerMismatch will
    // discard this registration and register again itself — so a
    // misconfiguration surfaces as duplicate registrations rather than as
    // silent credential reuse across authorization servers. That is the
    // intended trade-off: reusing a client registration bound to a different
    // authorization server is the failure worth preventing, and the
    // configuration mismatch that triggers this is a real bug in the caller's
    // setup, not something to paper over. See the README note under
    // "Design note: conditional delegation".
    const stamped: OAuthClientInformationFull = { ...registered, issuer: configuredIssuer };
    // MEDIO-A: client information is a credential too — it carries the
    // `client_secret`. Ordered through the same queue as token writes, so a
    // registration that started before an `invalidateCredentials()` cannot land
    // after it and put a rejected client back on disk, leaving auth() to retry
    // with the same `client_id` the server just refused instead of registering
    // anew. `provider.saveClientInformation` is guaranteed to exist: checked at
    // wrap time above.
    //
    // MEDIO-1: persist-and-re-revoke. If a revocation landed while the
    // registration was in flight, this client was minted at the authorization
    // server during a logout. Skipping the write would leave it orphaned there
    // — registered remotely, invisible locally, impossible to clean up — so it
    // is persisted either way, and the revocation is then re-applied to it.
    //
    // Both happen in ONE queue turn. Splitting them into two would open a
    // window in which the freshly minted `client_secret` is readable from the
    // provider's storage after a logout the caller was already told had
    // completed; inside a single turn no other credential mutation of this
    // wrapper can interleave, so the revoked state is restored before anything
    // else can observe otherwise. The window is therefore no wider than the
    // ordinary revocation path's own.
    await serializeCredentialMutation(async () => {
      await provider.saveClientInformation!(stamped);
      if (invalidationsAtEntry === invalidationCount) return;
      if (!provider.invalidateCredentials) return;
      // 'client' rather than 'all': the revocation that raced this has already
      // dealt with the tokens, and re-revoking those would discard credentials
      // that a legitimate login may have established since.
      await provider.invalidateCredentials('client');
    });

    if (invalidationsAtEntry !== invalidationCount) {
      // The caller asked who the client is; the honest answer after a logout
      // that overlapped the registration is "there isn't one" — returning the
      // stamped client would hand out a `client_secret` that no longer exists
      // in storage, and the SDK would then try to use it.
      throw new McpAuthKitError(
        'client_registration',
        'Client registration completed, but the credentials were invalidated while it was in flight, so the new client was revoked again rather than left in place',
        'this is a benign race against invalidateCredentials(), not a registration failure — retry the operation and a fresh client will be registered if one is still needed',
      );
    }
    return stamped;
  }

  async function tokens(): Promise<OAuthTokens | undefined> {
    // THE capture point for this operation. Read once, before the credentials
    // it describes, and propagated by parameter from here on — never re-read
    // mid-chain. `expiryGeneration` is only consulted afterwards to ask "is this
    // still current?", never to re-label work already under way: a label taken
    // later than the data it describes is how a refresh of a replaced
    // refresh_token gets mistaken for a current one.
    const generation = expiryGeneration;
    const stored = await provider.tokens();
    if (!stored) return undefined;

    if (expiresAt === undefined && !expiryStoreChecked) {
      // Committed under this operation's generation: if a saveTokens() landed
      // or credentials were invalidated while the read was in flight,
      // commitExpiryState drops the result instead of resurrecting a superseded
      // expiry over newer state.
      const loaded = await loadExpiryFromStore();
      commitExpiryState(generation, { expiresAt: loaded, expiryStoreChecked: true });
    }

    if (generation !== expiryGeneration) {
      // Authoritative state landed while we were reading. Both `stored` and the
      // expiry just judged describe a superseded generation, so neither may be
      // acted on: judging them would return a stale access token, and refreshing
      // them would send a replaced refresh_token — whose rejection, being
      // rethrown unwrapped for the SDK's benefit, would have auth() invalidate
      // the newer credentials that superseded it. Hand back what is current
      // instead (possibly nothing, if this was an invalidation).
      return provider.tokens();
    }

    if (expiresAt === undefined) {
      // Cold, and no (or no configured) expiry store to consult: we have no
      // basis to know whether this token — loaded fresh from the wrapped
      // provider's own storage, e.g. right after a process restart — is
      // actually still valid. Pass it through as-is rather than guessing.
      //
      // This is safe by construction, not just by omission: per the SDK's
      // own auth.js (verified — see README "Expiry persistence"), the stock
      // StreamableHTTPClientTransport/SSEClientTransport both react to a 401
      // by calling auth() again, and auth() itself attempts a silent
      // refresh_token grant before ever falling back to a full interactive
      // re-authorization. So a stale token loaded cold still self-heals on
      // the very next request for any client using those transports — at
      // the cost of one failed round trip — without mcp-auth-kit forcing a
      // refresh (and burning a refresh-token rotation) on every single
      // process start on the mere suspicion that it might be needed.
      return stored;
    }

    const needsRefresh = Date.now() >= expiresAt - refreshMarginMs;
    if (!needsRefresh) return stored;

    if (!stored.refresh_token) {
      throw new McpAuthKitError(
        'token_refresh',
        'Access token has expired and no refresh_token is available',
        'the user must complete the OAuth authorization code flow again; the authorization server did not issue a refresh_token, or it was not persisted',
      );
    }

    return refreshNow(stored, generation);
  }

  function loadExpiryFromStore(): Promise<number | undefined> {
    if (!expiryStore) return Promise.resolve(undefined);
    // Bajo-2: dedupe concurrent cold reads the same way refreshes are deduped.
    if (!expiryLoad) {
      const load = (async () => {
        // MEDIO-3: bounded. A failing OR hung read is no worse than not having a
        // store configured at all — degrade to the no-adapter default rather
        // than blocking tokens(), which the transport calls on every request.
        const raw = await runStoreOp<number | undefined>(
          'get',
          () => expiryStore.get(resourceKey),
          undefined,
        );
        if (raw === undefined) return undefined;

        if (!isFiniteNumber(raw)) {
          // M2: never let a bad value disable proactive refresh forever in
          // silence — warn once, then treat it exactly like "unknown".
          if (!warnedInvalidExpiryValue) {
            warnedInvalidExpiryValue = true;
            // M12: `resourceKey` defaults to a string built from `resource`,
            // which callers routinely take straight from server-advertised
            // protected-resource metadata — so it goes through the same
            // sanitizer as any other untrusted text before reaching a log line.
            onWarning(
              `[mcp-auth-kit] expiryStore.get("${sanitizeForMessage(resourceKey)}") returned a non-finite value; treating expiry as unknown for this process.`,
            );
          }
          return undefined;
        }

        // B4: upper bound only — see capStoredExpiresAt. A past timestamp
        // (including the revocation sentinel 0) is passed through untouched
        // so it reads as expired, which is exactly what it means.
        return capStoredExpiresAt(raw, Date.now());
      })();
      expiryLoad = load;
      // Only clear the slot if it still holds THIS load: invalidateCredentials()
      // may have already replaced/cleared it while this one was in flight.
      void load
        .finally(() => {
          if (expiryLoad === load) expiryLoad = undefined;
        })
        .catch(() => {
          // The load above never rejects; this only keeps the side-chain from
          // ever surfacing as an unhandled rejection.
        });
    }
    return expiryLoad;
  }

  /**
   * ALTO-1: only join an in-flight refresh from the SAME generation. One started
   * under an older generation is refreshing a refresh_token that has since been
   * replaced or revoked; inheriting its outcome would make this caller act on a
   * result that does not describe the credentials it holds — and, when that
   * outcome is an unwrapped `invalid_grant`, would have the SDK's auth()
   * invalidate the newer, valid tokens in response.
   *
   * `generation` is the caller's, captured alongside `stored` — it is NOT
   * re-read here. Re-reading would label this refresh with whatever generation
   * happens to be current at the moment the request starts, rather than the one
   * the `refresh_token` in `stored` actually belongs to.
   */
  function refreshNow(stored: OAuthTokens, generation: number): Promise<OAuthTokens> {
    if (refreshing && refreshing.generation === generation) {
      return refreshing.promise;
    }
    // MEDIO-2: a salvage from this same generation is still holding this very
    // `refresh_token`. Starting a second grant with it now is what makes a
    // strict authorization server see replay and revoke the family, so join the
    // one in flight instead of racing it.
    const joinable = salvageForGeneration(generation);
    if (joinable) {
      return joinPendingSalvage(joinable);
    }
    let tracked: Promise<OAuthTokens>;
    tracked = performRefresh(stored, generation).finally(() => {
      // Only release the slot if it still holds THIS refresh.
      if (refreshing?.promise === tracked) refreshing = undefined;
    });
    refreshing = { generation, promise: tracked };
    return tracked;
  }

  /**
   * MEDIO-2: wait on an in-flight salvage instead of starting a competing
   * refresh with the same `refresh_token`.
   *
   * The join inherits the same latency contract as the original attempt: the
   * caller is released after `timeoutMs` whether or not the salvage has landed,
   * so joining can never make a request wait the full salvage window. If the
   * salvage concludes with nothing to hand back, this surfaces a retryable
   * error rather than immediately firing the second grant it just avoided — by
   * the time the caller retries, the slot is clear and a fresh refresh starts
   * from whatever is actually stored.
   */
  async function joinPendingSalvage(salvage: {
    promise: Promise<OAuthTokens | undefined>;
  }): Promise<OAuthTokens> {
    const timedOut = Symbol('salvage-join-timeout');
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      salvage.promise,
      new Promise<typeof timedOut>((resolve) => {
        // Delivers this caller's answer, like the soft timeout it mirrors, so
        // it is deliberately not unref'd. See the note in runRefreshWithSalvage.
        timer = setTimeout(() => resolve(timedOut), timeoutMs);
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);

    if (outcome !== timedOut && outcome !== undefined) return outcome;

    // Thrown from refreshNow, which is outside performRefresh's catch, so this
    // is what the caller actually sees — it carries the package's own error
    // type rather than a bare Error, like every other failure callers are
    // handed. It is deliberately NOT one of the three classes auth() reacts to
    // by invalidating credentials: nothing here says the refresh_token is bad.
    throw new McpAuthKitError(
      'token_refresh',
      outcome === timedOut
        ? `A refresh for these credentials is already in flight and did not answer within timeoutMs (${timeoutMs}ms)`
        : 'A refresh for these credentials was already in flight and did not yield usable tokens',
      'retry the operation — a second refresh_token grant was deliberately not sent while the first is outstanding, because presenting a rotated refresh_token twice is what makes a strict authorization server revoke the whole token family; the in-flight attempt may still land and persist rotated credentials',
    );
  }

  /**
   * MEDIO-1 / MEDIO-2: the single place that decides what a refresh whose
   * generation has been superseded should resolve to. Called from both the
   * success and the failure path, so a stale refresh can never leak its outcome
   * into the newer generation by either route.
   *
   * - Superseded by a newer `saveTokens()`: valid tokens exist. Hand those back
   *   (last-write-wins, which is what an unwrapped provider would have done)
   *   instead of failing a request that has a perfectly good answer.
   * - Superseded by `invalidateCredentials()`: the credentials are gone. There
   *   is nothing to hand back, so surface it.
   */
  async function resolveSupersededRefresh(): Promise<OAuthTokens> {
    if (generationReason === 'save') {
      const current = await provider.tokens();
      if (current) return current;
      // Tokens were saved and then removed out-of-band; fall through to the
      // invalidated-shaped error rather than inventing a result.
    }
    throw new McpAuthKitError(
      'token_refresh',
      'The refresh was superseded while in flight: its credentials were invalidated or replaced before the response arrived, so the result was discarded',
      'this is a benign race, not a failure of the refresh itself — retry the operation; the newer credentials, or the re-authorization the invalidation implies, take precedence',
    );
  }

  /**
   * Runs the refresh grant with a SOFT timeout: the caller is released after
   * `timeoutMs`, but the request is not aborted. If it lands afterwards with
   * tokens, they are persisted rather than thrown away — the refresh grant
   * rotates the refresh token server-side on receipt, so discarding a late
   * success destroys the only credentials that still work.
   *
   * The late write goes through the same generation check as every other late
   * result in this wrapper: a response belonging to credentials that have since
   * been replaced or invalidated is dropped, never resurrected.
   */
  async function runRefreshWithSalvage(
    run: () => Promise<OAuthTokens>,
    generation: number,
    abort: () => void,
  ): Promise<OAuthTokens> {
    if (refreshSalvageMs <= 0) return run();

    const attempt = run();
    const timedOut = Symbol('refresh-soft-timeout');
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      attempt.then(
        (value) => ({ ok: true as const, value }),
        (error: unknown) => ({ ok: false as const, error }),
      ),
      new Promise<typeof timedOut>((resolve) => {
        // ALTO-2: deliberately NOT unref'd, for the same reason as the store
        // race above — this timer delivers the caller's answer. What must not
        // hold the process is the long salvage deadline inside the fetch
        // wrapper, and that one IS unref'd.
        timer = setTimeout(() => resolve(timedOut), timeoutMs);
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);

    if (outcome !== timedOut) {
      if (outcome.ok) return outcome.value;
      throw outcome.error;
    }

    // Soft timeout. Release the caller, keep the request.
    //
    // MEDIO-2: the salvage is published before the caller is released, so a
    // tokens() call arriving in the meantime joins it rather than sending the
    // same refresh_token a second time.
    let salvage: Promise<OAuthTokens | undefined>;
    salvage = attempt.then(
      async (late): Promise<OAuthTokens | undefined> => {
        // The salvage may land long after the caller gave up, so it is exactly
        // the kind of late writer rounds 4-7 exist to guard: only apply it if
        // nothing authoritative has happened since this attempt started.
        if (generation !== expiryGeneration) return undefined;
        const stamped: OAuthTokens = { ...late, issuer: configuredIssuer };
        try {
          await saveTokens(stamped);
        } catch {
          // Best effort: the caller already failed this attempt, and the
          // wrapped provider's own storage error is its to surface. The tokens
          // themselves are still good, so a joiner still gets them.
        }
        return stamped;
      },
      () => {
        // A late FAILURE has nothing to salvage. It also must not open the
        // failure-cache window or be rethrown: it belongs to an attempt the
        // caller has already been told failed. Joiners see `undefined` and get
        // a retryable error rather than inheriting a failure they never asked
        // for.
        return undefined;
      },
    );
    const salvageRegistration: SalvageRegistration = { generation, promise: salvage, abort };
    pendingSalvages.add(salvageRegistration);
    void salvage.then(() => {
      // Removed by identity, so a concurrent salvage for another generation is
      // never dropped along with this one.
      pendingSalvages.delete(salvageRegistration);
    });

    const softTimeout = new Error(
      `The refresh request did not answer within timeoutMs (${timeoutMs}ms)`,
    );
    // Named so the existing classification treats it exactly like any other
    // abort: transient, never cached, never one of auth()'s recoverable classes.
    softTimeout.name = 'AbortError';
    throw softTimeout;
  }

  /**
   * MEDIO-1: the cancel handle is registered BEFORE the function does anything
   * that can suspend, and released, identity-guarded, when the function
   * returns.
   *
   * Registering it after `await provider.clientInformation()` — real I/O in any
   * non-toy provider — left a window in which a revocation found nothing to
   * abort and the refresh grant then went out AFTER the credentials were gone,
   * on a socket nothing could reach for up to max(timeoutMs, refreshSalvageMs).
   * Narrowing that window was not enough twice over, so the handle now exists
   * for the whole life of the call by construction, and the body re-checks the
   * generation after every suspension point rather than trusting the check it
   * entered with.
   */
  async function performRefresh(stored: OAuthTokens, generation: number): Promise<OAuthTokens> {
    // `withTimeout` combines a caller-supplied signal with its own deadline
    // rather than overriding it, so this composes with the salvage deadline.
    const salvageAbort = new AbortController();
    const registration: RefreshRegistration = {
      generation,
      abort: () => salvageAbort.abort(),
    };
    inFlightRefreshes.add(registration);
    try {
      return await runRefresh(stored, generation, salvageAbort);
    } finally {
      // A salvage that outlives this frame keeps its own handle in
      // `pendingSalvages`, so cancellation stays reachable without this one.
      inFlightRefreshes.delete(registration);
    }
  }

  async function runRefresh(
    stored: OAuthTokens,
    generation: number,
    salvageAbort: AbortController,
  ): Promise<OAuthTokens> {
    // Bajo-7: a refresh_token the authorization server has definitively
    // rejected (invalid_grant, etc.) will be rejected identically on every
    // subsequent call. Without this window, every tokens() call launches
    // another doomed request.
    if (Date.now() < refreshBlockedUntil) {
      // FIX 2: if the cached failure was one of the three classes the SDK's
      // own auth() recovers from, serving it from cache must preserve that
      // type too — otherwise the negative cache re-introduces exactly the
      // broken recovery the unwrapped rethrow below exists to fix.
      if (isSdkRecoverableOAuthError(refreshBlockedCause)) {
        throw refreshBlockedCause;
      }
      throw new McpAuthKitError(
        'token_refresh',
        'Not retrying the refresh_token grant: a previous attempt failed with a definitive error and is still within the failure-cache window',
        `the stored refresh_token needs replacing, not retrying — complete a fresh authorization, or call invalidateCredentials() to clear this window immediately (it otherwise lapses after refreshFailureCacheMs, currently ${refreshFailureCacheMs}ms)`,
        refreshBlockedCause,
      );
    }

    const clientInfo = await provider.clientInformation();
    // MEDIO-1: the only suspension point before the grant goes out. A
    // revocation landing during it has already aborted this registration, but
    // an abort alone does not stop a request that has not started yet — so the
    // grant must not be sent at all. Checking here closes it by construction
    // instead of relying on the request being cancellable once it exists.
    if (generation !== expiryGeneration || salvageAbort.signal.aborted) {
      return resolveSupersededRefresh();
    }
    if (!clientInfo) {
      throw new McpAuthKitError(
        'token_refresh',
        'Cannot refresh the access token because no client information is registered',
        'call clientInformation()/register the client before tokens() is used, or configure the `registration` option so mcp-auth-kit can register automatically',
      );
    }

    // B2: compare issuers the same way the SDK itself does (issuersMatch —
    // tolerant of a trailing-slash difference and URL normalization), not
    // with raw string equality. The SDK's own fallback authorization server
    // URL (when RFC 9728 discovery isn't available) is always slash-suffixed
    // (`String(new URL('/', serverUrl))`), so a strict `!==` here would
    // false-positive on exactly the configuration this package tells users
    // to use.
    if (clientInfo.issuer !== undefined && !issuersMatch(clientInfo.issuer, configuredIssuer)) {
      throw new McpAuthKitError(
        'token_refresh',
        `Refusing to refresh: the stored client is bound to authorization server "${sanitizeForMessage(clientInfo.issuer)}", but this wrapper is configured for "${configuredIssuer}"`,
        'reconfigure authorizationServerUrl to match the client\'s issuer, or re-register the client against the configured authorization server — mcp-auth-kit will not send a refresh_token or client credentials to a mismatched issuer',
      );
    }
    if (stored.issuer !== undefined && !issuersMatch(stored.issuer, configuredIssuer)) {
      throw new McpAuthKitError(
        'token_refresh',
        `Refusing to refresh: the stored tokens were issued by "${sanitizeForMessage(stored.issuer)}", but this wrapper is configured for "${configuredIssuer}"`,
        'do not reuse a single mcp-auth-kit wrapper instance across multiple authorization servers; discard the stored tokens and re-authorize against the configured authorizationServerUrl',
      );
    }

    let refreshed: OAuthTokens;
    try {
      refreshed = await runRefreshWithSalvage(
        () =>
          refreshAuthorization(authorizationServerUrl, {
            clientInformation: clientInfo,
            refreshToken: stored.refresh_token as string,
            resource,
            addClientAuthentication: provider.addClientAuthentication,
            fetchFn: (url, init) => {
              // Fold any signal the SDK supplies into ours rather than dropping
              // either one — both must be able to cancel this request.
              if (init?.signal) {
                if (init.signal.aborted) salvageAbort.abort();
                else
                  init.signal.addEventListener('abort', () => salvageAbort.abort(), {
                    once: true,
                  });
              }
              return refreshFetchFn(url, { ...init, signal: salvageAbort.signal });
            },
          }),
        generation,
        () => salvageAbort.abort(),
      );
    } catch (error) {
      // sanitizedCause mutates `error.message` (and `errorUri`) in place and
      // returns the very same object, so `error` itself is sanitized from here
      // on — the unwrapped rethrow below is safe with respect to B11.
      const cause = sanitizedCause(error);

      // MEDIO-1: check supersession BEFORE doing anything with this failure.
      // A failure computed under an older generation describes credentials that
      // have since been replaced or discarded, so it must neither open a
      // suppression window over the newer state nor — critically — be rethrown
      // unwrapped as one of the three classes auth() reacts to by invalidating
      // credentials. Doing either would let a stale failure reach across
      // generations, which is exactly the invariant this mechanism exists for.
      if (generation !== expiryGeneration) {
        return resolveSupersededRefresh();
      }

      // Bajo-7: only DEFINITIVE failures open the suppression window.
      // Transient ones (network error, server_error, 429, our own timeout)
      // may well succeed on the next attempt and must stay retryable.
      if (!isRetryableOAuthError(error)) {
        commitExpiryState(generation, {
          refreshFailure: { until: Date.now() + refreshFailureCacheMs, cause },
        });
      }
      // FIX 2: the SDK's auth() recovers from exactly three error classes by
      // calling invalidateCredentials() and retrying into a re-authorization
      // redirect. Because auth() calls provider.tokens() — this wrapper —
      // BEFORE its own refresh logic, a refresh failure raised here is what
      // auth() sees. Wrapping these three in McpAuthKitError (which extends
      // Error, not OAuthError) makes auth()'s `instanceof` match fail and
      // turns a recoverable situation into a hard error for the caller. So
      // these three are rethrown untouched; everything else keeps the typed
      // mcp-auth-kit wrapper.
      if (isSdkRecoverableOAuthError(error)) {
        throw error;
      }
      throw new McpAuthKitError(
        'token_refresh',
        'Refreshing the access token via the refresh_token grant failed',
        isAbortError(error) && refreshSalvageMs > 0
          ? // Telling the caller to discard tokens here would be actively
            // wrong: the request may still be in flight, and if it lands with
            // rotated credentials they are persisted. Retry rather than reset.
            `the request did not answer in time and was not aborted — if it still lands with rotated credentials they will be persisted, so retry rather than discarding anything; raise timeoutMs if this authorization server is routinely this slow`
          : 'the refresh_token may have been revoked or expired; discard stored tokens and re-run the authorization code flow',
        cause,
      );
    }

    // If credentials were invalidated (or superseded by a newer saveTokens())
    // while this request was in flight, the tokens we just obtained describe a
    // generation that no longer exists. Persisting them would resurrect
    // discarded credentials, overwrite the `expiresAt = 0` revocation sentinel
    // invalidateCredentials() wrote, and clear a failure window that belongs to
    // the newer generation.
    if (generation !== expiryGeneration) {
      return resolveSupersededRefresh();
    }

    // B1: stamp `issuer` before persisting, same as the SDK's own auth()
    // does (`await provider.saveTokens({ ...tokens, issuer })`,
    // auth.js:336/:361). refreshAuthorization() parses the response with a
    // schema that OMITS `issuer` (auth.js `TokenResponseSchema =
    // OAuthTokensSchema.omit({ issuer: true })`), so without this, every
    // refresh mcp-auth-kit performs would silently erase the stamp that A3's
    // issuer-binding check depends on, disabling that check on its first use.
    const stamped: OAuthTokens = { ...refreshed, issuer: configuredIssuer };
    await saveTokens(stamped);
    return stamped;
  }

  async function saveTokens(newTokens: OAuthTokens): Promise<void> {
    // Persist first: if the wrapped provider's storage fails, propagate the
    // error and leave `expiresAt` untouched rather than believing a token
    // was saved when it wasn't (which would silently serve a stale token
    // forever afterward).
    // BAJO-D: revocations are counted at CALL time, so this captures every
    // invalidation that arrives from here on — whether while this save waits
    // for its turn or while its write is in flight.
    const invalidationsAtEntry = invalidationCount;
    // BAJO-D: the generation is captured when this save ACQUIRES ITS TURN, not
    // at the call site. Captured at the call site, two saves enqueued before
    // either had written shared one starting generation, and the second one
    // then misread the first one's bump as "someone superseded me" — skipping
    // its own expiry commit and leaving storage holding ITS tokens under the
    // FIRST save's expiry. Rounds 6-7 established that a generation is captured
    // alongside the data it describes; the data here is the write this closure
    // is about to perform, which is what the queue has just authorized, not the
    // call that requested it.
    //
    // KNOWN FRAGILITY, recorded deliberately rather than papered over. For two
    // overlapping saves this is correct only because of MICROTASK ORDERING, not
    // because of an explicit barrier: the earlier save's post-write block —
    // which calls beginGeneration() — is a `.then` continuation registered on
    // the queue inside serializeCredentialMutation BEFORE its caller awaits, so
    // it runs before the later save's closure here reads expiryGeneration.
    //
    // The margin is exactly ONE TICK, and it is deterministic under ECMA-262
    // rather than implementation-dependent. `serializeCredentialMutation`
    // registers `credentialMutations = next.then(...)` before it returns `next`
    // to the caller's await, so on `next`'s reaction list the successor's chain
    // link is entry 0 and the predecessor's post-await resumption is entry 1 —
    // and beginGeneration() runs synchronously inside that resumption. Thenable
    // assimilation and extra microtask hops inside the wrapped provider are all
    // absorbed before `next` settles, so they shift both reactions equally; this
    // was confirmed across synchronous, native-promise, non-native-thenable,
    // deeply-chained-thenable and macrotask provider shapes. It is nonetheless
    // an ordering property rather than something enforced in the code, so it is
    // invisible to a reader of either function alone.
    //
    // It was left as an ordering property on purpose. Making it explicit means
    // holding the queue turn across the post-write commit, which would put the
    // expiryStore write (bounded, but still I/O) inside the critical section
    // every credential mutation waits on — trading a correctness property that
    // currently holds for a new latency coupling on the path that revocation
    // ordering depends on. The failure this would guard against is also benign
    // by comparison: a stale expiry, self-healing on the transport's next 401.
    // If a future change moves beginGeneration() off that synchronous
    // continuation, this assumption breaks silently — the test named
    // "the later of two overlapping saves owns both storage and expiry" is what
    // catches that.
    let generationAtTurn = expiryGeneration;
    // Ordered against any concurrent credential mutation, so a revocation
    // called after this save cannot be overtaken by this save's storage write.
    await serializeCredentialMutation(() => {
      generationAtTurn = expiryGeneration;
      return provider.saveTokens(newTokens);
    });
    // ALTO-1: re-check AFTER the write resolves, not only before it started.
    // `provider.saveTokens` is real I/O — disk, keychain, network — and an
    // `invalidateCredentials()` landing during it clears the state and writes
    // the revocation sentinel. Committing afterwards would put an expiry back
    // over a revocation and overwrite that sentinel in the store. Every caller
    // of this function checks the generation before calling it; that check
    // alone cannot see what happens during the await.
    //
    // The two conditions are not redundant. The counter catches a revocation,
    // which is the case that must bail; the generation catches anything else
    // that made this write non-current by the time it landed.
    if (invalidationsAtEntry !== invalidationCount) return;
    if (generationAtTurn !== expiryGeneration) return;
    const ttlMs =
      newTokens.expires_in !== undefined
        ? clampServerExpiresInSeconds(newTokens.expires_in) * 1000
        : fallbackTokenTtlMs;
    // We now hold accepted tokens: this is authoritative state that supersedes
    // anything still in flight from an earlier generation (notably a cold
    // expiryStore read, which would otherwise resolve later and overwrite this
    // fresh expiry with the persisted one). Bumping the generation first means
    // those stale results are dropped by commitExpiryState.
    const generation = beginGeneration('save');
    const newExpiresAt = Date.now() + ttlMs;
    commitExpiryState(generation, {
      expiresAt: newExpiresAt,
      expiryStoreChecked: true,
      // Bajo-7: we hold tokens that were accepted, so whatever definitive
      // failure opened the suppression window no longer applies.
      refreshFailure: null,
    });
    // Persist the value THIS save computed, and only while it is still the
    // current generation — otherwise we would write an expiry for credentials
    // that have since been invalidated, overwriting the revocation sentinel.
    if (expiryStore && generation === expiryGeneration) {
      // M4 + MEDIO-3: the wrapped provider's own save already succeeded above —
      // a supplementary expiry cache that fails, or hangs, must not turn that
      // success into a thrown error or into an unbounded wait. Degrade to
      // in-memory-only tracking for the rest of this process instead.
      //
      // BAJO-1: ordered against this instance's other store writes, and
      // tracked so invalidateCredentials() can wait for all of them rather
      // than only the newest.
      await queueStoreWrite('set', () => expiryStore.set(resourceKey, newExpiresAt));
    }
  }

  const wrapped: OAuthClientProvider = {
    get redirectUrl() {
      return provider.redirectUrl;
    },
    get clientMetadata() {
      return provider.clientMetadata;
    },
    clientInformation,
    tokens,
    saveTokens,
    redirectToAuthorization: (authorizationUrl) => provider.redirectToAuthorization(authorizationUrl),
    saveCodeVerifier: (codeVerifier) => provider.saveCodeVerifier(codeVerifier),
    codeVerifier: () => provider.codeVerifier(),
  };

  // Every member below is defined ONLY if the wrapped provider defines it —
  // see the feature-detection note in the doc comment above.
  if (provider.clientMetadataUrl !== undefined) {
    wrapped.clientMetadataUrl = provider.clientMetadataUrl;
  }
  if (provider.state) {
    wrapped.state = () => provider.state!();
  }
  if (provider.saveClientInformation) {
    // MEDIO-A: same queue as every other credential write — see the note in
    // the auto-registration path. The SDK's own bindClientInformation()
    // (auth.js:286-295 in 1.31.0) writes through here, but ONLY when the stored
    // client information has no `issuer` stamp — not on every auth() run, as an
    // earlier version of this comment claimed. Both the SDK and this package's
    // registration path always stamp, so in practice that writer only appears
    // for legacy storage written before stamping existed.
    //
    // There is deliberately NO invalidation guard here, unlike saveTokens().
    // This is an explicit, caller-initiated write, so last call wins: a
    // saveClientInformation() issued after a revocation is the caller saying
    // "store this", and second-guessing it would make an unwrapped provider and
    // a wrapped one disagree about a plain setter. What the queue guarantees is
    // ordering — this write cannot overtake a revocation that was requested
    // first. Choosing what to write after a logout is the caller's business.
    wrapped.saveClientInformation = (info) =>
      serializeCredentialMutation(() => provider.saveClientInformation!(info));
  }
  if (provider.addClientAuthentication) {
    wrapped.addClientAuthentication = provider.addClientAuthentication;
  }
  if (provider.validateResourceURL) {
    wrapped.validateResourceURL = (serverUrl, res) => {
      const normalized = res !== undefined ? normalizeResourceIndicator(res) : undefined;
      // The wrapped provider is the one asserting the resource is valid for
      // its own server — we only pre-normalize the trailing slash for it,
      // we never invent or weaken that validation ourselves.
      return provider.validateResourceURL!(serverUrl, normalized);
    };
  }
  if (provider.invalidateCredentials) {
    wrapped.invalidateCredentials = async (scope) => {
      const tracked = scope === 'all' || scope === 'tokens';

      // Everything that must be true the instant this call is made happens
      // here, synchronously, before any await: a concurrent saveTokens() whose
      // write is already in flight has to be able to see this revocation the
      // moment it lands, and a tokens() running now must not serve what is
      // being revoked.
      if (tracked) {
        // BAJO-D: counted at call time. This is what tells a landing save
        // "a revocation happened, bail" as distinct from "an earlier save
        // moved the generation, you are the newer write, commit".
        invalidationCount += 1;
        // Start a new generation: anything still in flight from the previous
        // one (a cold store read, a refresh) now describes credentials that no
        // longer exist, and commitExpiryState will drop whatever it tries to
        // write.
        const generation = beginGeneration('invalidate');
        commitExpiryState(generation, {
          expiresAt: undefined,
          // Force the next tokens() call to re-consult expiryStore rather than
          // trusting a cached "nothing to check" from before the invalidation.
          expiryStoreChecked: false,
          // Bajo-7: the credentials that failed are being discarded, so the
          // suppression window they opened no longer applies.
          refreshFailure: null,
        });
        // Drop the shared in-flight read so the next one starts from scratch
        // rather than reusing a promise issued for the old generation.
        expiryLoad = undefined;
        // MEDIO-1: a refresh still waiting on a response belongs to credentials
        // that no longer exist. Its write would be discarded by the generation
        // check anyway, but leaving the request in flight keeps a rotated
        // refresh_token moving on a connection the user just asked to tear
        // down, and holds the socket until the request's own deadline. This
        // covers the request in every phase, not only once it has become a
        // salvage — the pre-timeout window is the common case.
        abortInFlightRefreshes();
      }

      // MEDIO-B: revoke at the wrapped provider IMMEDIATELY, never from behind
      // the queue. A revocation's latency is a security property: `storeTimeoutMs`
      // exists precisely so a slow dependency cannot stand between a revocation
      // request and the credentials being gone, and the SDK's auth() awaits this
      // call before retrying (auth.js:191/195), so blocking here stalls its whole
      // recovery path. Queueing this behind an in-flight `provider.saveTokens()`
      // made a hung storage layer do exactly that.
      //
      // Ordering is preserved by a SECOND, idempotent pass queued behind
      // whatever was already in flight — so a save that started before this call
      // and lands after the immediate revocation is followed by another
      // revocation rather than left standing. Nobody awaits that pass: awaiting
      // it would reinstate the block it exists to avoid, and the caller's own
      // guarantee ("the credentials are gone now") is already satisfied by the
      // immediate call above. It is also what keeps a reentrant invalidation
      // from inside a provider write structurally deadlock-free (BAJO-C).
      const revokeNow = provider.invalidateCredentials!(scope);
      const revokeInOrder = serializeCredentialMutation(
        () => provider.invalidateCredentials!(scope),
        // Nobody awaits this pass, so it cannot deadlock even when the provider
        // revokes from inside its own write — and in that case it is precisely
        // what stops the write it is nested in from standing.
        { allowReentrant: true },
      );
      // Never unhandled: the immediate call is the one whose failure the caller
      // must see, and this one's identical error would otherwise surface as an
      // unhandled rejection.
      void revokeInOrder.catch(() => {});

      // MEDIO-3: the wrapped provider — the thing that actually holds the
      // credentials — is revoked BEFORE the store is touched. A slow or hung
      // expiry cache must never be what stands between a revocation request and
      // the tokens being gone.
      //
      // If this throws, the store cleanup below is skipped and a persisted
      // expiry can outlive this call. That is deliberate and coherent, not a
      // gap: the throw means the credentials were NOT revoked, so they are still
      // there, and the expiry that describes them is still the right answer for
      // them. The caller sees the failure and can retry. Writing the revocation
      // sentinel here instead would claim a revocation that did not happen.
      await revokeNow;

      if (!tracked) return;

      if (expiryStore) {
        // BAJO-1: ordering against concurrent saveTokens() store writes comes
        // from the queue itself — the delete below is enqueued after every set
        // already issued, so no straggler can land after it and restore a
        // live-looking expiry. MEDIO-2: there is deliberately no separate wait
        // on those sets here. Waiting on them bought nothing the chain does not
        // already guarantee, and it made the revocation's latency the SUM of
        // every outstanding write's timeout — on the path the SDK's auth()
        // awaits before it can recover. This closes the ordering window within
        // a process; two processes racing on one store is outside what an
        // in-process wrapper can serialize (see README).
        //
        // M5: an un-deleted persisted expiry would otherwise outlive the
        // credentials it described — remove it, or if the store can't delete,
        // overwrite it with a sentinel that reads as "already expired" rather
        // than leaving the stale (still-valid-looking) value. Queued like every
        // other store write, so it is ordered after them rather than racing
        // whatever was already on its way.
        await queueStoreWrite(expiryStore.delete ? 'delete' : 'set', () =>
          expiryStore.delete ? expiryStore.delete(resourceKey) : expiryStore.set(resourceKey, 0),
        );
      }
    };
  }
  if (provider.prepareTokenRequest) {
    wrapped.prepareTokenRequest = (scope) => provider.prepareTokenRequest!(scope);
  }
  if (provider.saveDiscoveryState) {
    wrapped.saveDiscoveryState = (state) => provider.saveDiscoveryState!(state);
  }
  if (provider.discoveryState) {
    wrapped.discoveryState = () => provider.discoveryState!();
  }

  return wrapped;
}
