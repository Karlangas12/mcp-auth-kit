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
   * Known limitation: the token refresh request is a non-idempotent POST.
   * If the authorization server actually completes (and rotates) the
   * refresh token before this timeout fires, but the response doesn't reach
   * us in time, we abort having never seen the new refresh token — the next
   * refresh attempt then fails with an invalid_grant-shaped error and forces
   * a full re-login. This is not retried (retrying a possibly-already-applied
   * mutation would reopen the double-registration risk M10 exists to avoid);
   * raise `timeoutMs` if your authorization server is known to be slow.
   */
  timeoutMs?: number;
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
   * Called instead of `console.warn` for the (rare) conditions mcp-auth-kit
   * needs to surface but must not throw on — currently only an `expiryStore`
   * returning a non-finite value. Defaults to `console.warn`. Pass a no-op
   * to silence, or route it into your own logger.
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
  /** In-flight refresh, so concurrent tokens() calls share one refresh request. */
  let refreshing: Promise<OAuthTokens> | undefined;
  /** Whether we've already warned about an invalid expiryStore value this process. */
  let warnedInvalidExpiryValue = false;
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
   * (the credentials are gone).
   */
  function beginGeneration(): number {
    expiryGeneration += 1;
    return expiryGeneration;
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
    // `provider.saveClientInformation` is guaranteed to exist: checked at wrap time above.
    await provider.saveClientInformation!(stamped);
    return stamped;
  }

  async function tokens(): Promise<OAuthTokens | undefined> {
    const stored = await provider.tokens();
    if (!stored) return undefined;

    if (expiresAt === undefined && !expiryStoreChecked) {
      // Capture the generation before awaiting, then commit under it. If a
      // saveTokens() landed or credentials were invalidated while this read
      // was in flight, commitExpiryState drops the result instead of
      // resurrecting a superseded expiry over newer state.
      const generation = expiryGeneration;
      const loaded = await loadExpiryFromStore();
      commitExpiryState(generation, { expiresAt: loaded, expiryStoreChecked: true });
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

    return refreshNow(stored);
  }

  function loadExpiryFromStore(): Promise<number | undefined> {
    if (!expiryStore) return Promise.resolve(undefined);
    // Bajo-2: dedupe concurrent cold reads the same way refreshes are deduped.
    if (!expiryLoad) {
      const load = (async () => {
        let raw: number | undefined;
        try {
          raw = await expiryStore.get(resourceKey);
        } catch {
          // A failing read is no worse than not having a store configured at
          // all — degrade to the no-adapter default rather than blocking tokens().
          return undefined;
        }
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

  function refreshNow(stored: OAuthTokens): Promise<OAuthTokens> {
    if (!refreshing) {
      refreshing = performRefresh(stored).finally(() => {
        refreshing = undefined;
      });
    }
    return refreshing;
  }

  async function performRefresh(stored: OAuthTokens): Promise<OAuthTokens> {
    // The generation this refresh belongs to. Everything it later writes is
    // committed under this value, so a saveTokens() or invalidateCredentials()
    // that lands while the request is in flight supersedes it.
    const generation = expiryGeneration;

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
      refreshed = await refreshAuthorization(authorizationServerUrl, {
        clientInformation: clientInfo,
        refreshToken: stored.refresh_token as string,
        resource,
        addClientAuthentication: provider.addClientAuthentication,
        fetchFn,
      });
    } catch (error) {
      // sanitizedCause mutates `error.message` in place and returns the very
      // same object, so `error` itself is sanitized from here on — the
      // unwrapped rethrow below is safe with respect to B11.
      const cause = sanitizedCause(error);
      // Bajo-7: only DEFINITIVE failures open the suppression window.
      // Transient ones (network error, server_error, 429, our own timeout)
      // may well succeed on the next attempt and must stay retryable.
      // Committed under this refresh's generation: a failure that belongs to
      // credentials already invalidated (or superseded by a newer
      // saveTokens()) must not open a window over the newer state.
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
        'the refresh_token may have been revoked or expired; discard stored tokens and re-run the authorization code flow',
        cause,
      );
    }

    // If credentials were invalidated (or superseded by a newer saveTokens())
    // while this request was in flight, the tokens we just obtained describe a
    // generation that no longer exists. Persisting them would resurrect
    // discarded credentials, overwrite the `expiresAt = 0` revocation sentinel
    // invalidateCredentials() wrote, and clear a failure window that belongs to
    // the newer generation. Drop the result instead of committing it.
    if (generation !== expiryGeneration) {
      throw new McpAuthKitError(
        'token_refresh',
        'The refresh completed but its credentials were invalidated or replaced while the request was in flight, so the result was discarded',
        'this is a benign race, not a failure of the refresh itself — retry the operation; the newer credentials (or the re-authorization the invalidation implies) take precedence',
      );
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
    await provider.saveTokens(newTokens);
    const ttlMs =
      newTokens.expires_in !== undefined
        ? clampServerExpiresInSeconds(newTokens.expires_in) * 1000
        : fallbackTokenTtlMs;
    // We now hold accepted tokens: this is authoritative state that supersedes
    // anything still in flight from an earlier generation (notably a cold
    // expiryStore read, which would otherwise resolve later and overwrite this
    // fresh expiry with the persisted one). Bumping the generation first means
    // those stale results are dropped by commitExpiryState.
    const generation = beginGeneration();
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
      // M4: the wrapped provider's own save already succeeded above — an
      // optional, supplementary expiry cache failing to write must not turn
      // that success into a thrown error. Degrade to in-memory-only tracking
      // for the rest of this process instead.
      try {
        await expiryStore.set(resourceKey, newExpiresAt);
      } catch {
        // best-effort; expiresAt is still tracked in memory for this instance.
      }
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
    wrapped.saveClientInformation = (info) => provider.saveClientInformation!(info);
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
      if (scope === 'all' || scope === 'tokens') {
        // Start a new generation FIRST: anything still in flight from the
        // previous one (a cold store read, a refresh) now describes
        // credentials that no longer exist, and commitExpiryState will drop
        // whatever it tries to write.
        const generation = beginGeneration();
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
        if (expiryStore) {
          // M5: an un-deleted persisted expiry would otherwise outlive the
          // credentials it described — remove it, or if the store can't
          // delete, overwrite it with a sentinel that reads as "already
          // expired" rather than leaving the stale (still-valid-looking) value.
          try {
            if (expiryStore.delete) {
              await expiryStore.delete(resourceKey);
            } else {
              await expiryStore.set(resourceKey, 0);
            }
          } catch {
            // best-effort cleanup; in-memory state is already cleared above.
          }
        }
      }
      return provider.invalidateCredentials!(scope);
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
