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

import { isRetryableOAuthError } from './classifyError.js';
import { McpAuthKitError } from './errors.js';
import { withTimeout } from './fetchTimeout.js';
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
   * Default: 30.
   */
  minExpiresInSeconds?: number;
  /**
   * Upper bound, in seconds, clamped onto a server-supplied `expires_in`
   * before it's trusted. Guards against an unreasonably large value leaving
   * a token that's actually been revoked looking valid indefinitely.
   * Default: 30 days.
   */
  maxExpiresInSeconds?: number;
  /**
   * Timeout, in ms, applied to every HTTP call mcp-auth-kit makes on the
   * client's behalf (registration, token refresh). A hung authorization
   * server must not be able to block the whole MCP client. Default: 30000.
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
  /** RFC 8707 resource indicator to send with token requests, pre-normalization. */
  resource?: string | URL;
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
  const registrationOptions = options.registration;
  const resource = options.resource;
  const fetchFn = withTimeout(options.fetchFn, timeoutMs);

  if (registrationOptions && !provider.saveClientInformation) {
    throw new McpAuthKitError(
      'client_registration',
      'Auto dynamic-client-registration was requested via the `registration` option, but the wrapped provider does not implement saveClientInformation',
      'implement saveClientInformation on the wrapped provider so a newly registered client can actually be persisted, or omit the `registration` option and register the client yourself',
    );
  }

  /** Wall-clock ms at which the current access token is considered expired. */
  let expiresAt: number | undefined;
  /** In-flight refresh, so concurrent tokens() calls share one refresh request. */
  let refreshing: Promise<OAuthTokens | undefined> | undefined;

  function clampExpiresInSeconds(expiresIn: number): number {
    return Math.min(Math.max(expiresIn, minExpiresInSeconds), maxExpiresInSeconds);
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
        { ...registrationOptions, shouldRetry: isRetryableOAuthError },
      );
    } catch (error) {
      throw new McpAuthKitError(
        'client_registration',
        `Dynamic client registration (RFC 7591) failed after ${registrationOptions.maxAttempts ?? 3} attempt(s)`,
        'verify the authorization server advertises a registration_endpoint and supports dynamic client registration, or pre-register a client and provide clientInformation() statically instead of relying on auto-registration',
        sanitizedCause(error),
      );
    }

    // `provider.saveClientInformation` is guaranteed to exist: checked at wrap time above.
    await provider.saveClientInformation!(registered);
    return registered;
  }

  async function tokens(): Promise<OAuthTokens | undefined> {
    const stored = await provider.tokens();
    if (!stored) return undefined;

    const needsRefresh =
      expiresAt === undefined || Date.now() >= expiresAt - refreshMarginMs;
    if (!needsRefresh) return stored;

    if (!stored.refresh_token) {
      if (expiresAt === undefined) {
        // We have no basis to know this token is actually stale (e.g. it was
        // never saved through this wrapper) and no refresh_token to renew it
        // with anyway — pass it through rather than blocking every call.
        return stored;
      }
      throw new McpAuthKitError(
        'token_refresh',
        'Access token has expired and no refresh_token is available',
        'the user must complete the OAuth authorization code flow again; the authorization server did not issue a refresh_token, or it was not persisted',
      );
    }

    const refreshed = await refreshNow(stored);
    return refreshed ?? stored;
  }

  function refreshNow(stored: OAuthTokens): Promise<OAuthTokens | undefined> {
    if (!refreshing) {
      refreshing = performRefresh(stored).finally(() => {
        refreshing = undefined;
      });
    }
    return refreshing;
  }

  async function performRefresh(stored: OAuthTokens): Promise<OAuthTokens> {
    const clientInfo = await provider.clientInformation();
    if (!clientInfo) {
      throw new McpAuthKitError(
        'token_refresh',
        'Cannot refresh the access token because no client information is registered',
        'call clientInformation()/register the client before tokens() is used, or configure the `registration` option so mcp-auth-kit can register automatically',
      );
    }

    if (clientInfo.issuer !== undefined && clientInfo.issuer !== configuredIssuer) {
      throw new McpAuthKitError(
        'token_refresh',
        `Refusing to refresh: the stored client is bound to authorization server "${sanitizeForMessage(clientInfo.issuer)}", but this wrapper is configured for "${configuredIssuer}"`,
        'reconfigure authorizationServerUrl to match the client\'s issuer, or re-register the client against the configured authorization server — mcp-auth-kit will not send a refresh_token or client credentials to a mismatched issuer',
      );
    }
    if (stored.issuer !== undefined && stored.issuer !== configuredIssuer) {
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
      throw new McpAuthKitError(
        'token_refresh',
        'Refreshing the access token via the refresh_token grant failed',
        'the refresh_token may have been revoked or expired; discard stored tokens and re-run the authorization code flow',
        sanitizedCause(error),
      );
    }
    await saveTokens(refreshed);
    return refreshed;
  }

  async function saveTokens(newTokens: OAuthTokens): Promise<void> {
    // Persist first: if the wrapped provider's storage fails, propagate the
    // error and leave `expiresAt` untouched rather than believing a token
    // was saved when it wasn't (which would silently serve a stale token
    // forever afterward).
    await provider.saveTokens(newTokens);
    const ttlMs =
      newTokens.expires_in !== undefined
        ? clampExpiresInSeconds(newTokens.expires_in) * 1000
        : fallbackTokenTtlMs;
    expiresAt = Date.now() + ttlMs;
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
    wrapped.invalidateCredentials = (scope) => {
      if (scope === 'all' || scope === 'tokens') {
        expiresAt = undefined;
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
