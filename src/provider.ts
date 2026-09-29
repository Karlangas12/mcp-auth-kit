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

import { McpAuthKitError } from './errors.js';
import { normalizeResourceIndicator } from './resource.js';
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
   * When set, enables auto dynamic-client-registration-with-retry: if the
   * wrapped provider has no stored client information, mcp-auth-kit performs
   * RFC 7591 registration itself (with exponential backoff) instead of
   * leaving a single unretried attempt to fail hard
   * (openai/codex#13200).
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
 * The returned provider is a drop-in replacement: pass it anywhere the
 * wrapped provider was used (e.g. `new Client(...).connect(transport, {
 * authProvider })` or the SDK's `auth()` orchestrator).
 */
export function wrapOAuthClientProvider(
  provider: OAuthClientProvider,
  options: McpAuthKitOptions,
): OAuthClientProvider {
  return new McpAuthKitProvider(provider, options);
}

class McpAuthKitProvider implements OAuthClientProvider {
  private readonly inner: OAuthClientProvider;
  private readonly authorizationServerUrl: string | URL;
  private readonly fetchFn: FetchLike | undefined;
  private readonly fallbackTokenTtlMs: number;
  private readonly refreshMarginMs: number;
  private readonly registrationOptions: BackoffOptions | undefined;
  private readonly resource: string | URL | undefined;

  /** Wall-clock ms at which the current access token is considered expired. */
  private expiresAt: number | undefined;
  /** In-flight refresh, so concurrent tokens() calls share one refresh request. */
  private refreshing: Promise<OAuthTokens | undefined> | undefined;

  constructor(provider: OAuthClientProvider, options: McpAuthKitOptions) {
    this.inner = provider;
    this.authorizationServerUrl = options.authorizationServerUrl;
    this.fetchFn = options.fetchFn;
    this.fallbackTokenTtlMs = options.fallbackTokenTtlMs ?? 55 * 60 * 1000;
    this.refreshMarginMs = options.refreshMarginMs ?? 30 * 1000;
    this.registrationOptions = options.registration;
    this.resource = options.resource;
  }

  get redirectUrl(): string | URL | undefined {
    return this.inner.redirectUrl;
  }

  get clientMetadata() {
    return this.inner.clientMetadata;
  }

  state(): string | Promise<string> {
    if (!this.inner.state) {
      throw new McpAuthKitError(
        'authorization',
        'state() was called but the wrapped provider does not implement it',
        'implement state() on the wrapped provider, or omit calling it',
      );
    }
    return this.inner.state();
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    const existing = await this.inner.clientInformation();
    if (existing) return existing;
    if (!this.registrationOptions) return undefined;

    let registered: OAuthClientInformationFull;
    try {
      registered = await withExponentialBackoff(
        () =>
          registerClient(this.authorizationServerUrl, {
            clientMetadata: this.inner.clientMetadata,
            fetchFn: this.fetchFn,
          }),
        this.registrationOptions,
      );
    } catch (error) {
      throw new McpAuthKitError(
        'client_registration',
        `Dynamic client registration (RFC 7591) failed after ${this.registrationOptions.maxAttempts ?? 3} attempt(s)`,
        'verify the authorization server advertises a registration_endpoint and supports dynamic client registration, or pre-register a client and provide clientInformation() statically instead of relying on auto-registration',
        error,
      );
    }

    await this.inner.saveClientInformation?.(registered);
    return registered;
  }

  saveClientInformation(
    clientInformation: OAuthClientInformationMixed,
  ): void | Promise<void> {
    return this.inner.saveClientInformation?.(clientInformation);
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    const stored = await this.inner.tokens();
    if (!stored) return undefined;

    const needsRefresh =
      this.expiresAt === undefined || Date.now() >= this.expiresAt - this.refreshMarginMs;
    if (!needsRefresh) return stored;

    if (!stored.refresh_token) {
      if (this.expiresAt === undefined) {
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

    const refreshed = await this.refreshNow(stored);
    return refreshed ?? stored;
  }

  private refreshNow(stored: OAuthTokens): Promise<OAuthTokens | undefined> {
    if (!this.refreshing) {
      this.refreshing = this.performRefresh(stored).finally(() => {
        this.refreshing = undefined;
      });
    }
    return this.refreshing;
  }

  private async performRefresh(stored: OAuthTokens): Promise<OAuthTokens> {
    const clientInformation = await this.inner.clientInformation();
    if (!clientInformation) {
      throw new McpAuthKitError(
        'token_refresh',
        'Cannot refresh the access token because no client information is registered',
        'call clientInformation()/register the client before tokens() is used, or configure the `registration` option so mcp-auth-kit can register automatically',
      );
    }

    try {
      const refreshed = await refreshAuthorization(this.authorizationServerUrl, {
        clientInformation,
        refreshToken: stored.refresh_token as string,
        resource: this.resource,
        addClientAuthentication: this.inner.addClientAuthentication,
        fetchFn: this.fetchFn,
      });
      await this.saveTokens(refreshed);
      return refreshed;
    } catch (error) {
      throw new McpAuthKitError(
        'token_refresh',
        'Refreshing the access token via the refresh_token grant failed',
        'the refresh_token may have been revoked or expired; discard stored tokens and re-run the authorization code flow',
        error,
      );
    }
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const ttlMs = tokens.expires_in !== undefined ? tokens.expires_in * 1000 : this.fallbackTokenTtlMs;
    this.expiresAt = Date.now() + ttlMs;
    await this.inner.saveTokens(tokens);
  }

  redirectToAuthorization(authorizationUrl: URL): void | Promise<void> {
    return this.inner.redirectToAuthorization(authorizationUrl);
  }

  saveCodeVerifier(codeVerifier: string): void | Promise<void> {
    return this.inner.saveCodeVerifier(codeVerifier);
  }

  codeVerifier(): string | Promise<string> {
    return this.inner.codeVerifier();
  }

  get addClientAuthentication() {
    return this.inner.addClientAuthentication;
  }

  async validateResourceURL(
    serverUrl: string | URL,
    resource?: string,
  ): Promise<URL | undefined> {
    const normalized = resource !== undefined ? normalizeResourceIndicator(resource) : undefined;

    if (this.inner.validateResourceURL) {
      return this.inner.validateResourceURL(serverUrl, normalized);
    }
    if (normalized === undefined) return undefined;

    try {
      return new URL(normalized);
    } catch (error) {
      throw new McpAuthKitError(
        'resource_validation',
        `The resource indicator "${resource}" is not a valid absolute URL`,
        'ensure the MCP server (or its protected resource metadata) advertises a well-formed resource identifier',
        error,
      );
    }
  }

  invalidateCredentials(
    scope: 'all' | 'client' | 'tokens' | 'verifier' | 'discovery',
  ): void | Promise<void> {
    if (scope === 'all' || scope === 'tokens') {
      this.expiresAt = undefined;
    }
    return this.inner.invalidateCredentials?.(scope);
  }
}
