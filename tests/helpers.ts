import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { ExpiryStore } from '../src/expiryStore.js';

/**
 * A trivial in-memory ExpiryStore, standing in for whatever real persistence
 * (a file, a keychain entry, a DB row) a caller would actually use across
 * process restarts. Tests simulate "process restart" by keeping this store
 * alive across two separate `wrapOAuthClientProvider` instances.
 */
export class InMemoryExpiryStore implements ExpiryStore {
  private readonly values = new Map<string, number>();
  getCalls: string[] = [];
  setCalls: Array<{ resourceKey: string; expiresAtMs: number }> = [];

  async get(resourceKey: string): Promise<number | undefined> {
    this.getCalls.push(resourceKey);
    return this.values.get(resourceKey);
  }

  async set(resourceKey: string, expiresAtMs: number): Promise<void> {
    this.setCalls.push({ resourceKey, expiresAtMs });
    this.values.set(resourceKey, expiresAtMs);
  }
}

export interface InMemoryProviderOptions {
  /** Set to give this provider RFC 8707 resource validation of its own. */
  validateResourceURL?: (serverUrl: string | URL, resource?: string) => Promise<URL | undefined>;
  /** Set to give this provider an OAuth2 `state` implementation. */
  state?: () => string | Promise<string>;
  /** When false, this provider cannot persist client information at all (no saveClientInformation). */
  canSaveClientInformation?: boolean;
  /** Set to give this provider an invalidateCredentials() implementation. */
  canInvalidateCredentials?: boolean;
  /**
   * When true, `invalidateCredentials()` actually deletes the credentials, as
   * the SDK's interface intends ("provides a way for the client to invalidate
   * (e.g. delete) the specified credentials"), instead of only recording the
   * call. Opt-in so existing tests that rely on the stored tokens surviving an
   * invalidation keep working unchanged.
   */
  invalidateClearsCredentials?: boolean;
}

/** A minimal, fully in-memory OAuthClientProvider, the kind real MCP clients write. */
export class InMemoryProvider implements OAuthClientProvider {
  private _clientInformation: OAuthClientInformationMixed | undefined;
  private _tokens: OAuthTokens | undefined;
  private _codeVerifier = 'test-code-verifier';
  private readonly _opts: InMemoryProviderOptions;
  redirectToAuthorizationCalls: URL[] = [];
  validateResourceURLCalls: Array<{ serverUrl: string | URL; resource?: string }> = [];
  invalidateCredentialsCalls: string[] = [];

  constructor(
    private readonly metadata: OAuthClientMetadata,
    opts: InMemoryProviderOptions = {},
  ) {
    this._opts = opts;
    if (opts.validateResourceURL) {
      this.validateResourceURL = async (serverUrl, resource) => {
        this.validateResourceURLCalls.push({ serverUrl, resource });
        return opts.validateResourceURL!(serverUrl, resource);
      };
    }
    if (opts.state) {
      this.state = opts.state;
    }
    if (opts.canSaveClientInformation === false) {
      this.saveClientInformation = undefined as unknown as InMemoryProvider['saveClientInformation'];
    }
    if (opts.canInvalidateCredentials) {
      this.invalidateCredentials = async (scope) => {
        this.invalidateCredentialsCalls.push(scope);
        if (opts.invalidateClearsCredentials) {
          if (scope === 'all' || scope === 'tokens') this._tokens = undefined;
          if (scope === 'all' || scope === 'client') this._clientInformation = undefined;
        }
      };
    }
  }

  get redirectUrl() {
    return 'https://client.example.com/callback';
  }

  get clientMetadata() {
    return this.metadata;
  }

  clientInformation() {
    return this._clientInformation;
  }

  saveClientInformation?(info: OAuthClientInformationMixed) {
    this._clientInformation = info;
  }

  tokens() {
    return this._tokens;
  }

  saveTokens(tokens: OAuthTokens) {
    this._tokens = tokens;
  }

  redirectToAuthorization(authorizationUrl: URL) {
    this.redirectToAuthorizationCalls.push(authorizationUrl);
  }

  saveCodeVerifier(codeVerifier: string) {
    this._codeVerifier = codeVerifier;
  }

  codeVerifier() {
    return this._codeVerifier;
  }

  // Assigned conditionally in the constructor based on opts; declared here so
  // TypeScript knows the (optional) interface members can exist on instances.
  validateResourceURL?: OAuthClientProvider['validateResourceURL'];
  state?: OAuthClientProvider['state'];
  invalidateCredentials?: OAuthClientProvider['invalidateCredentials'];

  /** Test helper, not part of the interface. */
  presetClientInformation(info: OAuthClientInformationFull) {
    this._clientInformation = info;
  }
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

export function errorResponse(status: number, error = 'server_error'): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const testClientMetadata: OAuthClientMetadata = {
  redirect_uris: ['https://client.example.com/callback'],
  client_name: 'mcp-auth-kit test client',
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
};

export const testClientInformation: OAuthClientInformationFull = {
  client_id: 'test-client-id',
  ...testClientMetadata,
};

// ---------------------------------------------------------------------------
// Mock authorization/resource server, for tests that drive the SDK's real
// auth() orchestrator end to end instead of only exercising wrapper methods
// in isolation.
// ---------------------------------------------------------------------------

export interface MockServerConfig {
  mcpServerUrl: string; // e.g. 'https://mcp.example.com'
  authorizationServerUrl: string; // e.g. 'https://auth.example.com'
  /** The `resource` value the protected-resource metadata document advertises. */
  protectedResource: string;
  registrationResponse?: OAuthClientInformationFull | { status: number; body: unknown };
}

/**
 * A `fetchFn` implementation that answers the well-known discovery endpoints
 * and the registration endpoint the SDK's `auth()` hits during the discovery
 * + (optional) registration + redirect-to-authorization phase, i.e.
 * everything up to (not including) the authorization-code exchange.
 */
export function createMockAuthServer(config: MockServerConfig) {
  const calls: Array<{ url: string; method: string }> = [];

  const fetchFn = async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const method = init?.method ?? 'GET';
    calls.push({ url: u.toString(), method });

    if (u.pathname === '/.well-known/oauth-protected-resource' && method === 'GET') {
      return jsonResponse({
        resource: config.protectedResource,
        authorization_servers: [config.authorizationServerUrl],
      });
    }

    if (u.pathname === '/.well-known/oauth-authorization-server' && method === 'GET') {
      return jsonResponse({
        issuer: config.authorizationServerUrl,
        authorization_endpoint: `${config.authorizationServerUrl}/authorize`,
        token_endpoint: `${config.authorizationServerUrl}/token`,
        registration_endpoint: `${config.authorizationServerUrl}/register`,
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
      });
    }

    if (u.pathname === '/.well-known/openid-configuration') {
      return new Response('not found', { status: 404 });
    }

    if (u.pathname === '/register' && method === 'POST') {
      const resp = config.registrationResponse;
      if (resp && 'status' in resp) {
        return jsonResponse(resp.body, { status: resp.status });
      }
      return jsonResponse(
        resp ?? {
          client_id: 'dcr-client-id',
          ...testClientMetadata,
        },
      );
    }

    return new Response('not found', { status: 404 });
  };

  return { fetchFn, calls };
}

/**
 * BAJO-6: auto-registration now discovers the authorization server's real
 * `registration_endpoint` before posting, so a bare `fetchFn` sees a discovery
 * GET before the registration POST.
 *
 * This wraps a registration-only fetch so discovery is answered separately and
 * the caller's own spy counts registration attempts alone — which is what those
 * assertions were always about. It also makes the tests prove we post to the
 * ADVERTISED endpoint rather than a guessed one: the metadata deliberately puts
 * registration somewhere `new URL('/register', …)` would never find.
 */
export const advertisedRegistrationEndpoint = 'https://auth.example.com/oauth2/v2/register';

export function routeDiscovery(
  registrationFetch: (url: string | URL, init?: RequestInit) => Promise<Response>,
  options: { registrationEndpoint?: string | null } = {},
): (url: string | URL, init?: RequestInit) => Promise<Response> {
  const endpoint =
    options.registrationEndpoint === undefined
      ? advertisedRegistrationEndpoint
      : options.registrationEndpoint;
  return async (url, init) => {
    const href = String(url);
    if (href.includes('/.well-known/')) {
      if (endpoint === null) {
        // A server with no metadata document at all.
        return new Response('not found', { status: 404 });
      }
      return jsonResponse({
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
        registration_endpoint: endpoint,
        response_types_supported: ['code'],
      });
    }
    return registrationFetch(url, init);
  };
}
