import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';

/** A minimal, fully in-memory OAuthClientProvider, the kind real MCP clients write. */
export class InMemoryProvider implements OAuthClientProvider {
  private _clientInformation: OAuthClientInformationMixed | undefined;
  private _tokens: OAuthTokens | undefined;
  private _codeVerifier = 'test-code-verifier';

  constructor(private readonly metadata: OAuthClientMetadata) {}

  get redirectUrl() {
    return 'https://client.example.com/callback';
  }

  get clientMetadata() {
    return this.metadata;
  }

  clientInformation() {
    return this._clientInformation;
  }

  saveClientInformation(info: OAuthClientInformationMixed) {
    this._clientInformation = info;
  }

  tokens() {
    return this._tokens;
  }

  saveTokens(tokens: OAuthTokens) {
    this._tokens = tokens;
  }

  redirectToAuthorization() {
    /* no-op in tests */
  }

  saveCodeVerifier(codeVerifier: string) {
    this._codeVerifier = codeVerifier;
  }

  codeVerifier() {
    return this._codeVerifier;
  }

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
