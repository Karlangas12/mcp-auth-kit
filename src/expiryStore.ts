/**
 * Optional, mcp-auth-kit-owned persistence hook for the access-token expiry
 * clock — NOT part of {@link OAuthClientProvider} from the SDK. It exists
 * purely so the wrapper's in-memory `expiresAt` can survive a process
 * restart, when a caller provides one.
 *
 * Deliberately just two required methods, no `OAuthClientProvider` shape:
 * this is not a token store (the wrapped provider already owns that via
 * `tokens()`/`saveTokens()`) — it only ever holds a millisecond timestamp
 * keyed by an opaque string the caller controls (`resourceKey`, defaulting
 * to `authorizationServerUrl` combined with `resource` when one is set).
 */
export interface ExpiryStore {
  /** Returns the persisted expiry (ms since epoch) for this key, or `undefined` if nothing is stored. */
  get(resourceKey: string): Promise<number | undefined>;
  /** Persists the expiry (ms since epoch) for this key. */
  set(resourceKey: string, expiresAtMs: number): Promise<void>;
  /**
   * Optional: removes any persisted expiry for this key, called on
   * credential invalidation. If not implemented, mcp-auth-kit writes a
   * sentinel (`expiresAt = 0`, i.e. "already expired") instead of leaving a
   * stale value in place.
   */
  delete?(resourceKey: string): Promise<void>;
}
