import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';

/**
 * Wraps a fetch implementation so every request aborts after `timeoutMs`.
 * A hung authorization server must not be able to block the whole MCP
 * client forever — every fetch mcp-auth-kit makes on the client's behalf
 * (registration, refresh) goes through this.
 */
export function withTimeout(fetchFn: FetchLike | undefined, timeoutMs: number): FetchLike {
  const base: FetchLike = fetchFn ?? ((url, init) => fetch(url, init));
  return async (url, init) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await base(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  };
}
