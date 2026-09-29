import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';

/**
 * Wraps a fetch implementation so every request aborts after `timeoutMs`. A
 * hung authorization server must not be able to block the whole MCP client
 * forever — every fetch mcp-auth-kit makes on the client's behalf
 * (registration, refresh) goes through this.
 *
 * If the caller's own `init.signal` aborts, that also aborts the request
 * (combined, not overridden) — this is a public utility, and silently
 * dropping a caller's own cancellation would be its own bug.
 */
export function withTimeout(fetchFn: FetchLike | undefined, timeoutMs: number): FetchLike {
  const base: FetchLike = fetchFn ?? ((url, init) => fetch(url, init));
  return async (url, init) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const callerSignal = init?.signal ?? undefined;
    let onCallerAbort: (() => void) | undefined;
    if (callerSignal) {
      if (callerSignal.aborted) {
        controller.abort();
      } else {
        onCallerAbort = () => controller.abort();
        callerSignal.addEventListener('abort', onCallerAbort);
      }
    }
    try {
      return await base(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
      if (callerSignal && onCallerAbort) {
        callerSignal.removeEventListener('abort', onCallerAbort);
      }
    }
  };
}
