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
    const callerSignal = init?.signal ?? undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onCallerAbort: (() => void) | undefined;
    let cleanedUp = false;

    // Bajo-5: cleanup must be reachable even if `base` never settles. A
    // non-conforming fetch that ignores the AbortSignal would otherwise leave
    // our listener attached to the caller's (possibly long-lived, shared)
    // signal forever. Running this from the timeout path too bounds the
    // listener's lifetime to `timeoutMs` regardless of how `base` behaves.
    const cleanup = (): void => {
      if (cleanedUp) return;
      cleanedUp = true;
      if (timer !== undefined) clearTimeout(timer);
      if (callerSignal && onCallerAbort) {
        callerSignal.removeEventListener('abort', onCallerAbort);
      }
    };

    timer = setTimeout(() => {
      controller.abort();
      cleanup();
    }, timeoutMs);
    // ALTO-2: a deadline is a safety net, not work the process owes anyone. An
    // un-unref'd timer keeps the Node event loop alive, so a short-lived
    // client — which is what most MCP clients are — could not exit until it
    // elapsed. Unref'd, it still fires while the process is otherwise busy,
    // and stops being a reason to stay alive when it isn't.
    timer.unref?.();

    if (callerSignal) {
      if (callerSignal.aborted) {
        controller.abort();
      } else {
        onCallerAbort = () => {
          controller.abort();
          cleanup();
        };
        callerSignal.addEventListener('abort', onCallerAbort);
      }
    }

    try {
      return await base(url, { ...init, signal: controller.signal });
    } finally {
      cleanup();
    }
  };
}
