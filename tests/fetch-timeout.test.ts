import { describe, expect, it, vi } from 'vitest';
import { withTimeout } from '../src/fetchTimeout.js';

describe('withTimeout (Bajo-1): respects a caller-supplied AbortSignal instead of overriding it', () => {
  it('aborts when the callers own signal aborts, even before the timeout elapses', async () => {
    const callerController = new AbortController();
    let observedSignal: AbortSignal | undefined;

    const fetchFn = vi.fn((_url: string | URL, init?: RequestInit) => {
      observedSignal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted', 'AbortError'));
        });
      });
    });

    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 60_000);
    const resultPromise = wrapped('https://example.com', { signal: callerController.signal });

    callerController.abort();

    await expect(resultPromise).rejects.toMatchObject({ name: 'AbortError' });
    // The signal actually passed to the underlying fetch is mcp-auth-kit's
    // own combined signal, not the caller's raw one directly — but it must
    // reflect the caller's abort.
    expect(observedSignal?.aborted).toBe(true);
  });

  it('still aborts on its own timeout when the caller signal never fires', async () => {
    const callerController = new AbortController();
    const fetchFn = vi.fn((_url: string | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted', 'AbortError'));
        });
      });
    });

    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 20);
    await expect(
      wrapped('https://example.com', { signal: callerController.signal }),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('refuses to delegate at all when the caller signal is already aborted', async () => {
    // BAJO-5: previously the underlying fetch WAS invoked, with an aborted
    // signal, and it was left to that implementation to reject. Node's own
    // fetch does, but `base` is caller-supplied, and one that ignores the
    // signal would put an already-cancelled request on the wire — on the
    // refresh path, a refresh_token whose credentials were just revoked.
    const callerController = new AbortController();
    callerController.abort();

    const fetchFn = vi.fn(() => Promise.resolve(new Response('should never happen')));
    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 60_000);

    await expect(
      wrapped('https://example.com', { signal: callerController.signal }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('works normally with no caller-supplied signal at all', async () => {
    const fetchFn = vi.fn(async () => new Response('ok'));
    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 5000);

    const response = await wrapped('https://example.com');
    expect(await response.text()).toBe('ok');
  });
});

// Bajo-5 (round 3): the listener attached to the caller's signal was only
// removed in the `finally` of the awaited fetch. A non-conforming fetchFn that
// ignores the AbortSignal and never settles therefore leaked that listener
// onto a potentially long-lived, shared caller signal forever. Cleanup must be
// reachable from the timeout path too, bounding the listener's lifetime to
// `timeoutMs` regardless of how the underlying fetch behaves.
describe('withTimeout (Bajo-5): the caller-signal listener is cleaned up even if fetch never settles', () => {
  it('removes the listener once the timeout fires, for a fetch that ignores the signal entirely', async () => {
    const callerController = new AbortController();
    const signal = callerController.signal;
    const removeSpy = vi.spyOn(signal, 'removeEventListener');

    // Deliberately non-conforming: ignores the signal and never settles.
    const neverSettles = vi.fn(() => new Promise<Response>(() => {}));

    const wrapped = withTimeout(neverSettles as unknown as typeof fetch, 20);
    // Intentionally not awaited — this promise never resolves.
    void wrapped('https://example.com', { signal });

    expect(removeSpy).not.toHaveBeenCalled();

    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(neverSettles).toHaveBeenCalledTimes(1);
    expect(removeSpy).toHaveBeenCalledWith('abort', expect.any(Function));

    removeSpy.mockRestore();
  });

  it('still cleans up exactly once on the normal path (no double removal)', async () => {
    const callerController = new AbortController();
    const signal = callerController.signal;
    const removeSpy = vi.spyOn(signal, 'removeEventListener');

    const fetchFn = vi.fn(async () => new Response('ok'));
    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 5_000);

    await wrapped('https://example.com', { signal });

    expect(removeSpy).toHaveBeenCalledTimes(1);
    removeSpy.mockRestore();
  });
});
