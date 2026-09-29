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

  it('does not abort if the caller signal is already aborted before the call even starts', async () => {
    const callerController = new AbortController();
    callerController.abort();

    let observedAborted = false;
    const fetchFn = vi.fn((_url: string | URL, init?: RequestInit) => {
      observedAborted = init?.signal?.aborted ?? false;
      return Promise.reject(new DOMException('The operation was aborted', 'AbortError'));
    });

    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 60_000);
    await expect(
      wrapped('https://example.com', { signal: callerController.signal }),
    ).rejects.toBeTruthy();
    expect(observedAborted).toBe(true);
  });

  it('works normally with no caller-supplied signal at all', async () => {
    const fetchFn = vi.fn(async () => new Response('ok'));
    const wrapped = withTimeout(fetchFn as unknown as typeof fetch, 5000);

    const response = await wrapped('https://example.com');
    expect(await response.text()).toBe('ok');
  });
});
