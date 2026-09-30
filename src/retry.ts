export interface BackoffOptions {
  /** Maximum number of attempts, including the first. Default 3. */
  maxAttempts?: number;
  /** Delay before the first retry, in ms. Default 250. */
  baseDelayMs?: number;
  /** Upper bound on any single delay, in ms. Default 5000. */
  maxDelayMs?: number;
  /** Injectable sleep function, for tests. Defaults to real timers. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * Decides whether a given error is worth retrying. Defaults to "retry
   * everything" — callers dealing with a classifiable error type (e.g. OAuth
   * errors, HTTP responses) should narrow this to transient failures only.
   */
  shouldRetry?: (error: unknown) => boolean;
  /**
   * Random jitter applied to each delay, as a fraction of the computed delay
   * (0 = none, 0.2 = ±10%). Default 0.2. Avoids synchronized retry storms
   * across multiple clients backing off in lockstep.
   */
  jitter?: number;
  /** Injectable randomness source, for deterministic tests. Defaults to Math.random. */
  random?: () => number;
}

/**
 * Deliberately NOT `unref()`'d, unlike the deadline timers elsewhere in this
 * package. Those are safety nets, where firing is the exceptional path, so they
 * must not be a reason for a short-lived process to stay alive. This one is the
 * opposite: the delay *is* the work the caller is awaiting. A pending promise
 * does not hold the Node event loop, so this timer is the only thing keeping
 * the process alive between retry attempts — unref it and a process waiting on
 * `clientInformation()` would exit silently mid-backoff.
 */
const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Retries `fn` with exponential backoff (delay doubles each attempt) plus
 * jitter, until it succeeds, `shouldRetry` rejects an error, or `maxAttempts`
 * is exhausted — in which case the last error is rethrown.
 */
export async function withExponentialBackoff<T>(
  fn: (attempt: number) => Promise<T>,
  options: BackoffOptions = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const maxDelayMs = options.maxDelayMs ?? 5000;
  const sleep = options.sleep ?? defaultSleep;
  const shouldRetry = options.shouldRetry ?? (() => true);
  const jitter = options.jitter ?? 0.2;
  const random = options.random ?? Math.random;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (error) {
      if (attempt === maxAttempts || !shouldRetry(error)) throw error;
      const rawDelay = Math.min(baseDelayMs * 2 ** (attempt - 1), maxDelayMs);
      const jitterFactor = 1 + (random() * 2 - 1) * (jitter / 2);
      await sleep(Math.max(0, rawDelay * jitterFactor));
    }
  }
  // Unreachable: the loop above always returns or throws.
  throw new Error('withExponentialBackoff: exhausted attempts without a result');
}
