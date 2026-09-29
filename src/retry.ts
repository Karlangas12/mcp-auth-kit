export interface BackoffOptions {
  /** Maximum number of attempts, including the first. Default 3. */
  maxAttempts?: number;
  /** Delay before the first retry, in ms. Default 250. */
  baseDelayMs?: number;
  /** Upper bound on any single delay, in ms. Default 5000. */
  maxDelayMs?: number;
  /** Injectable sleep function, for tests. Defaults to real timers. */
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Retries `fn` with exponential backoff (delay doubles each attempt, no
 * jitter) until it succeeds or `maxAttempts` is exhausted, in which case the
 * last error is rethrown.
 */
export async function withExponentialBackoff<T>(
  fn: (attempt: number) => Promise<T>,
  options: BackoffOptions = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const maxDelayMs = options.maxDelayMs ?? 5000;
  const sleep = options.sleep ?? defaultSleep;

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (error) {
      lastError = error;
      if (attempt === maxAttempts) break;
      const delay = Math.min(baseDelayMs * 2 ** (attempt - 1), maxDelayMs);
      await sleep(delay);
    }
  }
  throw lastError;
}
