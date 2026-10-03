/**
 * The OAuth flow phase in which an {@link McpAuthKitError} occurred.
 */
export type McpAuthKitErrorPhase =
  | 'token_refresh'
  | 'client_registration'
  | 'authorization';

/**
 * Typed, actionable error thrown by mcp-auth-kit instead of failing silently.
 *
 * Every instance names the OAuth phase that failed and a concrete remediation
 * step, so callers (and their logs) never see a bare "unauthorized" with no
 * indication of what to fix.
 */
export class McpAuthKitError extends Error {
  readonly phase: McpAuthKitErrorPhase;
  readonly remediation: string;
  override readonly cause?: unknown;

  constructor(
    phase: McpAuthKitErrorPhase,
    message: string,
    remediation: string,
    cause?: unknown,
  ) {
    super(`[mcp-auth-kit:${phase}] ${message} — ${remediation}`);
    this.name = 'McpAuthKitError';
    this.phase = phase;
    this.remediation = remediation;
    this.cause = cause;
  }
}
