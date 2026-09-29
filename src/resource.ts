/**
 * Normalizes an RFC 8707 `resource` indicator by stripping a trailing slash.
 *
 * Some authorization servers (notably Microsoft Entra ID) reject or silently
 * misroute requests when the `resource` parameter carries a trailing slash
 * that the client added only because `new URL(...)` always yields one for a
 * pathless origin (see anthropics/claude-code#52871). We only strip a
 * *trailing* slash that isn't the entire string — `resource` is always
 * expected to be a non-empty absolute URL.
 */
export function normalizeResourceIndicator(resource: string): string {
  if (resource.length > 1 && resource.endsWith('/')) {
    return resource.slice(0, -1);
  }
  return resource;
}
