import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import pkg from '../package.json' with { type: 'json' };

// M14 (round 3): peerDependencies used to declare ">=1.0.0" while the package
// actually requires features that only exist in much newer SDKs — the `issuer`
// stamp on tokens/client information (A3 and B1 are meaningless without it),
// several recent optional OAuthClientProvider members, and a deep subpath
// import that only resolves through the wildcard export map. A peer range that
// admits versions the package cannot possibly work with is a false promise.

const require = createRequire(import.meta.url);

/**
 * The SDK's export map routes "./package.json" through its `./*` wildcard to
 * `dist/esm/package.json` (a stub carrying only `{"type":"module"}`), so the
 * root manifest has to be read off disk rather than imported.
 */
function installedSdkVersion(): string {
  const entry = require.resolve('@modelcontextprotocol/sdk/client/auth.js');
  const marker = `@modelcontextprotocol${entry.includes('\\') ? '\\' : '/'}sdk`;
  const rootEnd = entry.indexOf(marker) + marker.length;
  const manifestPath = `${entry.slice(0, rootEnd)}${entry.includes('\\') ? '\\' : '/'}package.json`;
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { name: string; version: string };
  if (manifest.name !== '@modelcontextprotocol/sdk') {
    throw new Error(`Resolved the wrong manifest at ${manifestPath}: ${manifest.name}`);
  }
  return manifest.version;
}

/** Lower bound of a simple "^x.y.z" / ">=x.y.z" range, as [major, minor, patch]. */
function rangeFloor(range: string): [number, number, number] {
  const match = /(\d+)\.(\d+)\.(\d+)/.exec(range);
  if (!match) throw new Error(`Unrecognized version range: ${range}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compare(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return 0;
}

/**
 * The oldest SDK this package is actually verified against. Bump this together
 * with peerDependencies when the floor is re-tested against a newer SDK.
 */
const VERIFIED_FLOOR: [number, number, number] = [1, 31, 0];

describe('M14: the declared SDK peer range reflects what the package really needs', () => {
  it('does not admit SDK versions below the verified floor', () => {
    const declared = pkg.peerDependencies['@modelcontextprotocol/sdk'];
    expect(declared).toBeTruthy();
    expect(
      compare(rangeFloor(declared), VERIFIED_FLOOR),
      `peerDependencies declares "${declared}", whose floor is below the verified ` +
        `${VERIFIED_FLOOR.join('.')}. The package depends on the token/client "issuer" stamp, ` +
        'recent optional OAuthClientProvider members, and the subpath export map — none of ' +
        'which exist in older SDKs.',
    ).toBeGreaterThanOrEqual(0);
  });

  it('is satisfied by the SDK version the tests actually run against', () => {
    const installed = installedSdkVersion();
    const declaredFloor = rangeFloor(pkg.peerDependencies['@modelcontextprotocol/sdk']);
    expect(
      compare(rangeFloor(installed), declaredFloor),
      `The installed SDK (${installed}) is below the declared peer floor.`,
    ).toBeGreaterThanOrEqual(0);
  });

  it('keeps the dev dependency aligned with the declared peer floor', () => {
    const peerFloor = rangeFloor(pkg.peerDependencies['@modelcontextprotocol/sdk']);
    const devFloor = rangeFloor(pkg.devDependencies['@modelcontextprotocol/sdk']);
    expect(
      compare(devFloor, peerFloor),
      'The dev dependency floor must not be lower than the declared peer floor, or CI would ' +
        'be free to test against a version consumers are told is unsupported.',
    ).toBeGreaterThanOrEqual(0);
  });

  it('the features the floor exists for are actually present in the installed SDK', async () => {
    // The subpath import that only resolves via the wildcard export map.
    const errors = await import('@modelcontextprotocol/sdk/server/auth/errors.js');
    expect(errors.InvalidGrantError).toBeTypeOf('function');

    // The `issuer` stamp B1/A3 depend on.
    const shared = await import('@modelcontextprotocol/sdk/shared/auth.js');
    const parsed = shared.OAuthTokensSchema.parse({
      access_token: 'a',
      token_type: 'Bearer',
      issuer: 'https://auth.example.com',
    });
    expect(parsed.issuer).toBe('https://auth.example.com');
  });
});
