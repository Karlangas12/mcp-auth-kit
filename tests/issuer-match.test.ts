import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { issuersMatch } from '../src/issuerMatch.js';

// Bajo-4 (round 3): src/issuerMatch.ts is a FORK of a private, non-exported
// function in the SDK (`issuersMatch` in client/auth.js). Round 3 verified it
// equivalent by fuzzing, but nothing stopped the SDK from changing that logic
// underneath us — the divergence would have been silent and permanent.
//
// This test closes that: it extracts the REAL function source from the
// installed SDK at test time, executes it, and differentially fuzzes it
// against our copy. If upstream changes the logic in any observable way, this
// goes red and the fork must be re-verified.

const require = createRequire(import.meta.url);

function readSdkAuthSource(): string {
  const entry = require.resolve('@modelcontextprotocol/sdk/client/auth.js');
  return readFileSync(entry, 'utf8');
}

/** Extracts a top-level `function <name>(...) { ... }` by brace matching. */
function extractFunctionSource(source: string, name: string): string {
  const start = source.indexOf(`function ${name}(`);
  if (start === -1) {
    throw new Error(
      `Could not find "function ${name}(" in the installed SDK's client/auth.js. ` +
        'The SDK has been restructured — re-verify src/issuerMatch.ts against it by hand.',
    );
  }
  const bodyStart = source.indexOf('{', start);
  let depth = 0;
  for (let i = bodyStart; i < source.length; i++) {
    const ch = source[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`Unbalanced braces while extracting ${name} from the SDK source.`);
}

function loadSdkIssuersMatch(): (a: string, b: string) => boolean {
  const src = extractFunctionSource(readSdkAuthSource(), 'issuersMatch');
  // Not eval of untrusted input: this is the same node_modules source the
  // package already imports and executes at runtime.
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${src}; return issuersMatch;`)() as (a: string, b: string) => boolean;
}

const corpus: string[] = [];
{
  const schemes = ['https', 'http', 'ftp', 'file', 'ws', 'foo', 'urn', 'mailto', 'data', 'HTTPS'];
  const bodies = [
    '', ':', ':/', '://', '://h', '://h/', '://h//', '://h:1', '://h:443', '://h/p', '://h/p/',
    '://u@h', '://h?q', '://h#f', ':x', ':x/', ':/x', '://[::1]', '://xn--e1afmkfd.xn--p1ai',
    '://exämple.com', '://h/%2e%2e/', '://h/./', '://h/../',
  ];
  for (const s of schemes) for (const b of bodies) corpus.push(s + b);
  corpus.push(
    '', ' ', '/', '//', '///', 'h', 'h/', 'a.b', 'a.b/', ':', '::', '?', '#', 'not a url',
    'auth.example.com', 'auth.example.com/', '//auth.example.com', '/tenant1', 'https://', 'https:/',
    'https://auth.example.com', 'https://auth.example.com/', 'https://auth.example.com//',
    'https://AUTH.example.com', 'https://auth.example.com:443', 'https://auth.example.com/tenant1',
    'https://auth.example.com/tenant1/',
  );
}

describe('Bajo-4: src/issuerMatch.ts stays equivalent to the SDK\'s private issuersMatch', () => {
  it('can still locate the function in the installed SDK', () => {
    const src = extractFunctionSource(readSdkAuthSource(), 'issuersMatch');
    expect(src).toContain('function issuersMatch');
    expect(src).toContain('new URL(');
  });

  it('is behaviourally identical across an exhaustive corpus cross-product', () => {
    const sdkIssuersMatch = loadSdkIssuersMatch();
    const disagreements: Array<{ a: string; b: string; sdk: boolean; local: boolean }> = [];

    for (const a of corpus) {
      for (const b of corpus) {
        const sdk = sdkIssuersMatch(a, b);
        const local = issuersMatch(a, b);
        if (sdk !== local) disagreements.push({ a, b, sdk, local });
      }
    }

    expect(
      disagreements.slice(0, 5),
      `src/issuerMatch.ts has diverged from the installed SDK's issuersMatch. ` +
        `Re-verify the fork against node_modules/@modelcontextprotocol/sdk/dist/esm/client/auth.js ` +
        `and update both the implementation and the version noted in its JSDoc. ` +
        `${disagreements.length} disagreement(s) over ${corpus.length ** 2} pairs.`,
    ).toEqual([]);
  });

  it('is behaviourally identical under randomized fuzzing', () => {
    const sdkIssuersMatch = loadSdkIssuersMatch();
    const chars = 'ab:/.@?#[]%\\ \t\n-';
    const rnd = (): string => {
      let s = '';
      const n = 1 + Math.floor(Math.random() * 12);
      for (let i = 0; i < n; i++) s += chars[Math.floor(Math.random() * chars.length)];
      return s;
    };

    for (let i = 0; i < 20_000; i++) {
      const a = Math.random() < 0.5 ? rnd() : corpus[Math.floor(Math.random() * corpus.length)]!;
      const b = Math.random() < 0.5 ? rnd() : corpus[Math.floor(Math.random() * corpus.length)]!;
      if (sdkIssuersMatch(a, b) !== issuersMatch(a, b)) {
        throw new Error(
          `Divergence from the SDK's issuersMatch on a=${JSON.stringify(a)} b=${JSON.stringify(b)}. ` +
            'Re-verify src/issuerMatch.ts against the installed SDK.',
        );
      }
    }
  });

  it('tolerates the trailing-slash difference this fork exists to handle (regression guard for B2)', () => {
    expect(issuersMatch('https://auth.example.com', 'https://auth.example.com/')).toBe(true);
    expect(issuersMatch('https://auth.example.com/', 'https://auth.example.com')).toBe(true);
    expect(issuersMatch('HTTPS://AUTH.EXAMPLE.COM', 'https://auth.example.com')).toBe(true);
    expect(issuersMatch('https://auth.example.com:443', 'https://auth.example.com')).toBe(true);
    expect(issuersMatch('https://auth.example.com', 'https://other.example.com')).toBe(false);
  });
});
