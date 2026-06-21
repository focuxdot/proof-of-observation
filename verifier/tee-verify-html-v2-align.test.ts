// CI guard: docs/tee-verify.html is an independent browser implementation of
// the v2 statement builder. Check it against the golden vectors shared with
// verifier/signing.ts and the enclave implementation.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'docs/tee-verify.html'), 'utf8');
const js = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join('\n');

const grab = (re: RegExp): string => {
  const m = js.match(re);
  if (!m) throw new Error('missing in tee-verify.html: ' + re);
  return m[0];
};

const build = new Function(
  [
    'const te = new TextEncoder();',
    grab(/const SIGNING_DOMAIN_V2\s*=\s*'[^']*';/),
    grab(/function pathNoQuery\(p\)\{[^}]*\}/),
    grab(/function buildV2Statement\(t\)\{[\s\S]*?\n\}/),
    'return buildV2Statement;',
  ].join('\n'),
)() as (t: Record<string, unknown>) => Uint8Array;

const fx = JSON.parse(readFileSync(join(root, 'enclave/signing-vectors.json'), 'utf8')) as {
  cases_v2: Array<{
    name: string;
    nonce_b64: string;
    upstream_host: string;
    upstream_path: string;
    http_method: string;
    http_status: number;
    resp_content_type: string;
    expected: { statement_hex: string; request_body_sha256: string; response_body_sha256: string };
  }>;
};

describe('docs/tee-verify.html buildV2Statement == golden', () => {
  expect(fx.cases_v2.length).toBeGreaterThan(0);
  for (const c of fx.cases_v2) {
    it(c.name, () => {
      const t = {
        nonce: c.nonce_b64,
        upstream_host: c.upstream_host,
        upstream_path: c.upstream_path,
        http_method: c.http_method,
        http_status: c.http_status,
        resp_content_type: c.resp_content_type,
        request_body_sha256: c.expected.request_body_sha256,
        response_body_sha256: c.expected.response_body_sha256,
      };
      expect(Buffer.from(build(t)).toString('hex')).toBe(c.expected.statement_hex);
    });
  }
});
