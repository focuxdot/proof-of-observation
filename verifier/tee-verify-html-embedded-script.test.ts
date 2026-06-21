// CI guard: docs/tee-verify.html embeds verifier/verify-attestation-cose.mjs so
// users without a checkout can download the same reference verifier from the
// page. Keep the embedded copy byte-for-byte aligned.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'docs/tee-verify.html'), 'utf8');
const source = readFileSync(join(root, 'verifier/verify-attestation-cose.mjs'), 'utf8');

const m = html.match(/<script type="text\/plain" id="src-cose">\n([\s\S]*?)\n<\/script>/);

describe('docs/tee-verify.html embedded verify-attestation-cose.mjs', () => {
  it('has the embedded source block', () => {
    expect(m, 'missing <script id="src-cose"> in docs/tee-verify.html').not.toBeNull();
  });

  it('matches verifier/verify-attestation-cose.mjs', () => {
    expect(m![1].trim()).toBe(source.trim());
  });
});
