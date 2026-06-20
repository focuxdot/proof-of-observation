// 真硬件「完整产品」离线验证器(CLI · full 档 · v2):合验真 attestation 与真模型响应签名,并用你
// **自己的请求体**核对「请求绑定」(答的就是你这条请求),读出签名覆盖的 host/path。
//
//   npx tsx verify-real-bundle.ts <bundle.json> --pcr0 <hex> [--host <api.example.com>]
//
//   · --pcr0  (必填)审计公布、且可由 docs/tee-reproducible-build.md 复算的镜像度量
//   · --host  (可选)核对签名覆盖的 upstream_host;不给则只展示由你判断
//
// bundle:{ requestBody_b64, responseBody_b64, proof(v2) }。proof 自带 host/path/status/两段哈希,
// 故无需单独给 host/path。验证逻辑全部落在共享核心 tee-verify-core.ts(与客户端 CLI / 校验代理同一份,零漂移)。

import { readFileSync } from 'node:fs';
import { verifyTeeExchange } from './tee-verify-core.ts';

const args = process.argv.slice(2);
const FLAGS = new Set(['--pcr0', '--host']);
const flag = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const consumed = new Set<number>();
args.forEach((a, i) => {
  if (FLAGS.has(a)) {
    consumed.add(i);
    consumed.add(i + 1);
  }
});
const bundlePath = args.find((a, i) => !consumed.has(i) && !a.startsWith('--'));
const pcr0 = flag('--pcr0');
const expectedHost = flag('--host');
if (!bundlePath || !pcr0) {
  console.error('用法: tsx verify-real-bundle.ts <bundle.json> --pcr0 <hex> [--host <api.example.com>]');
  console.error('  --pcr0 必填;--host 可选(给了就核对签名覆盖的 upstream_host)。');
  process.exit(2);
}

const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
const b = (s: string | undefined) => Buffer.from(s ?? '', 'base64');

const result = verifyTeeExchange({
  expectedPcr0: pcr0,
  expectedHost,
  requestBody: b(bundle.requestBody_b64),
  responseBody: b(bundle.responseBody_b64),
  proof: bundle.proof,
});

console.log('── 真硬件 · 完整产品离线验证 (v2) ──');
console.log('module_id :', result.attestation.moduleId);
console.log('PCR0(文档):', result.attestation.pcr0);
console.log('绑定公钥  :', result.attestation.publicKey);
console.log('上游 host :', result.provenance.upstreamHost, result.provenance.upstreamPath);
console.log('状态/类型 :', `${result.provenance.httpStatus} · ${result.provenance.respContentType}`);
console.log('──');
for (const c of result.checks) console.log(`  ${c.ok ? '✅' : '❌'} ${String(c.name).padEnd(6, '　')} ${c.detail}`);
console.log(`  判定: ${result.ok ? '✅ 全过——真飞地跑审计代码、host 已签名覆盖、请求绑定(答的就是你这条请求)、签了这条真实响应' : '❌ 校验失败'}`);
process.exit(result.ok ? 0 : 1);
